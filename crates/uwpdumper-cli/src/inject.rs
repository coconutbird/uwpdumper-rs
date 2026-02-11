//! DLL injection using LoadLibrary

use std::ffi::c_void;
use std::path::Path;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_MOD_NOT_FOUND, ERROR_TIMEOUT, GetLastError, HANDLE, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, OpenProcess, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_SYNCHRONIZE, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE, WaitForSingleObject,
};
use windows::core::{Error, Result, s, w};

// Undocumented ntdll function types
type NtSuspendProcessFn = unsafe extern "system" fn(HANDLE) -> i32;
type NtResumeProcessFn = unsafe extern "system" fn(HANDLE) -> i32;

/// Get NtSuspendProcess and NtResumeProcess from ntdll
fn get_nt_suspend_resume() -> Option<(NtSuspendProcessFn, NtResumeProcessFn)> {
    // Type returned by GetProcAddress
    type FarProc = unsafe extern "system" fn() -> isize;

    unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
        let suspend = GetProcAddress(ntdll, s!("NtSuspendProcess"))?;
        let resume = GetProcAddress(ntdll, s!("NtResumeProcess"))?;
        Some((
            std::mem::transmute::<FarProc, NtSuspendProcessFn>(suspend),
            std::mem::transmute::<FarProc, NtResumeProcessFn>(resume),
        ))
    }
}

/// Suspend a process by PID using NtSuspendProcess
pub fn suspend_process(pid: u32) -> Result<()> {
    let (suspend_fn, _) = get_nt_suspend_resume().ok_or_else(Error::from_win32)?;

    unsafe {
        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid)?;
        let status = suspend_fn(handle);
        CloseHandle(handle)?;

        if status != 0 {
            return Err(Error::from_win32());
        }
    }
    Ok(())
}

/// Handle to a target process that auto-closes on drop
pub struct ProcessHandle(HANDLE);

impl ProcessHandle {
    /// Check if the process is still running
    /// Returns true if running, false if terminated
    pub fn is_alive(&self) -> bool {
        // WaitForSingleObject with timeout 0 returns immediately
        // WAIT_TIMEOUT means still running, WAIT_OBJECT_0 means terminated
        unsafe { WaitForSingleObject(self.0, 0) == WAIT_TIMEOUT }
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Inject a DLL into a target process
/// Returns a handle to the process for monitoring
pub fn inject_dll(pid: u32, dll_path: &Path) -> Result<ProcessHandle> {
    // Set ACL on DLL for UWP access
    set_uwp_acl(dll_path)?;

    let dll_path_str = dll_path.to_string_lossy();
    let dll_path_wide: Vec<u16> = dll_path_str
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let dll_path_bytes = dll_path_wide.len() * 2;

    unsafe {
        // Open target process (PROCESS_SYNCHRONIZE needed for WaitForSingleObject)
        let process = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )?;

        // Allocate memory in target process
        let remote_mem = VirtualAllocEx(
            process,
            None,
            dll_path_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            CloseHandle(process)?;
            return Err(Error::from_win32());
        }

        // Write DLL path to target process
        let mut written = 0;
        let write_result = WriteProcessMemory(
            process,
            remote_mem,
            dll_path_wide.as_ptr() as *const c_void,
            dll_path_bytes,
            Some(&mut written),
        );

        if write_result.is_err() || written != dll_path_bytes {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE)?;
            CloseHandle(process)?;
            return Err(Error::from_win32());
        }

        // Get LoadLibraryW address
        let kernel32 = GetModuleHandleW(w!("kernel32.dll"))?;
        let load_library = GetProcAddress(kernel32, s!("LoadLibraryW"));

        if load_library.is_none() {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE)?;
            CloseHandle(process)?;
            return Err(Error::from_win32());
        }

        // Create remote thread to call LoadLibraryW
        #[allow(clippy::missing_transmute_annotations)]
        let thread = CreateRemoteThread(
            process,
            None,
            0,
            Some(std::mem::transmute(load_library.unwrap())),
            Some(remote_mem),
            0,
            None,
        );

        let thread = match thread {
            Ok(t) => t,
            Err(e) => {
                VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE)?;
                CloseHandle(process)?;
                return Err(e);
            }
        };

        // Wait for thread to complete
        let wait_result = WaitForSingleObject(thread, 10000); // 10 second timeout

        if wait_result == WAIT_TIMEOUT {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE)?;
            CloseHandle(thread)?;
            CloseHandle(process)?;
            return Err(Error::new(
                windows::core::HRESULT::from_win32(ERROR_TIMEOUT.0),
                "Timeout waiting for LoadLibraryW",
            ));
        }

        if wait_result != WAIT_OBJECT_0 {
            let err = GetLastError();
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE)?;
            CloseHandle(thread)?;
            CloseHandle(process)?;
            return Err(Error::from(err));
        }

        // Check thread exit code (LoadLibraryW return value)
        // If LoadLibraryW failed, it returns NULL (0)
        let mut exit_code: u32 = 0;
        GetExitCodeThread(thread, &mut exit_code)?;

        // Clean up thread and memory (but keep process handle for monitoring)
        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE)?;
        CloseHandle(thread)?;

        if exit_code == 0 {
            CloseHandle(process)?;
            return Err(Error::new(
                windows::core::HRESULT::from_win32(ERROR_MOD_NOT_FOUND.0),
                "LoadLibraryW failed in target process (returned NULL). The DLL may have missing dependencies or the process may block injection.",
            ));
        }

        // Return process handle for monitoring
        Ok(ProcessHandle(process))
    }
}

/// Set ACL on DLL to allow UWP apps to read it
fn set_uwp_acl(dll_path: &Path) -> Result<()> {
    use std::process::Command;

    // Use icacls to grant ALL APPLICATION PACKAGES read access
    let output = Command::new("icacls")
        .arg(dll_path)
        .arg("/grant")
        .arg("*S-1-15-2-1:(RX)")
        .output();

    match output {
        Ok(o) if o.status.success() => Ok(()),
        _ => {
            // Non-fatal - injection might still work
            Ok(())
        }
    }
}
