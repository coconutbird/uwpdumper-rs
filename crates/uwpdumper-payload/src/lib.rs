//! UWPDumper DLL - injected into UWP processes to dump package files

mod dumper;
mod uwp;

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use uwpdumper_shared::IpcClient;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{DisableThreadLibraryCalls, FreeLibraryAndExitThread};
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows::Win32::System::Threading::{CreateThread, GetCurrentProcessId, THREAD_CREATION_FLAGS};

/// Store the module handle so we can unload ourselves
static MODULE_HANDLE: AtomicUsize = AtomicUsize::new(0);

/// DLL entry point
#[unsafe(no_mangle)]
pub extern "system" fn DllMain(module: HMODULE, call_reason: u32, _reserved: *mut c_void) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            // Store module handle for later unloading
            MODULE_HANDLE.store(module.0 as usize, Ordering::SeqCst);

            // Disable thread attach/detach notifications
            unsafe {
                let _ = DisableThreadLibraryCalls(module);
            }

            // Spawn worker thread
            unsafe {
                let _ = CreateThread(
                    None,
                    0,
                    Some(dumper_thread),
                    None,
                    THREAD_CREATION_FLAGS(0),
                    None,
                );
            }
            true
        }
        DLL_PROCESS_DETACH => true,
        _ => true,
    }
}

/// Main dumper thread
extern "system" fn dumper_thread(_param: *mut c_void) -> u32 {
    let pid = unsafe { GetCurrentProcessId() };

    // Try to connect to IPC
    let mut ipc = match IpcClient::open(pid) {
        Ok(ipc) => ipc,
        Err(_) => {
            // No IPC available - can't communicate
            unload_self(1);
        }
    };

    // Signal ready
    ipc.push_packet(uwpdumper_shared::Packet::ready());

    // Wait for start signal
    while !ipc.should_start() {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Run the dumper
    let exit_code = match dumper::run(&mut ipc) {
        Ok(dump_path) => {
            // Send dump path in Complete packet so CLI can copy to custom output
            ipc.push_packet(uwpdumper_shared::Packet::complete(
                &dump_path.to_string_lossy(),
            ));
            0
        }
        Err(e) => {
            ipc.push_packet(uwpdumper_shared::Packet::fatal(&format!(
                "Dumper failed: {}",
                e
            )));
            1
        }
    };

    // Signal finished
    ipc.set_finished();

    // Give CLI time to read final messages
    std::thread::sleep(std::time::Duration::from_millis(100));

    unload_self(exit_code);
}

/// Unload the DLL and exit the current thread
fn unload_self(exit_code: u32) -> ! {
    unsafe {
        let module = HMODULE(MODULE_HANDLE.load(Ordering::SeqCst) as *mut c_void);
        FreeLibraryAndExitThread(module, exit_code);
    }
}
