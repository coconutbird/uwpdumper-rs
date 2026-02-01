//! Shared memory IPC implementation
//!
//! Uses a byte-based ring buffer with packet protocol:
//! - Header contains control flags and ring buffer indices
//! - Data region is a circular buffer for variable-size packets

#[cfg(test)]
use crate::messages::PacketId;
use crate::messages::{HEADER_SIZE, LogLevel, MAX_PAYLOAD_SIZE, Packet, PacketHeader};
use crate::{MAGIC, SHARED_MEMORY_NAME_PREFIX, SHARED_MEMORY_SIZE};
use std::sync::atomic::{AtomicU32, Ordering};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, SET_ACCESS, SetEntriesInAclW, TRUSTEE_FORM,
    TRUSTEE_TYPE, TRUSTEE_W,
};
use windows::Win32::Security::{
    ACE_FLAGS, ACL, InitializeSecurityDescriptor, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR, SetSecurityDescriptorDacl,
};
use windows::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_ALL_ACCESS, FILE_MAP_READ, FILE_MAP_WRITE,
    MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, OpenFileMappingW, PAGE_READWRITE, UnmapViewOfFile,
};
use windows::core::{Error, PCWSTR, Result, w};
/// Size of the shared header (64 bytes core + reserved padding = 1024)
pub const SHARED_HEADER_SIZE: usize = 1024;

/// Size of the ring buffer data region
pub const RING_BUFFER_SIZE: usize = SHARED_MEMORY_SIZE - SHARED_HEADER_SIZE;

/// Header at the start of shared memory
#[repr(C)]
pub struct SharedHeader {
    /// Magic value to verify valid shared memory
    pub magic: u32,
    /// Process ID of the target UWP process
    pub target_pid: u32,
    /// Write offset in ring buffer (DLL writes here)
    pub write_offset: AtomicU32,
    /// Read offset in ring buffer (CLI reads from here)
    pub read_offset: AtomicU32,
    /// Flag: DLL should start dumping
    pub start_dump: AtomicU32,
    /// Flag: DLL has finished
    pub finished: AtomicU32,
    /// Progress: current file count (DLL updates, CLI reads)
    pub progress_current: AtomicU32,
    /// Progress: total file count (DLL updates, CLI reads)
    pub progress_total: AtomicU32,
    /// Sync counter: DLL increments, CLI acknowledges by matching
    pub sync_request: AtomicU32,
    /// Sync acknowledgment: CLI sets to match sync_request
    pub sync_ack: AtomicU32,
    /// Reserved for future use / padding
    pub reserved: [u8; 976],
}

/// Handle to shared memory (CLI side - creates the mapping)
pub struct IpcHost {
    handle: HANDLE,
    view: MEMORY_MAPPED_VIEW_ADDRESS,
}

impl IpcHost {
    /// Create shared memory for a target process with ACL for UWP access
    pub fn create(target_pid: u32) -> Result<Self> {
        let name = format!("{}{}\0", SHARED_MEMORY_NAME_PREFIX, target_pid);
        let name_wide: Vec<u16> = name.encode_utf16().collect();

        unsafe {
            // Create security descriptor that grants access to:
            // 1. ALL APPLICATION PACKAGES (S-1-15-2-1) - for UWP apps
            // 2. EVERYONE (S-1-1-0) - for the CLI/tests
            let mut sid_uwp: PSID = PSID::default();
            let mut sid_everyone: PSID = PSID::default();

            if ConvertStringSidToSidW(w!("S-1-15-2-1"), &mut sid_uwp).is_err() {
                return Err(Error::from_win32());
            }

            if ConvertStringSidToSidW(w!("S-1-1-0"), &mut sid_everyone).is_err() {
                let _ = LocalFree(Some(std::mem::transmute::<PSID, HLOCAL>(sid_uwp)));
                return Err(Error::from_win32());
            }

            // Create EXPLICIT_ACCESS entries
            let ea_entries = [
                // ALL APPLICATION PACKAGES
                EXPLICIT_ACCESS_W {
                    grfAccessPermissions: FILE_MAP_ALL_ACCESS.0,
                    grfAccessMode: SET_ACCESS,
                    grfInheritance: ACE_FLAGS(0),
                    Trustee: TRUSTEE_W {
                        pMultipleTrustee: std::ptr::null_mut(),
                        MultipleTrusteeOperation: Default::default(),
                        TrusteeForm: TRUSTEE_FORM(0), // TRUSTEE_IS_SID
                        TrusteeType: TRUSTEE_TYPE(5), // TRUSTEE_IS_WELL_KNOWN_GROUP
                        ptstrName: windows::core::PWSTR(sid_uwp.0 as *mut u16),
                    },
                },
                // EVERYONE
                EXPLICIT_ACCESS_W {
                    grfAccessPermissions: FILE_MAP_ALL_ACCESS.0,
                    grfAccessMode: SET_ACCESS,
                    grfInheritance: ACE_FLAGS(0),
                    Trustee: TRUSTEE_W {
                        pMultipleTrustee: std::ptr::null_mut(),
                        MultipleTrusteeOperation: Default::default(),
                        TrusteeForm: TRUSTEE_FORM(0), // TRUSTEE_IS_SID
                        TrusteeType: TRUSTEE_TYPE(5), // TRUSTEE_IS_WELL_KNOWN_GROUP
                        ptstrName: windows::core::PWSTR(sid_everyone.0 as *mut u16),
                    },
                },
            ];

            // Build ACL
            let mut acl: *mut ACL = std::ptr::null_mut();
            let result = SetEntriesInAclW(Some(&ea_entries), None, &mut acl);
            if result.0 != 0 {
                let _ = LocalFree(Some(std::mem::transmute::<PSID, HLOCAL>(sid_uwp)));
                let _ = LocalFree(Some(std::mem::transmute::<PSID, HLOCAL>(sid_everyone)));
                return Err(Error::from_win32());
            }

            // Initialize security descriptor
            let mut sd = SECURITY_DESCRIPTOR::default();
            let sd_ptr = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut std::ffi::c_void);
            if InitializeSecurityDescriptor(sd_ptr, 1).is_err() {
                let _ = LocalFree(Some(std::mem::transmute::<*mut ACL, HLOCAL>(acl)));
                let _ = LocalFree(Some(std::mem::transmute::<PSID, HLOCAL>(sid_uwp)));
                let _ = LocalFree(Some(std::mem::transmute::<PSID, HLOCAL>(sid_everyone)));
                return Err(Error::from_win32());
            }

            // Set DACL
            if SetSecurityDescriptorDacl(sd_ptr, true, Some(acl), false).is_err() {
                let _ = LocalFree(Some(std::mem::transmute::<*mut ACL, HLOCAL>(acl)));
                let _ = LocalFree(Some(std::mem::transmute::<PSID, HLOCAL>(sid_uwp)));
                let _ = LocalFree(Some(std::mem::transmute::<PSID, HLOCAL>(sid_everyone)));
                return Err(Error::from_win32());
            }

            // Create security attributes
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: &mut sd as *mut _ as *mut std::ffi::c_void,
                bInheritHandle: false.into(),
            };

            let handle = CreateFileMappingW(
                HANDLE::default(),
                Some(&sa),
                PAGE_READWRITE,
                0,
                SHARED_MEMORY_SIZE as u32,
                PCWSTR(name_wide.as_ptr()),
            );

            // Clean up security resources
            let _ = LocalFree(Some(std::mem::transmute::<*mut ACL, HLOCAL>(acl)));
            let _ = LocalFree(Some(std::mem::transmute::<PSID, HLOCAL>(sid_uwp)));
            let _ = LocalFree(Some(std::mem::transmute::<PSID, HLOCAL>(sid_everyone)));

            let handle = handle?;

            let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEMORY_SIZE);
            if view.Value.is_null() {
                CloseHandle(handle)?;
                return Err(Error::from_win32());
            }

            // Initialize header
            let header = &mut *(view.Value as *mut SharedHeader);
            header.magic = MAGIC;
            header.target_pid = target_pid;
            header.write_offset = AtomicU32::new(0);
            header.read_offset = AtomicU32::new(0);
            header.start_dump = AtomicU32::new(0);
            header.finished = AtomicU32::new(0);
            header.progress_current = AtomicU32::new(0);
            header.progress_total = AtomicU32::new(0);
            header.sync_request = AtomicU32::new(0);
            header.sync_ack = AtomicU32::new(0);
            header.reserved = [0u8; 976];

            Ok(Self { handle, view })
        }
    }

    /// Get pointer to header
    fn header(&self) -> &SharedHeader {
        unsafe { &*(self.view.Value as *const SharedHeader) }
    }

    fn header_mut(&mut self) -> &mut SharedHeader {
        unsafe { &mut *(self.view.Value as *mut SharedHeader) }
    }

    /// Get pointer to ring buffer data region
    fn ring_buffer(&self) -> &[u8] {
        unsafe {
            let ptr = (self.view.Value as *const u8).add(SHARED_HEADER_SIZE);
            std::slice::from_raw_parts(ptr, RING_BUFFER_SIZE)
        }
    }

    /// Signal DLL to start dumping
    pub fn start_dump(&mut self) {
        self.header_mut().start_dump.store(1, Ordering::SeqCst);
    }

    /// Check if DLL has finished
    pub fn is_finished(&self) -> bool {
        self.header().finished.load(Ordering::SeqCst) != 0
    }

    /// Try to read a packet (non-blocking)
    pub fn try_read(&mut self) -> Option<Packet> {
        let header = self.header();
        let read_off = header.read_offset.load(Ordering::Acquire);
        let write_off = header.write_offset.load(Ordering::Acquire);

        if read_off == write_off {
            return None; // No data
        }

        let ring = self.ring_buffer();

        // Read packet header (may wrap around)
        let mut hdr_bytes = [0u8; HEADER_SIZE];
        for i in 0..HEADER_SIZE {
            hdr_bytes[i] = ring[(read_off as usize + i) % RING_BUFFER_SIZE];
        }

        let pkt_header = PacketHeader::from_bytes(&hdr_bytes)?;
        if !pkt_header.is_valid() {
            return None;
        }

        let payload_size = pkt_header.size as usize;
        if payload_size > MAX_PAYLOAD_SIZE {
            return None;
        }

        // Read payload (may wrap around)
        let mut payload = vec![0u8; payload_size];
        let payload_start = (read_off as usize + HEADER_SIZE) % RING_BUFFER_SIZE;
        for i in 0..payload_size {
            payload[i] = ring[(payload_start + i) % RING_BUFFER_SIZE];
        }

        let total_size = HEADER_SIZE + payload_size;
        let new_read_off = (read_off as usize + total_size) % RING_BUFFER_SIZE;

        // Advance read offset
        self.header_mut()
            .read_offset
            .store(new_read_off as u32, Ordering::Release);

        Some(Packet {
            header: pkt_header,
            payload,
        })
    }

    /// Get current progress (current, total) from shared memory
    pub fn get_progress(&self) -> (u32, u32) {
        let header = self.header();
        let current = header.progress_current.load(Ordering::Relaxed);
        let total = header.progress_total.load(Ordering::Relaxed);
        (current, total)
    }

    /// Check if DLL is requesting a sync and acknowledge it
    /// Returns true if a sync was acknowledged
    pub fn check_and_ack_sync(&mut self) -> bool {
        let header = self.header();
        let request = header.sync_request.load(Ordering::Acquire);
        let ack = header.sync_ack.load(Ordering::Relaxed);
        if request != ack {
            self.header_mut().sync_ack.store(request, Ordering::Release);
            true
        } else {
            false
        }
    }
}

impl Drop for IpcHost {
    fn drop(&mut self) {
        unsafe {
            let _ = UnmapViewOfFile(self.view);
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Handle to shared memory (DLL side - opens existing mapping)
pub struct IpcClient {
    #[allow(dead_code)]
    handle: HANDLE,
    view: MEMORY_MAPPED_VIEW_ADDRESS,
}

// SAFETY: IpcClient can be sent between threads because:
// - The HANDLE is a process-wide kernel object
// - The memory mapping is valid for the entire process
// - We only access it through &mut self which ensures exclusive access
unsafe impl Send for IpcClient {}

// SAFETY: IpcClient can be shared between threads for read-only operations
// like set_progress() which only writes to atomics in shared memory
unsafe impl Sync for IpcClient {}

impl IpcClient {
    /// Open existing shared memory for this process
    pub fn open(target_pid: u32) -> Result<Self> {
        let name = format!("{}{}\0", SHARED_MEMORY_NAME_PREFIX, target_pid);
        let name_wide: Vec<u16> = name.encode_utf16().collect();

        unsafe {
            let handle = OpenFileMappingW(
                (FILE_MAP_READ | FILE_MAP_WRITE).0,
                false,
                PCWSTR(name_wide.as_ptr()),
            )?;

            let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEMORY_SIZE);
            if view.Value.is_null() {
                CloseHandle(handle)?;
                return Err(Error::from_win32());
            }

            // Verify magic
            let header = &*(view.Value as *const SharedHeader);
            if header.magic != MAGIC {
                UnmapViewOfFile(view)?;
                CloseHandle(handle)?;
                return Err(Error::from_win32());
            }

            Ok(Self { handle, view })
        }
    }

    /// Get pointer to header
    fn header(&self) -> &SharedHeader {
        unsafe { &*(self.view.Value as *const SharedHeader) }
    }

    fn header_mut(&mut self) -> &mut SharedHeader {
        unsafe { &mut *(self.view.Value as *mut SharedHeader) }
    }

    /// Get mutable pointer to ring buffer data region
    fn ring_buffer_mut(&mut self) -> &mut [u8] {
        unsafe {
            let ptr = (self.view.Value as *mut u8).add(SHARED_HEADER_SIZE);
            std::slice::from_raw_parts_mut(ptr, RING_BUFFER_SIZE)
        }
    }

    /// Check if we should start dumping
    pub fn should_start(&self) -> bool {
        self.header().start_dump.load(Ordering::SeqCst) != 0
    }

    /// Signal that we're finished
    pub fn set_finished(&mut self) {
        self.header_mut().finished.store(1, Ordering::SeqCst);
    }

    /// Push a packet to the ring buffer
    pub fn push_packet(&mut self, packet: Packet) {
        let bytes = packet.to_bytes();
        let total_size = bytes.len();

        let write_off = self.header().write_offset.load(Ordering::Acquire) as usize;
        let ring = self.ring_buffer_mut();

        // Write bytes with wrap-around
        for (i, &byte) in bytes.iter().enumerate() {
            ring[(write_off + i) % RING_BUFFER_SIZE] = byte;
        }

        let new_write_off = (write_off + total_size) % RING_BUFFER_SIZE;
        self.header_mut()
            .write_offset
            .store(new_write_off as u32, Ordering::Release);
    }

    /// Helper to send an info log message
    pub fn info(&mut self, text: &str) {
        self.push_packet(Packet::log(LogLevel::Info, text));
    }

    /// Helper to send a success log message
    pub fn success(&mut self, text: &str) {
        self.push_packet(Packet::log(LogLevel::Success, text));
    }

    /// Helper to send a warning log message
    pub fn warn(&mut self, text: &str) {
        self.push_packet(Packet::log(LogLevel::Warning, text));
    }

    /// Helper to send an error log message
    pub fn error(&mut self, text: &str) {
        self.push_packet(Packet::log(LogLevel::Error, text));
    }

    /// Set progress in shared memory header (for polling by CLI)
    pub fn set_progress(&self, current: u32, total: u32) {
        let header = self.header();
        header.progress_current.store(current, Ordering::Relaxed);
        header.progress_total.store(total, Ordering::Relaxed);
    }

    /// Request sync and wait for CLI to acknowledge
    /// This ensures CLI has polled the current progress before continuing
    pub fn sync(&self) {
        let header = self.header();
        let new_val = header.sync_request.fetch_add(1, Ordering::Release) + 1;
        // Spin until CLI acknowledges
        while header.sync_ack.load(Ordering::Acquire) != new_val {
            std::hint::spin_loop();
        }
    }
}

impl Drop for IpcClient {
    fn drop(&mut self) {
        unsafe {
            let _ = UnmapViewOfFile(self.view);
            let _ = CloseHandle(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Generate a unique PID for each test to avoid conflicts
    fn unique_pid() -> u32 {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(99000);
        COUNTER.fetch_add(1, Ordering::SeqCst)
    }

    #[tokio::test]
    async fn test_ipc_host_create() {
        let pid = unique_pid();
        let host = IpcHost::create(pid).expect("Failed to create IPC host");
        assert!(!host.is_finished());
        drop(host);
    }

    #[tokio::test]
    async fn test_ipc_client_open() {
        let pid = unique_pid();
        let host = IpcHost::create(pid).expect("Failed to create IPC host");
        let client = IpcClient::open(pid).expect("Failed to open IPC client");
        drop(client);
        drop(host);
    }

    #[tokio::test]
    async fn test_ipc_client_open_fails_without_host() {
        let pid = unique_pid();
        let result = IpcClient::open(pid);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ipc_start_dump_signal() {
        let pid = unique_pid();
        let mut host = IpcHost::create(pid).expect("Failed to create IPC host");
        let client = IpcClient::open(pid).expect("Failed to open IPC client");

        assert!(!client.should_start());
        host.start_dump();
        assert!(client.should_start());
    }

    #[tokio::test]
    async fn test_ipc_finished_signal() {
        let pid = unique_pid();
        let host = IpcHost::create(pid).expect("Failed to create IPC host");
        let mut client = IpcClient::open(pid).expect("Failed to open IPC client");

        assert!(!host.is_finished());
        client.set_finished();
        assert!(host.is_finished());
    }

    #[tokio::test]
    async fn test_ipc_single_packet() {
        let pid = unique_pid();
        let mut host = IpcHost::create(pid).expect("Failed to create IPC host");
        let mut client = IpcClient::open(pid).expect("Failed to open IPC client");

        // No packets initially
        assert!(host.try_read().is_none());

        // Send a packet
        client.info("Hello from DLL");

        // Read the packet
        let pkt = host.try_read().expect("Expected a packet");
        assert_eq!(pkt.id(), PacketId::Log);
        assert_eq!(pkt.log_level(), Some(LogLevel::Info));
        assert_eq!(pkt.message(), "Hello from DLL");

        // No more packets
        assert!(host.try_read().is_none());
    }

    #[tokio::test]
    async fn test_ipc_multiple_packets() {
        let pid = unique_pid();
        let mut host = IpcHost::create(pid).expect("Failed to create IPC host");
        let mut client = IpcClient::open(pid).expect("Failed to open IPC client");

        client.info("Message 1");
        client.success("Message 2");
        client.warn("Message 3");
        client.error("Message 4");

        let pkt1 = host.try_read().unwrap();
        assert_eq!(pkt1.id(), PacketId::Log);
        assert_eq!(pkt1.log_level(), Some(LogLevel::Info));
        assert_eq!(pkt1.message(), "Message 1");

        let pkt2 = host.try_read().unwrap();
        assert_eq!(pkt2.id(), PacketId::Log);
        assert_eq!(pkt2.log_level(), Some(LogLevel::Success));
        assert_eq!(pkt2.message(), "Message 2");

        let pkt3 = host.try_read().unwrap();
        assert_eq!(pkt3.id(), PacketId::Log);
        assert_eq!(pkt3.log_level(), Some(LogLevel::Warning));
        assert_eq!(pkt3.message(), "Message 3");

        let pkt4 = host.try_read().unwrap();
        assert_eq!(pkt4.id(), PacketId::Log);
        assert_eq!(pkt4.log_level(), Some(LogLevel::Error));
        assert_eq!(pkt4.message(), "Message 4");

        assert!(host.try_read().is_none());
    }

    #[tokio::test]
    async fn test_ipc_ring_buffer_wrap() {
        let pid = unique_pid();
        let mut host = IpcHost::create(pid).expect("Failed to create IPC host");
        let mut client = IpcClient::open(pid).expect("Failed to open IPC client");

        // Send many messages to test wrap-around
        for i in 0..50 {
            client.info(&format!("Message {}", i));
            let pkt = host.try_read().unwrap();
            assert_eq!(pkt.message(), format!("Message {}", i));
        }
    }

    #[test]
    fn test_ipc_concurrent_communication() {
        let pid = unique_pid();

        // Create host first to avoid race condition
        let mut host = IpcHost::create(pid).expect("Failed to create IPC host");

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let barrier_clone = barrier.clone();

        // Simulate DLL sending packets in a separate thread
        let sender = std::thread::spawn(move || {
            let mut client = IpcClient::open(pid).expect("Failed to open IPC client");
            barrier_clone.wait();
            for i in 0..20 {
                client.info(&format!("Async message {}", i));
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            client.set_finished();
        });

        // Receive packets in this thread after synchronizing
        barrier.wait();
        let mut received = Vec::new();
        loop {
            while let Some(pkt) = host.try_read() {
                received.push(pkt.message().to_string());
            }
            if host.is_finished() {
                // Drain remaining
                while let Some(pkt) = host.try_read() {
                    received.push(pkt.message().to_string());
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        sender.join().unwrap();

        assert_eq!(received.len(), 20);
        for (i, msg) in received.iter().enumerate().take(20) {
            assert_eq!(*msg, format!("Async message {}", i));
        }
    }

    #[test]
    fn test_ipc_sync() {
        let pid = unique_pid();

        let mut host = IpcHost::create(pid).expect("Failed to create IPC host");
        let client = IpcClient::open(pid).expect("Failed to open IPC client");

        // Spawn thread that will call sync and wait for ack
        let sync_thread = std::thread::spawn(move || {
            // Set progress before sync
            client.set_progress(50, 100);
            client.sync();
            // After sync returns, CLI must have acknowledged
            client.set_progress(100, 100);
            client.sync();
        });

        // Give the thread a moment to start and call sync
        std::thread::sleep(std::time::Duration::from_millis(10));

        // First sync: check progress and acknowledge
        let progress = host.get_progress();
        assert_eq!(progress, (50, 100));
        assert!(host.check_and_ack_sync());

        // Give thread time to proceed to second sync
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Second sync: check progress and acknowledge
        let progress = host.get_progress();
        assert_eq!(progress, (100, 100));
        assert!(host.check_and_ack_sync());

        sync_thread.join().unwrap();
    }

    #[test]
    fn test_ipc_sync_blocks_until_ack() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let pid = unique_pid();

        let mut host = IpcHost::create(pid).expect("Failed to create IPC host");
        let client = IpcClient::open(pid).expect("Failed to open IPC client");

        let sync_completed = Arc::new(AtomicBool::new(false));
        let sync_completed_clone = sync_completed.clone();

        // Spawn thread that will call sync
        let sync_thread = std::thread::spawn(move || {
            client.sync();
            sync_completed_clone.store(true, Ordering::SeqCst);
        });

        // Wait a bit - sync should NOT complete yet
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            !sync_completed.load(Ordering::SeqCst),
            "sync should block until ack"
        );

        // Now acknowledge
        host.check_and_ack_sync();

        // Wait for thread to complete
        sync_thread.join().unwrap();
        assert!(
            sync_completed.load(Ordering::SeqCst),
            "sync should complete after ack"
        );
    }
}
