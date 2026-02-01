//! Shared types and IPC protocol for UWPDumper
//!
//! Communication between CLI and DLL uses shared memory (file mapping).
//!
//! # Architecture
//!
//! The IPC system uses a ring buffer in shared memory for message passing:
//! - [`IpcHost`] - Created by CLI, owns the shared memory
//! - [`IpcClient`] - Opened by DLL, writes messages to the ring buffer
//!
//! # Message Protocol
//!
//! Messages use a packet-based protocol defined in [`messages`]:
//! - [`Packet`] - Variable-length message with header and payload
//! - [`PacketId`] - Message type identifier
//! - [`LogLevel`] - Severity level for log messages

#![deny(missing_docs)]

pub mod ipc;
pub mod messages;

pub use ipc::*;
pub use messages::*;

/// Shared memory name format - includes PID for uniqueness
pub const SHARED_MEMORY_NAME_PREFIX: &str = "UWPDumper_IPC_";

/// Size of the shared memory region
pub const SHARED_MEMORY_SIZE: usize = 64 * 1024; // 64KB

/// Magic value to identify valid shared memory
pub const MAGIC: u32 = 0x55575044; // "UWPD"
