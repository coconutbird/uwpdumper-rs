//! Message protocol for IPC communication
//!
//! Packet format:
//! ```text
//! ┌──────────────┐
//! │ magic: u32   │  <- 0x55575044 "UWPD"
//! │ id: u32      │  <- packet type (Log, Ready, Complete, Fatal)
//! │ size: u32    │  <- payload size in bytes
//! │ payload...   │  <- variable length, format depends on packet type
//! └──────────────┘
//! ```
//!
//! Payload formats:
//! - Log: level (u8) + message (UTF-8 string)
//! - Ready: empty
//! - Complete: message (UTF-8 string)
//! - Fatal: message (UTF-8 string)

use crate::MAGIC;

/// Packet header size in bytes
pub const HEADER_SIZE: usize = 12; // magic + id + size

/// Maximum payload size
pub const MAX_PAYLOAD_SIZE: usize = 8192;

/// Packet types (id field)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketId {
    /// No packet / invalid
    None = 0,
    /// Log message (payload: LogLevel + UTF-8 string)
    Log = 1,
    /// DLL is ready and waiting (payload: none)
    Ready = 2,
    /// Dump complete (payload: UTF-8 string)
    Complete = 3,
    /// DLL encountered fatal error (payload: UTF-8 string)
    Fatal = 4,
}

impl From<u32> for PacketId {
    fn from(v: u32) -> Self {
        match v {
            1 => PacketId::Log,
            2 => PacketId::Ready,
            3 => PacketId::Complete,
            4 => PacketId::Fatal,
            _ => PacketId::None,
        }
    }
}

/// Log levels for Log packets
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Informational message
    Info = 0,
    /// Success/completion message
    Success = 1,
    /// Warning message
    Warning = 2,
    /// Error message
    Error = 3,
}

impl From<u8> for LogLevel {
    fn from(v: u8) -> Self {
        match v {
            0 => LogLevel::Info,
            1 => LogLevel::Success,
            2 => LogLevel::Warning,
            3 => LogLevel::Error,
            _ => LogLevel::Info,
        }
    }
}

/// Packet header (12 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    /// Magic value for validation (0x55575044 "UWPD")
    pub magic: u32,
    /// Packet type identifier
    pub id: u32,
    /// Payload size in bytes
    pub size: u32,
}

impl PacketHeader {
    /// Create a new packet header
    pub fn new(id: PacketId, payload_size: usize) -> Self {
        Self {
            magic: MAGIC,
            id: id as u32,
            size: payload_size as u32,
        }
    }

    /// Check if header has valid magic and reasonable size
    pub fn is_valid(&self) -> bool {
        self.magic == MAGIC && self.size as usize <= MAX_PAYLOAD_SIZE
    }

    /// Get the packet type
    pub fn packet_id(&self) -> PacketId {
        PacketId::from(self.id)
    }

    /// Serialize header to bytes (little-endian)
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..4].copy_from_slice(&self.magic.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.id.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.size.to_le_bytes());
        bytes
    }

    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_SIZE {
            return None;
        }
        Some(Self {
            magic: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            id: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            size: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        })
    }
}

/// A complete packet with header and payload
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet header containing type and size
    pub header: PacketHeader,
    /// Variable-length payload data
    pub payload: Vec<u8>,
}

impl Packet {
    /// Create a log message packet
    pub fn log(level: LogLevel, message: &str) -> Self {
        let mut payload = Vec::with_capacity(1 + message.len());
        payload.push(level as u8);
        payload.extend_from_slice(message.as_bytes());
        Self {
            header: PacketHeader::new(PacketId::Log, payload.len()),
            payload,
        }
    }

    /// Create a ready packet (no payload)
    pub fn ready() -> Self {
        Self {
            header: PacketHeader::new(PacketId::Ready, 0),
            payload: Vec::new(),
        }
    }

    /// Create a complete packet
    pub fn complete(message: &str) -> Self {
        Self {
            header: PacketHeader::new(PacketId::Complete, message.len()),
            payload: message.as_bytes().to_vec(),
        }
    }

    /// Create a fatal error packet
    pub fn fatal(message: &str) -> Self {
        Self {
            header: PacketHeader::new(PacketId::Fatal, message.len()),
            payload: message.as_bytes().to_vec(),
        }
    }

    /// Get packet ID
    pub fn id(&self) -> PacketId {
        self.header.packet_id()
    }

    /// Get log level (for Log packets)
    pub fn log_level(&self) -> Option<LogLevel> {
        if self.id() == PacketId::Log && !self.payload.is_empty() {
            Some(LogLevel::from(self.payload[0]))
        } else {
            None
        }
    }

    /// Get log message (for Log packets) or text payload (for Complete/Fatal)
    pub fn message(&self) -> &str {
        match self.id() {
            PacketId::Log if !self.payload.is_empty() => {
                std::str::from_utf8(&self.payload[1..]).unwrap_or("")
            }
            PacketId::Complete | PacketId::Fatal => {
                std::str::from_utf8(&self.payload).unwrap_or("")
            }
            _ => "",
        }
    }

    /// Total size in bytes (header + payload)
    pub fn total_size(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.total_size());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let header = PacketHeader::from_bytes(bytes)?;
        if !header.is_valid() {
            return None;
        }
        let payload_end = HEADER_SIZE + header.size as usize;
        if bytes.len() < payload_end {
            return None;
        }
        Some(Self {
            header,
            payload: bytes[HEADER_SIZE..payload_end].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_id_from_u32() {
        assert_eq!(PacketId::from(0), PacketId::None);
        assert_eq!(PacketId::from(1), PacketId::Log);
        assert_eq!(PacketId::from(2), PacketId::Ready);
        assert_eq!(PacketId::from(3), PacketId::Complete);
        assert_eq!(PacketId::from(4), PacketId::Fatal);
        assert_eq!(PacketId::from(99), PacketId::None);
    }

    #[test]
    fn test_log_level_from_u8() {
        assert_eq!(LogLevel::from(0), LogLevel::Info);
        assert_eq!(LogLevel::from(1), LogLevel::Success);
        assert_eq!(LogLevel::from(2), LogLevel::Warning);
        assert_eq!(LogLevel::from(3), LogLevel::Error);
        assert_eq!(LogLevel::from(99), LogLevel::Info); // Default
    }

    #[test]
    fn test_packet_header_serialization() {
        let header = PacketHeader::new(PacketId::Log, 42);
        let bytes = header.to_bytes();
        let parsed = PacketHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.magic, MAGIC);
        assert_eq!(parsed.packet_id(), PacketId::Log);
        assert_eq!(parsed.size, 42);
        assert!(parsed.is_valid());
    }

    #[test]
    fn test_packet_header_invalid_magic() {
        let mut bytes = PacketHeader::new(PacketId::Log, 10).to_bytes();
        bytes[0] = 0xFF; // Corrupt magic
        let parsed = PacketHeader::from_bytes(&bytes).unwrap();
        assert!(!parsed.is_valid());
    }

    #[test]
    fn test_packet_log() {
        let pkt = Packet::log(LogLevel::Info, "Hello, World!");
        assert_eq!(pkt.id(), PacketId::Log);
        assert_eq!(pkt.log_level(), Some(LogLevel::Info));
        assert_eq!(pkt.message(), "Hello, World!");
        // payload = 1 byte level + 13 bytes message
        assert_eq!(pkt.header.size, 14);
    }

    #[test]
    fn test_packet_log_levels() {
        let info = Packet::log(LogLevel::Info, "info");
        let success = Packet::log(LogLevel::Success, "success");
        let warning = Packet::log(LogLevel::Warning, "warning");
        let error = Packet::log(LogLevel::Error, "error");

        assert_eq!(info.log_level(), Some(LogLevel::Info));
        assert_eq!(success.log_level(), Some(LogLevel::Success));
        assert_eq!(warning.log_level(), Some(LogLevel::Warning));
        assert_eq!(error.log_level(), Some(LogLevel::Error));
    }

    #[test]
    fn test_packet_ready() {
        let pkt = Packet::ready();
        assert_eq!(pkt.id(), PacketId::Ready);
        assert_eq!(pkt.header.size, 0);
        assert!(pkt.payload.is_empty());
    }

    #[test]
    fn test_packet_complete() {
        let pkt = Packet::complete("Dump finished!");
        assert_eq!(pkt.id(), PacketId::Complete);
        assert_eq!(pkt.message(), "Dump finished!");
    }

    #[test]
    fn test_packet_fatal() {
        let pkt = Packet::fatal("Something went wrong");
        assert_eq!(pkt.id(), PacketId::Fatal);
        assert_eq!(pkt.message(), "Something went wrong");
    }

    #[test]
    fn test_packet_log_serialization() {
        let pkt = Packet::log(LogLevel::Success, "Test message");
        let bytes = pkt.to_bytes();
        let parsed = Packet::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.id(), PacketId::Log);
        assert_eq!(parsed.log_level(), Some(LogLevel::Success));
        assert_eq!(parsed.message(), "Test message");
    }

    #[test]
    fn test_packet_total_size() {
        let pkt = Packet::log(LogLevel::Info, "hello");
        // header (12) + level (1) + message (5)
        assert_eq!(pkt.total_size(), HEADER_SIZE + 6);
    }

    #[test]
    fn test_packet_from_bytes_too_short() {
        let bytes = [0u8; 5]; // Less than header size
        assert!(Packet::from_bytes(&bytes).is_none());
    }
}
