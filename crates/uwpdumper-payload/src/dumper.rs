//! Core dumping logic - copies UWP package files to an accessible location

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use rayon::prelude::*;
use thiserror::Error;
use uwpdumper_shared::IpcClient;
use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows::core::PCWSTR;

use crate::uwp::{self, CurrentPackage};

/// Error type for dumper operations
#[derive(Debug, Error)]
pub enum DumperError {
    /// Failed to retrieve UWP package information
    #[error("Failed to get package info: {0}")]
    PackageInfo(#[from] windows::core::Error),

    /// IO error during file operations
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Process is not a UWP application
    #[error("This process is not a UWP application")]
    NotUwpProcess,

    /// Insufficient disk space
    #[error("Insufficient disk space: need {needed} bytes, only {available} bytes available")]
    InsufficientSpace { needed: u64, available: u64 },
}

/// File entry with size information
struct FileEntry {
    path: PathBuf,
    #[allow(dead_code)] // Size is accumulated during collection for disk space check
    size: u64,
}

/// Get available disk space for a path
fn get_available_space(path: &Path) -> io::Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut free_bytes_available: u64 = 0;

    unsafe {
        GetDiskFreeSpaceExW(
            PCWSTR(path_wide.as_ptr()),
            Some(&mut free_bytes_available),
            None,
            None,
        )
        .map_err(|e| io::Error::other(e.to_string()))?;
    }

    Ok(free_bytes_available)
}

/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Run the dumper, returns the path where files were dumped
pub fn run(ipc: &mut IpcClient) -> Result<PathBuf, DumperError> {
    ipc.info("Retrieving package information...");

    let package = match CurrentPackage::current() {
        Ok(p) => p,
        Err(e) => {
            if e.code().0 == 0x80073D54u32 as i32 {
                return Err(DumperError::NotUwpProcess);
            }
            return Err(e.into());
        }
    };

    ipc.info(&format!("Family Name: {}", package.family_name));
    ipc.info(&format!("Full Name: {}", package.full_name));
    ipc.info(&format!("Package Path: {}", package.package_path.display()));

    // Always dump to TempState (sandbox-accessible location)
    let temp_state = uwp::get_temp_state_path()?;
    let dump_path = temp_state.join("DUMP");

    ipc.info(&format!("Dump Path: {}", dump_path.display()));

    if dump_path.exists() {
        ipc.info("Cleaning up previous dump...");
        fs::remove_dir_all(&dump_path)?;
    }

    fs::create_dir_all(&dump_path)?;

    let start_time = Instant::now();

    ipc.info("Scanning package files...");

    let (files, total_size) = collect_files_with_progress(&package.package_path, ipc)?;
    let total = files.len() as u32;

    // Sync to ensure CLI sees scan complete
    ipc.sync();

    ipc.info(&format!(
        "Found {} files to dump ({})",
        total,
        format_bytes(total_size)
    ));

    // Check available disk space (require 10% buffer for safety)
    let required_space = total_size + (total_size / 10);
    match get_available_space(&dump_path) {
        Ok(available) => {
            if available < required_space {
                ipc.error(&format!(
                    "Insufficient disk space: need {}, only {} available",
                    format_bytes(required_space),
                    format_bytes(available)
                ));
                return Err(DumperError::InsufficientSpace {
                    needed: required_space,
                    available,
                });
            }
            ipc.info(&format!(
                "Available disk space: {}",
                format_bytes(available)
            ));
        }
        Err(e) => {
            ipc.warn(&format!("Could not check disk space: {}", e));
        }
    }

    // Pre-create all unique directories first
    let mut dirs: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for file in &files {
        let relative = file
            .path
            .strip_prefix(&package.package_path)
            .unwrap_or(&file.path);
        let dest = dump_path.join(relative);
        if let Some(parent) = dest.parent() {
            dirs.insert(parent.to_path_buf());
        }
    }

    let dir_total = dirs.len() as u32;
    ipc.info(&format!("Creating {} directories...", dir_total));
    ipc.set_progress(0, dir_total);
    ipc.sync();

    for (i, dir) in dirs.iter().enumerate() {
        let _ = fs::create_dir_all(dir);
        ipc.set_progress(i as u32 + 1, dir_total);
    }

    // Sync to ensure CLI sees 100% before moving on
    ipc.set_progress(dir_total, dir_total);
    ipc.sync();

    ipc.info(&format!("Copying {} files (parallel)...", total));

    // Set initial progress in shared memory (CLI will poll this)
    ipc.set_progress(0, total);

    let processed = AtomicU32::new(0);
    let failed_files: std::sync::Mutex<Vec<(PathBuf, String)>> = std::sync::Mutex::new(Vec::new());

    // Copy files in parallel - update progress atomically in shared memory
    files.par_iter().for_each(|file| {
        let relative = file
            .path
            .strip_prefix(&package.package_path)
            .unwrap_or(&file.path);
        let dest = dump_path.join(relative);

        if let Err(e) = copy_file_buffered(&file.path, &dest)
            && let Ok(mut failed) = failed_files.lock()
        {
            failed.push((relative.to_path_buf(), e.to_string()));
        }

        // Update progress in shared memory (CLI polls this directly)
        let current = processed.fetch_add(1, Ordering::Relaxed) + 1;
        ipc.set_progress(current, total);
    });

    // Sync to ensure CLI sees 100%
    ipc.set_progress(total, total);
    ipc.sync();

    let elapsed = start_time.elapsed();
    let failed = failed_files.into_inner().unwrap_or_default();
    let final_errors = failed.len() as u32;
    let final_copied = total - final_errors;

    ipc.success(&format!(
        "Dumped {} files ({} errors) in {:.1}s",
        final_copied,
        final_errors,
        elapsed.as_secs_f64()
    ));

    // Log failed files (limit to first 10 to avoid flooding)
    if !failed.is_empty() {
        let show_count = failed.len().min(10);
        for (path, error) in failed.iter().take(show_count) {
            ipc.warn(&format!("Failed: {} - {}", path.display(), error));
        }
        if failed.len() > show_count {
            ipc.warn(&format!(
                "... and {} more failed files",
                failed.len() - show_count
            ));
        }
    }

    ipc.info(&format!("Output: {}", dump_path.display()));

    Ok(dump_path)
}

/// Recursively collect all files in a directory with progress updates
/// Returns (files, total_size)
fn collect_files_with_progress(dir: &Path, ipc: &IpcClient) -> io::Result<(Vec<FileEntry>, u64)> {
    let mut files = Vec::new();
    let mut total_size = 0u64;
    let mut dirs_scanned = 0u32;
    collect_files_recursive(dir, &mut files, &mut total_size, ipc, &mut dirs_scanned)?;
    Ok((files, total_size))
}

fn collect_files_recursive(
    dir: &Path,
    files: &mut Vec<FileEntry>,
    total_size: &mut u64,
    ipc: &IpcClient,
    dirs_scanned: &mut u32,
) -> io::Result<()> {
    // Skip symlinks and junctions to prevent infinite loops
    if dir.symlink_metadata()?.file_type().is_symlink() {
        return Ok(());
    }

    if dir.is_dir() {
        *dirs_scanned += 1;
        // Update progress (we don't know total dirs, so just show count)
        ipc.set_progress(*dirs_scanned, 0);

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;

            // Skip symlinks
            if file_type.is_symlink() {
                continue;
            }

            if file_type.is_dir() {
                collect_files_recursive(&path, files, total_size, ipc, dirs_scanned)?;
            } else if file_type.is_file() {
                // Get file size
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                *total_size += size;
                files.push(FileEntry { path, size });
            }
            // Skip other types (devices, etc.)
        }
    }

    Ok(())
}

/// Convert a path to extended-length format (\\?\) to handle paths > 260 chars
fn to_extended_path(path: &Path) -> PathBuf {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    // Only add prefix if it's an absolute path and doesn't already have the prefix
    let path_wide: Vec<u16> = path.as_os_str().encode_wide().collect();

    // Check if already has extended-length prefix (\\?\)
    let has_prefix = path_wide.len() >= 4
        && path_wide[0] == b'\\' as u16
        && path_wide[1] == b'\\' as u16
        && path_wide[2] == b'?' as u16
        && path_wide[3] == b'\\' as u16;

    if path.is_absolute() && !has_prefix && path_wide.len() > 200 {
        // Prepend \\?\
        let prefix: Vec<u16> = r"\\?\".encode_utf16().collect();
        let extended: Vec<u16> = prefix.into_iter().chain(path_wide).collect();
        PathBuf::from(OsString::from_wide(&extended))
    } else {
        path.to_path_buf()
    }
}

/// Copy file using buffered streaming (no attribute preservation, avoids EFS issues)
fn copy_file_buffered(src: &Path, dest: &Path) -> io::Result<u64> {
    // Use extended-length paths to handle long paths
    let src_extended = to_extended_path(src);
    let dest_extended = to_extended_path(dest);

    let src_file = File::open(&src_extended)?;
    let dest_file = File::create(&dest_extended)?;

    let mut reader = BufReader::with_capacity(64 * 1024, src_file);
    let mut writer = BufWriter::with_capacity(64 * 1024, dest_file);

    io::copy(&mut reader, &mut writer)
}
