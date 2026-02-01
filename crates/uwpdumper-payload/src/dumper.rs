//! Core dumping logic - copies UWP package files to an accessible location

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use rayon::prelude::*;
use thiserror::Error;
use uwpdumper_shared::IpcClient;

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

    let files = collect_files_with_progress(&package.package_path, ipc)?;
    let total = files.len() as u32;

    // Sync to ensure CLI sees scan complete
    ipc.sync();

    ipc.info(&format!("Found {} files to dump", total));

    // Pre-create all unique directories first
    let mut dirs: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for file in &files {
        let relative = file.strip_prefix(&package.package_path).unwrap_or(file);
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
    let errors = AtomicU32::new(0);

    // Copy files in parallel - update progress atomically in shared memory
    files.par_iter().for_each(|file| {
        let relative = file.strip_prefix(&package.package_path).unwrap_or(file);
        let dest = dump_path.join(relative);

        if copy_file_buffered(file, &dest).is_err() {
            errors.fetch_add(1, Ordering::Relaxed);
        }

        // Update progress in shared memory (CLI polls this directly)
        let current = processed.fetch_add(1, Ordering::Relaxed) + 1;
        ipc.set_progress(current, total);
    });

    // Sync to ensure CLI sees 100%
    ipc.set_progress(total, total);
    ipc.sync();

    let elapsed = start_time.elapsed();
    let final_errors = errors.load(Ordering::Relaxed);
    let final_copied = total - final_errors;

    ipc.success(&format!(
        "Dumped {} files ({} errors) in {:.1}s",
        final_copied,
        final_errors,
        elapsed.as_secs_f64()
    ));
    ipc.info(&format!("Output: {}", dump_path.display()));

    Ok(dump_path)
}

/// Recursively collect all files in a directory with progress updates
fn collect_files_with_progress(dir: &Path, ipc: &IpcClient) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut dirs_scanned = 0u32;
    collect_files_recursive(dir, &mut files, ipc, &mut dirs_scanned)?;
    Ok(files)
}

fn collect_files_recursive(
    dir: &Path,
    files: &mut Vec<PathBuf>,
    ipc: &IpcClient,
    dirs_scanned: &mut u32,
) -> io::Result<()> {
    if dir.is_dir() {
        *dirs_scanned += 1;
        // Update progress (we don't know total dirs, so just show count)
        ipc.set_progress(*dirs_scanned, 0);

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                collect_files_recursive(&path, files, ipc, dirs_scanned)?;
            } else {
                files.push(path);
            }
        }
    }

    Ok(())
}

/// Copy file using buffered streaming (no attribute preservation, avoids EFS issues)
fn copy_file_buffered(src: &Path, dest: &Path) -> io::Result<u64> {
    let src_file = File::open(src)?;
    let dest_file = File::create(dest)?;

    let mut reader = BufReader::with_capacity(64 * 1024, src_file);
    let mut writer = BufWriter::with_capacity(64 * 1024, dest_file);

    io::copy(&mut reader, &mut writer)
}
