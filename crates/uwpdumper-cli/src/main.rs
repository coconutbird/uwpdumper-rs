//! UWPDumper CLI - injects DLL into UWP processes and displays output

mod inject;
mod package;
mod process;

use clap::Parser;
use colored::Colorize;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use uwpdumper_shared::{IpcHost, LogLevel, Packet, PacketId};

#[derive(Parser)]
#[command(name = "uwpdumper")]
#[command(about = "Modern UWP file dumper - extracts files from sandboxed UWP applications")]
#[command(version)]
struct Args {
    /// Process name to inject into (e.g., HaloWars2_WinAppDX12Final.exe)
    #[arg(short, long)]
    name: Option<String>,

    /// Process ID to inject into
    #[arg(short, long)]
    pid: Option<u32>,

    /// List all installed UWP packages
    #[arg(short, long)]
    list: bool,

    /// Package name to launch and dump (e.g., Microsoft.HoganThreshold)
    #[arg(long = "package")]
    package: Option<String>,

    /// Custom output directory for dumped files
    #[arg(short, long)]
    output: Option<String>,
}

fn main() {
    let args = Args::parse();

    print_banner();

    // Handle --list flag
    if args.list {
        list_packages_command();
        return;
    }

    // Handle --package flag (launch and dump)
    if let Some(ref pkg_name) = args.package {
        launch_and_dump(pkg_name, args.output.as_deref());
        return;
    }

    // Get DLL path (same directory as exe)
    let dll_path = match get_dll_path() {
        Some(p) => p,
        None => return,
    };

    // Determine target process
    let target = if args.pid.is_some() || args.name.is_some() {
        match find_process(args.pid, args.name.as_deref()) {
            Some(p) => p,
            None => {
                if let Some(pid) = args.pid {
                    eprintln!("{} No UWP process found with PID: {}", "[ERROR]".red(), pid);
                } else if let Some(ref name) = args.name {
                    eprintln!(
                        "{} No UWP process found matching: {}",
                        "[ERROR]".red(),
                        name
                    );
                }
                return;
            }
        }
    } else {
        // Interactive mode
        match select_process_interactive() {
            Some(p) => p,
            None => return,
        }
    };

    println!(
        "\n{} Selected: {} (PID: {})",
        "[INFO]".blue(),
        target.name,
        target.pid
    );

    inject_and_dump(target.pid, &dll_path, args.output.as_deref());
}

fn print_banner() {
    println!();
    println!("{}", "UWPDumper-RS".cyan().bold());
    println!("{}", "Modern UWP file dumper".white());
    println!();
}

/// Get and validate the DLL path
/// Returns None if DLL doesn't exist
fn get_dll_path() -> Option<PathBuf> {
    let exe_path = std::env::current_exe().unwrap_or_default();
    let dll_path = exe_path
        .parent()
        .unwrap_or(&exe_path)
        .join("uwpdumper_payload.dll");

    if dll_path.exists() {
        Some(dll_path)
    } else {
        eprintln!(
            "{} DLL not found at: {}",
            "[ERROR]".red(),
            dll_path.display()
        );
        eprintln!("Make sure uwpdumper_payload.dll is in the same directory as this executable.");
        None
    }
}

fn list_packages_command() {
    println!("{} Listing installed UWP packages...\n", "[INFO]".blue());

    match package::list_packages() {
        Ok(mut packages) => {
            if packages.is_empty() {
                println!("{} No UWP packages found.", "[WARN]".yellow());
            } else {
                // Sort alphabetically by display name (case-insensitive)
                packages.sort_by(|a, b| {
                    a.display_name
                        .to_lowercase()
                        .cmp(&b.display_name.to_lowercase())
                });

                println!(
                    "{:<35} {}",
                    "Display Name".cyan().bold(),
                    "Package Name".cyan().bold(),
                );

                println!("{}", "-".repeat(80));

                for pkg in packages {
                    println!("{:<35} {}", pkg.display_name, pkg.name);
                }
            }
        }
        Err(e) => {
            eprintln!("{} Failed to list packages: {}", "[ERROR]".red(), e);
        }
    }
}

fn launch_and_dump(pkg_name: &str, output_path: Option<&str>) {
    // Find the package
    println!("{} Looking for package: {}", "[INFO]".blue(), pkg_name);

    let pkg = match package::find_package(pkg_name) {
        Ok(Some(p)) => p,
        Ok(None) => {
            eprintln!(
                "{} No package found matching: {}",
                "[ERROR]".red(),
                pkg_name
            );
            return;
        }
        Err(e) => {
            eprintln!("{} Failed to find package: {}", "[ERROR]".red(), e);
            return;
        }
    };

    println!(
        "{} Found: {} ({})",
        "[OK]".green(),
        pkg.name,
        pkg.family_name
    );

    println!("{} Launching application...", "[INFO]".blue());

    // Launch the app
    let pid = match package::launch_package(&pkg) {
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("{} Failed to launch package: {}", "[ERROR]".red(), e);
            return;
        }
    };

    println!("{} Launched with PID: {}", "[OK]".green(), pid);

    // Immediately suspend the process before it can do anything
    println!("{} Suspending process...", "[INFO]".blue());
    if let Err(e) = inject::suspend_process(pid) {
        eprintln!("{} Failed to suspend process: {}", "[ERROR]".red(), e);
        return;
    }
    println!("{} Process suspended", "[OK]".green());

    // Now inject and dump while suspended
    let dll_path = match get_dll_path() {
        Some(p) => p,
        None => {
            // Resume process before returning on error
            let _ = inject::resume_process(pid);
            return;
        }
    };

    inject_and_dump_suspended(pid, &dll_path, output_path);
}

/// Inject and dump a suspended process, resuming it on failure
fn inject_and_dump_suspended(pid: u32, dll_path: &std::path::Path, output_path: Option<&str>) {
    // Helper to resume process on early return
    let resume_on_error = || {
        if let Err(e) = inject::resume_process(pid) {
            eprintln!("{} Failed to resume process: {}", "[WARN]".yellow(), e);
        } else {
            println!("{} Process resumed", "[INFO]".blue());
        }
    };

    // Set up IPC
    println!("{} Setting up IPC...", "[INFO]".blue());
    let mut ipc = match IpcHost::create(pid) {
        Ok(ipc) => ipc,
        Err(e) => {
            eprintln!("{} Failed to create IPC: {}", "[ERROR]".red(), e);
            resume_on_error();
            return;
        }
    };

    // Inject DLL
    println!("{} Injecting DLL...", "[INFO]".blue());
    let process = match inject::inject_dll(pid, dll_path) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("{} Injection failed: {}", "[ERROR]".red(), e);
            resume_on_error();
            return;
        }
    };

    println!(
        "{} DLL injected, waiting for ready signal...",
        "[OK]".green()
    );

    // Wait for ready signal
    let mut ready = false;
    for _ in 0..500 {
        if !process.is_alive() {
            eprintln!(
                "{} Target process crashed during initialization",
                "[ERROR]".red()
            );
            return; // Process is dead, no need to resume
        }
        if let Some(pkt) = ipc.try_read()
            && pkt.id() == PacketId::Ready
        {
            ready = true;
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    if !ready {
        eprintln!("{} Timeout waiting for DLL ready signal", "[ERROR]".red());
        resume_on_error();
        return;
    }

    // Start dump and run message loop
    println!("{} Starting dump...\n", "[INFO]".blue());

    ipc.start_dump();

    let dump_path = run_message_loop(&mut ipc, &process);

    // If custom output path was specified, copy files from TempState to destination
    if let (Some(output), Some(source)) = (output_path, dump_path) {
        copy_to_output(&source, output);
    }

    println!();
}

fn inject_and_dump(pid: u32, dll_path: &std::path::Path, output_path: Option<&str>) {
    // Check if process is 32-bit (we only support 64-bit)
    match inject::is_process_32bit(pid) {
        Ok(true) => {
            eprintln!(
                "{} Target process is 32-bit. This tool only supports 64-bit processes.",
                "[ERROR]".red()
            );
            eprintln!(
                "{} You need a 32-bit build of the injector and payload DLL.",
                "[INFO]".blue()
            );
            return;
        }
        Ok(false) => {} // 64-bit, continue
        Err(e) => {
            eprintln!(
                "{} Warning: Could not determine process architecture: {}",
                "[WARN]".yellow(),
                e
            );
            // Continue anyway, injection will fail if architecture mismatch
        }
    }

    // Set up IPC
    println!("{} Setting up IPC...", "[INFO]".blue());
    let mut ipc = match IpcHost::create(pid) {
        Ok(ipc) => ipc,
        Err(e) => {
            eprintln!("{} Failed to create IPC: {}", "[ERROR]".red(), e);
            return;
        }
    };

    // Inject DLL
    println!("{} Injecting DLL...", "[INFO]".blue());
    let process = match inject::inject_dll(pid, dll_path) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("{} Injection failed: {}", "[ERROR]".red(), e);
            return;
        }
    };

    println!(
        "{} DLL injected, waiting for ready signal...",
        "[OK]".green()
    );

    // Wait for ready signal
    let mut ready = false;
    for _ in 0..500 {
        if !process.is_alive() {
            eprintln!(
                "{} Target process crashed during initialization",
                "[ERROR]".red()
            );
            return;
        }
        if let Some(pkt) = ipc.try_read()
            && pkt.id() == PacketId::Ready
        {
            ready = true;
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    if !ready {
        eprintln!("{} Timeout waiting for DLL ready signal", "[ERROR]".red());
        return;
    }

    // Start dump and run message loop
    println!("{} Starting dump...\n", "[INFO]".blue());

    ipc.start_dump();

    let dump_path = run_message_loop(&mut ipc, &process);

    // If custom output path was specified, copy files from TempState to destination
    if let (Some(output), Some(source)) = (output_path, dump_path) {
        copy_to_output(&source, output);
    }

    println!();
}

/// Copy dumped files from TempState to custom output directory
fn copy_to_output(source: &str, dest: &str) {
    use rayon::prelude::*;
    use std::path::Path;
    use std::sync::atomic::{AtomicU32, Ordering};

    let source_path = Path::new(source);
    let dest_path = Path::new(dest);

    if !source_path.exists() {
        eprintln!("{} Source path does not exist: {}", "[ERROR]".red(), source);
        return;
    }

    println!("\n{} Copying files to custom output...", "[INFO]".blue());

    // Create destination directory
    if let Err(e) = std::fs::create_dir_all(dest_path) {
        eprintln!(
            "{} Failed to create output directory: {}",
            "[ERROR]".red(),
            e
        );
        return;
    }

    // Collect all files and directories
    let entries: Vec<_> = walkdir::WalkDir::new(source_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .collect();

    // Create all directories first (sequential, fast)
    for entry in entries.iter().filter(|e| e.file_type().is_dir()) {
        let relative = entry
            .path()
            .strip_prefix(source_path)
            .unwrap_or(entry.path());
        let dst = dest_path.join(relative);
        let _ = std::fs::create_dir_all(&dst);
    }

    // Collect files only
    let files: Vec<_> = entries
        .into_iter()
        .filter(|e| e.file_type().is_file())
        .collect();

    let file_count = files.len();
    println!(
        "{} Copying {} files (parallel)...",
        "[INFO]".blue(),
        file_count
    );

    use std::sync::Arc;

    let copied = Arc::new(AtomicU32::new(0));
    let errors = Arc::new(AtomicU32::new(0));
    let processed = Arc::new(AtomicU32::new(0));

    // Spawn progress display thread
    let total = file_count as u32;
    let progress_handle = std::thread::spawn({
        let processed = Arc::clone(&processed);
        move || {
            let mut last_percent = 0;
            loop {
                let current = processed.load(Ordering::Relaxed);
                let percent = if total > 0 {
                    (current * 100 / total) as usize
                } else {
                    0
                };
                if percent != last_percent || current == total {
                    print!(
                        "\r\x1b[K{} [{}{}] {}% ({}/{})",
                        "[COPY]".cyan(),
                        "█".repeat(percent * 40 / 100),
                        "░".repeat(40 - percent * 40 / 100),
                        percent,
                        current,
                        total
                    );
                    let _ = io::stdout().flush();
                    last_percent = percent;
                }
                if current >= total {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    });

    // Copy files in parallel
    files.par_iter().for_each(|entry| {
        let src = entry.path();
        let relative = src.strip_prefix(source_path).unwrap_or(src);
        let dst = dest_path.join(relative);

        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        if std::fs::copy(src, &dst).is_ok() {
            copied.fetch_add(1, Ordering::Relaxed);
        } else {
            errors.fetch_add(1, Ordering::Relaxed);
        }
        processed.fetch_add(1, Ordering::Relaxed);
    });

    let _ = progress_handle.join();

    let final_copied = copied.load(Ordering::Relaxed);
    let final_errors = errors.load(Ordering::Relaxed);

    println!();
    println!(
        "{} Copied {} files ({} errors) to {}",
        "[OK]".green(),
        final_copied,
        final_errors,
        dest
    );
}

fn find_process(pid: Option<u32>, name: Option<&str>) -> Option<process::ProcessInfo> {
    let processes = process::list_uwp_processes().ok()?;

    if let Some(pid) = pid {
        processes.into_iter().find(|p| p.pid == pid)
    } else if let Some(name) = name {
        let name_lower = name.to_lowercase();
        processes
            .into_iter()
            .find(|p| p.name.to_lowercase().contains(&name_lower))
    } else {
        None
    }
}

fn select_process_interactive() -> Option<process::ProcessInfo> {
    println!("{} Scanning for UWP processes...", "[INFO]".blue());
    let processes = match process::list_uwp_processes() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} Failed to list processes: {}", "[ERROR]".red(), e);
            return None;
        }
    };

    if processes.is_empty() {
        println!("{} No UWP processes found.", "[WARN]".yellow());

        return None;
    }

    // Display process list
    println!(
        "\n{} Found {} UWP processes:\n",
        "[OK]".green(),
        processes.len()
    );
    for (i, proc) in processes.iter().enumerate() {
        println!("  [{}] {} (PID: {})", i + 1, proc.name.cyan(), proc.pid);
    }

    // Get user selection
    print!("\nEnter process number (or 0 to exit): ");
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return None;
    }

    let selection: usize = match input.trim().parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("{} Invalid input", "[ERROR]".red());
            return None;
        }
    };

    if selection == 0 || selection > processes.len() {
        return None;
    }

    Some(processes.into_iter().nth(selection - 1).unwrap())
}

/// Track if we're in the middle of a progress line
static PROGRESS_ACTIVE: AtomicBool = AtomicBool::new(false);

fn clear_progress_line() {
    if PROGRESS_ACTIVE.swap(false, Ordering::SeqCst) {
        println!(); // Move to new line
    }
}

/// Main message loop - polls progress and displays packets
/// Returns the dump path from the Complete packet if successful
fn run_message_loop(ipc: &mut IpcHost, process: &inject::ProcessHandle) -> Option<String> {
    let mut last_progress = (0u32, 0u32);

    loop {
        // Check if target process crashed
        if !process.is_alive() {
            clear_progress_line();
            eprintln!(
                "\n{} Target process crashed or was terminated",
                "[ERROR]".red()
            );
            return None;
        }

        // Process packets first (messages should appear before progress)
        while let Some(pkt) = ipc.try_read() {
            display_packet(&pkt);
            match pkt.id() {
                PacketId::Complete => {
                    return Some(pkt.message().to_string());
                }
                PacketId::Fatal => {
                    return None;
                }
                _ => {}
            }
        }

        // Poll and display progress
        let progress = ipc.get_progress();
        if progress != last_progress {
            display_progress(progress.0, progress.1);
            last_progress = progress;
        }

        // Acknowledge sync after we've displayed progress
        ipc.check_and_ack_sync();

        if ipc.is_finished() {
            clear_progress_line();
            while let Some(pkt) = ipc.try_read() {
                display_packet(&pkt);
                if pkt.id() == PacketId::Complete {
                    return Some(pkt.message().to_string());
                }
            }
            return None;
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Display progress bar
fn display_progress(current: u32, total: u32) {
    if current == 0 && total == 0 {
        return;
    }

    PROGRESS_ACTIVE.store(true, Ordering::SeqCst);

    if total == 0 {
        // Unknown total - scanning directories
        print!(
            "\r\x1b[K{} {} directories scanned",
            "[SCAN]".cyan(),
            current
        );
    } else {
        // Known total - show progress bar
        let percent = (current * 100) / total;
        let bar_width = 40;
        let filled = (percent as usize * bar_width) / 100;
        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(bar_width - filled));

        print!(
            "\r\x1b[K{} [{}] {}% ({}/{})",
            "[PROG]".cyan(),
            bar.green(),
            percent,
            current,
            total
        );
    }
    let _ = io::stdout().flush();
}

/// Display a packet from the DLL
fn display_packet(pkt: &Packet) {
    match pkt.id() {
        PacketId::Log => {
            clear_progress_line();
            match pkt.log_level() {
                Some(LogLevel::Info) => println!("{} {}", "[INFO]".blue(), pkt.message()),
                Some(LogLevel::Success) => println!("{} {}", "[OK]".green(), pkt.message()),
                Some(LogLevel::Warning) => println!("{} {}", "[WARN]".yellow(), pkt.message()),
                Some(LogLevel::Error) => println!("{} {}", "[ERROR]".red(), pkt.message()),
                None => {}
            }
        }
        PacketId::Complete => {
            clear_progress_line();
            println!("{} {}", "[DONE]".green().bold(), pkt.message());
        }
        PacketId::Fatal => {
            clear_progress_line();
            println!("{} {}", "[FATAL]".red().bold(), pkt.message());
        }
        _ => {}
    }
}
