# UWPDumper-RS

[![CI](https://github.com/coconutbird/uwpdumper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/coconutbird/uwpdumper-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)

A modern Rust implementation of UWPDumper for extracting files from sandboxed UWP (Universal Windows Platform) applications on Windows.

## Features

- **DLL Injection** - Injects into running UWP processes to access sandboxed files
- **Shared Memory IPC** - Communicates between CLI and injected DLL via memory-mapped files
- **Parallel File Copying** - Uses rayon for fast multi-threaded file extraction
- **Package Management** - List installed UWP packages and launch them directly
- **Real-time Progress** - Live progress bar with file count and speed

## Installation

### From Source

```bash
git clone https://github.com/coconutbird/uwpdumper-rs.git
cd uwpdumper-rs
cargo build --release
```

Binaries will be in `target/release/`:

- `uwpdumper.exe` - CLI tool
- `uwpdumper_payload.dll` - Injected payload DLL

## Usage

### Interactive Mode

```bash
uwpdumper.exe
```

Lists running UWP processes and lets you select one to dump.

### By Process Name

```bash
uwpdumper.exe --name HaloWars2_WinAppDX12Final.exe
```

### By Process ID

```bash
uwpdumper.exe --pid 12345
```

### List Installed Packages

```bash
uwpdumper.exe --list
```

### Launch and Dump Package

```bash
uwpdumper.exe --package Microsoft.HoganThreshold
```

### Custom Output Directory

```bash
uwpdumper.exe --pid 12345 --output C:\Dumps\MyApp
```

## Architecture

```
uwpdumper-rs/
├── crates/
│   ├── uwpdumper-cli/      # CLI injector tool
│   ├── uwpdumper-payload/  # DLL payload injected into UWP process
│   └── uwpdumper-shared/   # Shared IPC protocol and types
```

The CLI creates a shared memory region, injects the DLL into the target UWP process, and communicates via a ring buffer protocol. The DLL copies files from the sandboxed package directory to an accessible location.

## Requirements

- Windows 10/11
- Rust 1.85+ (uses Rust 2024 edition)
- Administrator privileges (for DLL injection)

## License

MIT License - see [LICENSE](LICENSE) for details.
