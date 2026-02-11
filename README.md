# UWPDumper-RS

<div align="center">

[![Build Status](https://github.com/coconutbird/uwpdumper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/coconutbird/uwpdumper-rs/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/coconutbird/uwpdumper-rs?include_prereleases)](https://github.com/coconutbird/uwpdumper-rs/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)
[![Windows](https://img.shields.io/badge/platform-Windows%2010%2F11-blue.svg)](https://www.microsoft.com/windows)

**A modern Rust implementation of UWPDumper for extracting files from sandboxed UWP applications.**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [How It Works](#how-it-works) • [License](#license)

</div>

---

## Features

- **DLL Injection** — Injects into UWP processes to access sandboxed files
- **Parallel Extraction** — Multi-threaded file copying with rayon
- **Package Management** — List, launch, and dump UWP packages directly
- **Real-time Progress** — Live progress bar with file counts
- **Disk Space Validation** — Checks available space before dumping
- **Long Path Support** — Handles paths exceeding 260 characters
- **Error Recovery** — Logs failed files and continues extraction

## Installation

### Download Release

Download the latest release from [GitHub Releases](https://github.com/coconutbird/uwpdumper-rs/releases):

- `uwpdumper.exe` — CLI tool
- `uwpdumper_payload.dll` — Payload DLL (must be in same directory)

### Build from Source

```bash
git clone https://github.com/coconutbird/uwpdumper-rs.git
cd uwpdumper-rs
cargo build --release
```

Binaries output to `target/release/`.

## Usage

> **Note:** Run as Administrator for DLL injection to work.

### Interactive Mode

```bash
uwpdumper.exe
```

Scans for running UWP processes and prompts for selection.

### Dump by Process

```bash
# By process name
uwpdumper.exe --name GameApp.exe

# By process ID
uwpdumper.exe --pid 12345
```

### Dump by Package

```bash
# List installed packages
uwpdumper.exe --list

# Launch and dump a package
uwpdumper.exe --package Microsoft.MyGame
```

### Custom Output

```bash
uwpdumper.exe --pid 12345 --output C:\Dumps\MyGame
```

By default, files are dumped to the app's `TempState\DUMP` folder.

## How It Works

UWP apps run in a sandbox with restricted filesystem access. UWPDumper-RS bypasses this by:

1. **Injecting a DLL** into the target UWP process
2. **Communicating via shared memory** using a ring buffer IPC protocol
3. **Copying files** from inside the sandbox to an accessible location (`TempState`)

```
┌─────────────────┐         IPC          ┌─────────────────┐
│  uwpdumper.exe  │◄────────────────────►│  payload.dll    │
│    (CLI)        │   Shared Memory      │  (in UWP app)   │
└─────────────────┘                      └─────────────────┘
        │                                        │
        ▼                                        ▼
   User Output                           Package Files
   & Progress                            → TempState/DUMP
```

### Project Structure

```
crates/
├── uwpdumper-cli/      # CLI injector
├── uwpdumper-payload/  # Injected DLL
└── uwpdumper-shared/   # IPC protocol
```

## Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Windows 10/11 (64-bit) |
| **Rust** | 1.85+ (Rust 2024 edition) |
| **Privileges** | Administrator |

## License

MIT License — see [LICENSE](LICENSE) for details.
