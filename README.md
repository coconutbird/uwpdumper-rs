# uwpdumper-rs

[![CI](https://github.com/coconutbird/uwpdumper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/coconutbird/uwpdumper-rs/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/coconutbird/uwpdumper-rs)](https://github.com/coconutbird/uwpdumper-rs/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://github.com/coconutbird/uwpdumper-rs)

A modern Rust implementation of UWPDumper for extracting files from sandboxed UWP (Universal Windows Platform) applications on Windows.

## Overview

UWP applications (including Xbox Game Pass games) run in a sandboxed environment that restricts file access. **uwpdumper-rs** solves this by injecting a DLL into UWP processes that copies files from inside the sandbox to an accessible location.

**Key concept:** The tool injects into a running UWP process, gains access to the sandboxed package files, and copies them to the app's `TempState` folder (which is accessible from outside the sandbox).

## Features

- 🎮 **Launch & Dump** - Launch UWP apps and dump their files automatically
- 💉 **Process Injection** - Inject into running UWP processes by name or PID
- 📦 **Package Discovery** - List and search installed UWP packages
- 📊 **Real-time Progress** - Live progress bar with file counts
- ⚡ **Parallel Extraction** - Multi-threaded file copying with rayon
- 💾 **Disk Space Check** - Validates available space before dumping
- 📁 **Long Path Support** - Handles paths exceeding 260 characters
- 🔄 **Error Recovery** - Logs failed files and continues extraction
- 🔒 **UWP Compatible** - Proper ACL handling for UWP sandbox access

## Quick Start

1. **Download** the [latest release](https://github.com/coconutbird/uwpdumper-rs/releases/latest) and extract
2. **Find your game's package name**: `uwpdumper --list`
3. **Dump the package**: `uwpdumper --package YourGame`
4. **Find your files** in: `%LOCALAPPDATA%\Packages\<PackageFamilyName>\AC\TempState\DUMP\`

## Installation

### Prerequisites

- Windows 10/11
- Administrator privileges (required for DLL injection)

### Download

Download the zip from [GitHub Releases](https://github.com/coconutbird/uwpdumper-rs/releases/latest) and extract. The zip contains:
- `uwpdumper.exe` - CLI tool
- `uwpdumper_payload.dll` - Injected DLL (must be in same folder as exe)

### Building from Source

```bash
cargo build --release
```

The output binaries will be in `target/release/`.

## Usage

### Launch and dump a UWP app

```bash
# First, find your game's package name
uwpdumper --list

# Launch and dump by package name (partial match works)
uwpdumper --package HaloWars
```

### Inject into an already-running process

```bash
# By process name
uwpdumper --name HaloWars2_WinAppDX12Final.exe

# By process ID
uwpdumper --pid 12345
```

### Interactive mode

```bash
# Run without arguments to see a list of running UWP processes
uwpdumper
```

### Custom output directory

```bash
# Copy dumped files to a custom location
uwpdumper --package HaloWars --output C:\Dumps\HaloWars
```

## Output Location

By default, files are dumped to:

```
%LOCALAPPDATA%\Packages\<PackageFamilyName>\AC\TempState\DUMP\
```

This location is used because:
- The injected DLL runs inside the UWP sandbox
- `AC\TempState` (Application Container TempState) is one of the few folders a sandboxed app can write to
- It's also accessible from outside the sandbox

Use `--output` to copy files to a custom location after dumping.

## Architecture

The project consists of three crates:

| Crate              | Description                                    |
|--------------------|------------------------------------------------|
| `uwpdumper-cli`    | Command-line interface for launching/injecting |
| `uwpdumper-payload`| DLL injected into target processes             |
| `uwpdumper-shared` | Shared IPC protocol and message types          |

### How it works

1. **CLI** creates shared memory with proper ACLs for UWP sandbox access
2. **CLI** injects the payload DLL into the target process
3. **DLL** scans the package directory and copies files to `TempState\DUMP`
4. **IPC** communicates progress and status between CLI and DLL via ring buffer
5. **CLI** optionally copies files to a custom output directory

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

## CLI Options

| Option              | Description                              |
|---------------------|------------------------------------------|
| `-n, --name <NAME>` | Process name to inject into              |
| `-p, --pid <PID>`   | Process ID to inject into                |
| `-l, --list`        | List all installed UWP packages          |
| `--package <NAME>`  | Package name to launch and dump          |
| `-o, --output <DIR>`| Custom output directory for dumped files |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Disclaimer

This tool is intended for legitimate purposes such as backup and modding. Use responsibly and in accordance with the terms of service of the applications you dump.
