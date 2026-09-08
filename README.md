[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)

# TripleFantasy

A modular, Windows-based security research framework for adversarial simulation and defensive validation.

---

## Overview

TripleFantasy is a research-oriented software framework designed to model advanced persistent threat (APT) behaviors in controlled laboratory environments. It implements a flexible plugin architecture, encrypted communication channels, and runtime integrity checks to support the development and testing of defensive security solutions.

This project is the work of independent security researcher **Sadpainy** and is released for educational and research purposes only.

---

## Features

- Modular plugin system with runtime loading and unloading
- Encrypted network communication using AES-256-GCM and ChaCha20
- Cryptographic key derivation via HKDF
- Secure memory management with automatic zeroization
- Runtime integrity verification using SHA-256
- Configurable beacon intervals with jitter
- Anti-debugging and anti-analysis detection mechanisms
- Physical memory read/write support (hardware-level testing)
- USB propagation simulation for air-gap scenarios

---

## System Requirements

### Build Environment
- Windows 10 / Windows 11 (x64)
- Visual Studio 2022 or later
- Windows SDK 10.0.20348.0 or later

### Compiler Flags (Release Build)
```

Configuration: Release
Platform: x64
Runtime Library: Multi-threaded (/MT)
Optimization: /O2
Security Checks: /GS-
Character Set: Unicode

```

---

## Build Instructions

Compile using the Visual Studio solution or via the command line:

```cmd
cl /O2 /GS- /MT TripleFantasy.cpp advapi32.lib user32.lib ws2_32.lib shell32.lib wininet.lib
```

Ensure that all required system libraries are linked as specified.

---

## Configuration

The global configuration is defined in the tf_core::tf_global_config structure.

Example configuration values:

```cpp
cfg.magic = TF_MAGIC;
cfg.version = (TF_VERSION_MAJOR << 24) | (TF_VERSION_MINOR << 16) | TF_VERSION_BUILD;
cfg.antidebug_threshold = 30;
cfg.self_destruct_on_fail = 0;
cfg.max_modules = TF_MAX_MODULES;
```

The C2 communication parameters are configurable via the tf_c2::tf_config structure:

```cpp
cfg.c2.c2_host = "192.168.1.100";
cfg.c2.c2_port = 8080;
cfg.c2.beacon_min = 30000;
cfg.c2.beacon_max = 120000;
cfg.c2.jitter = 25;
```

All cryptographic keys are generated at runtime using the internal RNG.

---

## Usage

This framework is intended solely for use in isolated, authorized testing environments. Execution on production systems or networks without explicit permission is prohibited.

Execution

```cmd
TripleFantasy.exe
```

Runtime Sequence

1. Initialize global context
2. Perform anti-debugging and environment checks
3. Generate cryptographic keys and session identifiers
4. Connect to the configured C2 server
5. Load any available plugins
6. Enter the main operational loop (heartbeat, keylogging, command processing)

---

Plugin Interface

Plugins must implement the following entry point:

```cpp
NTSTATUS WINAPI PluginEntry(PVOID context, ULONG reason);
```

The reason parameter indicates the event:

· 1: Plugin loaded
· 2: Plugin active (execution state)
· 3: Plugin unloaded

Detailed interface specifications are provided in the tf_module class definition.

---

Cryptographic Components

· AES-256-GCM: Symmetric encryption for network payloads
· ChaCha20: Alternate stream cipher for certain operations
· HKDF: Key derivation from master secrets
· HMAC-SHA256: Message authentication
· RNG: Xorshift-based generator with hardware entropy seeding

---

Anti-Analysis Mechanisms

· PEB debugger flag detection
· NtGlobalFlag inspection
· Hardware breakpoint detection
· Software breakpoint (INT3) scanning
· Timing anomaly detection (RDTSC/RDTSCP)
· VM and sandbox detection via CPUID and registry
· Anti-hooking verification for critical system functions

---

Limitations

· Windows platform only (x64)
· Administrative privileges required for certain operations
· No built-in persistence or logging features
· Network communication requires a compatible C2 server implementation

---

Legal Notice

This software is provided for security research, penetration testing, and educational purposes only. Any unauthorized use, including deployment on systems without explicit consent, is strictly prohibited.

The author, Sadpainy, assumes no liability for misuse of this framework. Users are responsible for ensuring their activities comply with all applicable laws and regulations in their jurisdiction.

---

## License

This project is released under the MIT License. Refer to the LICENSE file for full terms.

---

Author

Sadpainy
Independent Security Researcher
https://github.com/Sadpainy

---

## Acknowledgements

This framework incorporates concepts derived from public threat intelligence and APT research. It is intended to contribute to the broader security community's understanding of modern attack techniques and defensive countermeasures.
