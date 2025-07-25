![RevBot Logo](https://github.com/exfil0/RevBot/blob/main/REVBOT_LOGO_1.png)

# RevBot

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/release/python-380/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![GitHub Issues](https://img.shields.io/github/issues/exfil0/RevBot)](https://github.com/exfil0/RevBot/issues) [![GitHub Stars](https://img.shields.io/github/stars/exfil0/RevBot)](https://github.com/exfil0/RevBot/stargazers)

RevBot is a sophisticated, modular reverse shell generator crafted for penetration testing, red team operations, and cybersecurity education. It enables the creation of customizable reverse shells in multiple languages (Python, PowerShell, Bash), supporting TCP and HTTP/WebSocket protocols for stealthy command and control (C2). With built-in encryption (AES-256, TLS), data encoding, persistence mechanisms, multi-client management, file transfers, and code obfuscation, RevBot is designed to be extensible and secure. Emphasizing ethical use, it includes comprehensive logging and warnings to ensure responsible deployment.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
  - [Examples](#examples)
  - [Running the Listener](#running-the-listener)
  - [Running the Client](#running-the-client)
- [Command-Line Options](#command-line-options)
- [Warnings and Limitations](#warnings-and-limitations)
- [Security Considerations](#security-considerations)
- [Dependencies](#dependencies)
- [Roadmap](#roadmap)
- [Contribution](#contribution)
- [License](#license)
- [Disclaimer](#disclaimer)

## Features

RevBot offers a rich set of capabilities to facilitate advanced reverse shell operations:

- **Multi-Language Clients**: 
  - Python: Full feature support, including WebSocket C2, file transfers, screenshots, and AES/TLS encryption.
  - PowerShell: Basic command execution and file transfers, with .NET AES encryption and AMSI bypass.
  - Bash: Basic command execution and file transfers, with base64 encoding for data protection.
- **Protocols**:
  - TCP: Reliable for traditional reverse shells.
  - HTTP/WebSocket: Firewall evasion with persistent, bidirectional C2 communication.
- **Encryption**:
  - AES-256-CBC: Consistent implementation across clients (where supported), with random IV per message.
  - TLS: Self-signed certificates for secure TCP/WebSocket connections, auto-generated during setup.
- **Encoding**:
  - None: Raw data transfer.
  - Base64: Basic obfuscation.
  - Zlib_base64: Compression for efficient, evasive data transmission.
- **Persistence**:
  - Windows: Registry keys for auto-start.
  - Linux/macOS: Cron jobs for scheduled execution.
  - Debug logging for persistence errors to aid troubleshooting without compromising stealth.
- **Session Management**:
  - Multi-client support with threading/queues for concurrent handling.
  - Commands like `sessions` (list clients), `interact <id>` (switch sessions), and `exit` (graceful shutdown).
- **File Transfers**:
  - Upload/download small files (<1MB) with SHA256 checksums for integrity verification.
  - Basic support in PowerShell/Bash using base64 encoding.
- **Obfuscation**:
  - Randomized variable/function names and base64-encoded constants to evade static analysis.
- **Logging**:
  - Detailed session logs for auditing, saved in timestamped files.
  - Stealth mode with optional debug logging for errors.
- **Cross-Platform Compatibility**:
  - Dynamic platform detection in initial handshake.
  - Tested on Windows, Linux, and macOS.
- **Enhancements**:
  - Jittered reconnection intervals for stealth.
  - Non-blocking HTTP C2 with command/response queuing.
  - Automatic TLS certificate generation.

## Architecture

RevBot is structured as a Python package for modularity and ease of extension:

- **`generator.py`**: CLI entry point for parsing arguments and coordinating script generation.
- **`client_generator.py`**: Handles client script creation for Python, PowerShell, and Bash.
- **`listener_generator.py`**: Generates the listener script with TCP and WebSocket support.
- **`utilities.py`**: Shared functions for obfuscation, logging, TLS generation, and AES key handling.
- **`templates.py`**: Contains template strings for client and listener scripts.
- **`__init__.py`**: Package initializer.
- **`requirements.txt`**: Dependency list.

This design allows for easy addition of new client types, protocols, or features by modifying templates or utilities.

## Installation

1. **Clone the Repository**:
   ```
   git clone https://github.com/exfil0/RevBot.git
   cd RevBot
   ```

2. **Install Dependencies**:
   ```
   pip install -r revbot/requirements.txt
   ```
   Dependencies:
   - `pycryptodome`: AES encryption.
   - `websockets`: WebSocket C2.
   - `prompt_toolkit`: Interactive prompt with history.

3. **Optional Dependencies**:
   - `openssl`: For TLS certificate generation (system package, e.g., `sudo apt install openssl` on Ubuntu).

## Usage

The generator creates client and listener scripts in the specified output directory.

### Examples

1. **Python TCP with AES Encryption and Windows Persistence**:
   ```
   python3 -m revbot --lhost 192.168.1.100 --lport 4444 --shell-type python_tcp --encryption aes --persistence windows_registry --platform Windows --generate-tls
   ```

2. **PowerShell TCP with TLS**:
   ```
   python3 -m revbot --lhost 192.168.1.100 --lport 443 --shell-type powershell_tcp --encryption tls
   ```

3. **Bash TCP with Base64 Encoding**:
   ```
   python3 -m revbot --lhost 192.168.1.100 --lport 4444 --shell-type bash_tcp --encoding base64 --platform Linux
   ```

4. **HTTP/WebSocket Python Client with TLS**:
   ```
   python3 -m revbot --lhost 192.168.1.100 --lport 8080 --shell-type python_tcp --encryption tls --generate-tls
   ```

### Running the Listener
```
python3 revbot_output/revbot_listener.py
```

### Running the Client
- Python: `python3 client_python_tcp.py`
- PowerShell: `powershell -File client_powershell_tcp.ps1`
- Bash: `./client_bash_tcp.sh`

## Command-Line Options

| Option | Description | Required | Default |
|--------|-------------|----------|---------|
| `--lhost` | Listener IP address | Yes | N/A |
| `--lport` | Listener port | Yes | N/A |
| `--shell-type` | Client type (python_tcp, powershell_tcp, bash_tcp) | No | python_tcp |
| `--encoding` | Encoding scheme (none, base64, zlib_base64) | No | base64 |
| `--encryption` | Encryption type (none, aes, tls) | No | none |
| `--aes-key` | Base64-encoded AES key (32 bytes; auto-generated if omitted) | No | Auto-generated |
| `--persistence` | Persistence method (none, windows_registry) | No | none |
| `--platform` | Target platform (Windows, Linux, Darwin) | No | Windows |
| `--output-dir` | Output directory | No | revbot_output |
| `--jitter-min` | Minimum reconnect jitter (seconds) | No | 5 |
| `--jitter-max` | Maximum reconnect jitter (seconds) | No | 15 |
| `--generate-tls` | Generate self-signed TLS certificates | No | False |

## Warnings and Limitations

- **PowerShell/Bash Clients**: Limited command execution and file transfers. No WebSocket or screenshot support. AES in PowerShell uses .NET AES-256-CBC (not identical to Python's implementation). Bash uses base64 only (no AES). Use Python for advanced capabilities.
- **File Transfers**: Restricted to files <1MB to prevent buffer overflows. Larger files may cause issues; use dedicated tools for bulk transfers.
- **HTTP/WebSocket C2**: Experimental and Python-only. Ensure port forwarding for WebSocket (wss:// with TLS).
- **Dependencies**: Requires `pycryptodome`, `websockets`, `prompt_toolkit`. `openssl` for TLS.
- **Legal and Ethical Use**: RevBot is for authorized penetration testing only. Obtain explicit permission before use. Misuse may violate laws.

## Security Considerations

- **Encryption Keys**: AES keys are auto-generated (32 bytes) or user-supplied. Use strong, unique keys for production. TLS uses self-signed certificates—replace with CA-signed for real-world scenarios.
- **Obfuscation**: Helps evade basic AV, but not advanced EDR. Use responsibly.
- **Persistence**: Mechanisms like registry keys may trigger detection; test in controlled environments.
- **Logging**: Logs contain sensitive data (commands, outputs); secure log files.
- **Best Practices**: Run in isolated VMs. Avoid internet-exposed listeners without authentication.

## Dependencies

Listed in `revbot/requirements.txt`:
```
pycryptodome==3.20.0
websockets==12.0
prompt_toolkit==3.0.47
```

## Roadmap

- v1.1: Add screenshot support for PowerShell clients.
- v1.2: Implement full HTTP POST/GET C2 for PowerShell/Bash.
- v1.3: Integrate more persistence options (e.g., Windows tasks, Linux systemd).
- v2.0: Support for additional languages (e.g., Go, C#) and cloud C2 (e.g., AWS Lambda).

## Contribution

We welcome contributions! Follow these steps:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/new-feature`).
3. Commit changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature/new-feature`).
5. Create a Pull Request against the `main` branch.

Please adhere to code style guidelines and include tests for new features.

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

RevBot is provided "as is" for educational and authorized testing purposes only. The developers are not responsible for any misuse or damage caused by this tool. Always obtain explicit permission before testing on any system. Unauthorized use may violate local laws and ethical standards.
