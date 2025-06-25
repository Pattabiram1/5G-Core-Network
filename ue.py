import socket
import sctp  # Install with: pip install pysctp
import hashlib
import json
from datetime import datetime
import sys
import time

def log(message):
    print(f"{datetime.now()} - UE: {message}")

def calculate_res(rand, shared_key):
    return hashlib.sha256((rand + shared_key).encode()).hexdigest()

# === UE Configuration ===
initial_ip = "192.168.1.100"  # Temporary IP for initial setup
initial_port = 9015
gnb_ip = "192.168.1.101"
gnb_port = 8080
shared_key = "key654321"
imsi = "987654321098765"

# === Initial SCTP connection ===
sock = sctp.sctpsocket_tcp(socket.AF_INET)
try:
    sock.bind((initial_ip, initial_port))
    sock.connect((gnb_ip, gnb_port))
    log(f"Connected to gNB from initial IP {initial_ip}")
except Exception as e:
    log(f"Connection error: {e}")
    sys.exit(1)

def send_message(socket_obj, message, wait_for_reply=True):
    try:
        socket_obj.send(message.encode())
        log(f"Sent: {message}")
        if wait_for_reply:
            response = socket_obj.recv(4096).decode()
            log(f"Received: {response}")
            return response
        return ""
    except Exception as e:
        log(f"Error: {e}")
        return ""

# === Step 1: Registration Request ===
response = send_message(sock, json.dumps({"RegistrationRequest": {"imsi": imsi}}))
if not response:
    log("No response received. Exiting.")
    sock.close()
    sys.exit(1)

# === Step 2: Authentication Challenge ===
try:
    auth_challenge = json.loads(response)
    rand = auth_challenge["AuthenticationChallenge"]["rand"]
    log(f"Received RAND: {rand}")
except (json.JSONDecodeError, KeyError):
    log("Invalid Authentication Challenge.")
    sock.close()
    sys.exit(1)

# === Step 3: Authentication Response ===
res = calculate_res(rand, shared_key)
response = send_message(sock, json.dumps({"AuthenticationResponse": {"imsi": imsi, "res": res}}))

# === Step 4: Authentication Result ===
try:
    auth_result = json.loads(response)
    if auth_result.get("authentication_result") != "Success":
        log("Authentication failed.")
        sock.close()
        sys.exit(1)
except json.JSONDecodeError:
    log("Failed to parse Authentication Result JSON.")
    sock.close()
    sys.exit(1)

# === Step 5: Session Request (IP Allocation) ===
response = send_message(sock, json.dumps({"SessionRequest": {"IMSI": imsi}}))

# === Parse Session Response ===
try:
    session_response = json.loads(response)
    session_data = session_response["SessionResponse"]
    allocated_ip = session_data["AllocatedIP"]
    upf_info = session_data["UPF"]
    upf_ip = upf_info.get("gtpu_ip")
    upf_port = upf_info.get("gtpu_port")

    if not all([allocated_ip, upf_ip, upf_port]):
        raise ValueError("Missing one or more session response fields")

    log(f"✅ Assigned IP: {allocated_ip}")
    log(f"🔗 UPF IP: {upf_ip}, UPF GTP-U Port: {upf_port}")
except (json.JSONDecodeError, KeyError, ValueError) as e:
    log(f"Failed to parse session response: {e}")
    sock.close()
    sys.exit(1)

# === Rebind SCTP socket with new allocated IP ===
sock.close()
time.sleep(1)  # Small delay to ensure port is freed

sock = sctp.sctpsocket_tcp(socket.AF_INET)
try:
    sock.bind((allocated_ip, initial_port))  # Rebind with allocated IP
    sock.connect((gnb_ip, gnb_port))
    log(f"🔁 Reconnected to gNB using allocated IP {allocated_ip}")
except Exception as e:
    log(f"Reconnection error: {e}")
    sys.exit(1)

# === Step 6: Send Packet (Google Ping Request) ===
data_packet = {
    "Packet": {
        "src": allocated_ip,
        "dst": "8.8.8.8",
        "data": "ping",
        "upf": {
            "ip": upf_ip,
            "port": upf_port
        }
    }
}
send_message(sock, json.dumps(data_packet), wait_for_reply=False)

# === Step 6.5: Wait for Google Response via gNB ===
try:
    response = sock.recv(4096).decode()
    log(f"🔁 Google Response (via gNB): {response}")
except Exception as e:
    log(f"Error while waiting for Google response: {e}")

# === Step 7: Terminate Session ===
send_message(sock, json.dumps({"SessionTerminationRequest": {"IMSI": imsi}}), wait_for_reply=False)

# === Step 7.5: Receive Session Termination Response ===
try:
    response = sock.recv(4096).decode()
    log(f"✅ Session Termination Response: {response}")
except Exception as e:
    log(f"Error receiving session termination response: {e}")

# === Step 8: Close Connection ===
sock.close()
log("Connection closed.")

