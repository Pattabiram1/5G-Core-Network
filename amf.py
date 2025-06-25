import socket
import sctp  # pip install pysctp
import httpx  # pip install httpx
import json
import threading
import time
import logging
from datetime import datetime

# --- Configuration ---
AMF_IP = "192.168.1.102"
AMF_SCTP_PORT = 9000
NRF_URL = "https://192.168.1.106:8000"

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
format="%(asctime)s - AMF: %(message)s",
handlers=[logging.FileHandler("amf.log"),
logging.StreamHandler()])
logger = logging.getLogger()

def log(message):
    logger.info(message)

# --- NRF Registration & Heartbeat ---
def register_with_nrf():
    payload = {
        "nf_type": "AMF",
        "nf_id": "AMF_001",
        "ip": AMF_IP,
        "port": AMF_SCTP_PORT,
        "status": "available"
    }
    try:
        with httpx.Client(http2=True, verify=False, timeout=5) as client:
            response = client.post(f"{NRF_URL}/register_nf", json=payload)
            if response.status_code == 200:
                log("Registered with NRF successfully.")
            else:
                log(f"NRF registration failed: {response.status_code}")
    except Exception as e:
        log(f"Exception during NRF registration: {e}")

def heartbeat_to_nrf():
    payload = {
        "nf_type": "AMF",
        "nf_id": "AMF_001",
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat()
    }
    while True:
        try:
            with httpx.Client(http2=True, verify=False, timeout=5) as client:
                response = client.post(f"{NRF_URL}/heartbeat_nf", json=payload)
                if response.status_code == 200:
                    log("Heartbeat sent to NRF.")
                else:
                    log(f"NRF heartbeat failed: {response.status_code}")
        except Exception as e:
            log(f"Exception during NRF heartbeat: {e}")
        time.sleep(30)

def start_nrf_tasks():
    threading.Thread(target=register_with_nrf, daemon=True).start()
    threading.Thread(target=heartbeat_to_nrf, daemon=True).start()

# --- Store and reuse network function info ---
nf_info_cache = {}

def get_nf_from_nrf(nf_type):
    if nf_type in nf_info_cache:
        log(f"Using cached {nf_type} info: {nf_info_cache[nf_type]}")
        return nf_info_cache[nf_type]

    try:
        with httpx.Client(http2=True, verify=False, timeout=5) as client:
            response = client.get(f"{NRF_URL}/get_nf?nf_type={nf_type}")
        if response.status_code == 200:
            nf_info = response.json()
            nf_info_cache[nf_type] = nf_info  # Cache the info
            log(f"Discovered {nf_type} from NRF: {nf_info}")
            return nf_info
        else:
            log(f"NRF service discovery error: {response.status_code}")
            return None
    except Exception as e:
        log(f"Exception during NRF service discovery: {e}")
        return None

# --- SCTP Socket Setup ---
def create_sctp_socket():
    sock = sctp.sctpsocket_tcp(socket.AF_INET)
    sock.bind((AMF_IP, AMF_SCTP_PORT))
    return sock

# --- Handle gNB Connection ---
def handle_gnb_connection(conn):
    try:
        data = conn.recv(4096).decode()
        if not data:
            return
        log(f"Received from gNB: {data}")
        message = json.loads(data)

        # --- Registration Request ---
        if "RegistrationRequest" in message:
            imsi = message["RegistrationRequest"]["imsi"]
            ausf_info = get_nf_from_nrf("AUSF")
            if not ausf_info:
                conn.sendall(json.dumps({"error": "No available AUSF"}).encode())
                return

            ausf_url = f"https://{ausf_info['ip']}:{ausf_info['port']}"
            ausf_payload = {"RegistrationRequest": {"imsi": imsi}}

            try:
                with httpx.Client(http2=True, verify=False, timeout=5) as client:
                    ausf_resp = client.post(f"{ausf_url}/registration", json=ausf_payload)
                if ausf_resp.status_code != 200:
                    conn.sendall(json.dumps({"error": "Error contacting AUSF"}).encode())
                    return
                auth_challenge = ausf_resp.json()
                conn.sendall(json.dumps(auth_challenge).encode())
                log(f"Forwarded Authentication Challenge to gNB: {auth_challenge}")
            except Exception as e:
                log(f"Exception contacting AUSF: {e}")
                conn.sendall(json.dumps({"error": "Exception contacting AUSF"}).encode())
                return

            # --- Authentication Response ---
            res_data = conn.recv(4096).decode()
            log(f"Received AuthResponse from gNB: {res_data}")
            try:
                auth_response_msg = json.loads(res_data)
                with httpx.Client(http2=True, verify=False, timeout=5) as client:
                    ausf_resp2 = client.post(f"{ausf_url}/authresponse", json=auth_response_msg)
                if ausf_resp2.status_code != 200:
                    conn.sendall(json.dumps({"error": "Error from AUSF auth"}).encode())
                    return
                auth_result = ausf_resp2.json()
                conn.sendall(json.dumps(auth_result).encode())
                log(f"Forwarded Authentication Result to gNB: {auth_result}")
            except Exception as e:
                log(f"Exception during AUSF auth response: {e}")
                conn.sendall(json.dumps({"error": "Exception contacting AUSF"}).encode())
                return

            # --- Session Establishment ---
            if auth_result.get("authentication_result") == "Success":
                session_request = conn.recv(4096).decode()
                log(f"Received Session Request from gNB: {session_request}")
                try:
                    smf_info = get_nf_from_nrf("SMF")
                    if not smf_info:
                        conn.sendall(json.dumps({"error": "No available SMF"}).encode())
                        return
                    
                    smf_url = f"https://{smf_info['ip']}:{smf_info['port']}"
                    session_payload = json.loads(session_request)
                    
                    with httpx.Client(http2=True, verify=False, timeout=5) as client:
                        smf_resp = client.post(f"{smf_url}/session_establishment", json=session_payload)

                    if smf_resp.status_code != 200:
                        conn.sendall(json.dumps({"error": "Error contacting SMF"}).encode())
                        return
                    
                    ip_allocation = smf_resp.json()
                    conn.sendall(json.dumps(ip_allocation).encode())
                    log(f"Forwarded IP Allocation to gNB: {ip_allocation}")
                except Exception as e:
                    log(f"Exception contacting SMF: {e}")
                    conn.sendall(json.dumps({"error": "Exception contacting SMF"}).encode())

        # --- Session Termination ---
        elif "SessionTerminationRequest" in message:
            termination_req = message.get("SessionTerminationRequest", {})
            imsi = termination_req.get("IMSI", "")

            if not imsi:
                log("IMSI missing in Session Termination Request.")
                conn.sendall(json.dumps({"error": "Missing IMSI in termination request"}).encode())
                return

            log(f"Received Session Termination Request for IMSI: {imsi}")

            smf_info = nf_info_cache.get("SMF")
            if not smf_info:
                smf_info = get_nf_from_nrf("SMF")  # Fallback if no cached info
                if not smf_info:
                    conn.sendall(json.dumps({"error": "No available SMF"}).encode())
                    return

            smf_url = f"https://{smf_info['ip']}:{smf_info['port']}"
            termination_payload = {"SessionRelease": {"IMSI": imsi}}

            log(f"Sending termination payload to SMF: {termination_payload}")

            try:
                with httpx.Client(http2=True, verify=False, timeout=5) as client:
                    smf_resp = client.post(f"{smf_url}/session_termination", json=termination_payload)

                if smf_resp.status_code != 200:
                    conn.sendall(json.dumps({"error": "SMF termination failed"}).encode())
                    return

                termination_response = smf_resp.json()
                conn.sendall(json.dumps({"SessionTerminationResponse": termination_response}).encode())
                log(f"Forwarded Termination Response to gNB: {termination_response}")
            except Exception as e:
                log(f"Exception during SMF termination: {e}")
                conn.sendall(json.dumps({"error": "Exception during SMF termination"}).encode())

        else:
            log("Unknown message type received.")

    except Exception as e:
        log(f"Error handling gNB connection: {e}")

# --- Main Loop ---
def main():
    start_nrf_tasks()
    sctp_sock = create_sctp_socket()
    sctp_sock.listen(5)
    log("AMF SCTP server listening for gNB connections...")
    while True:
        conn, addr = sctp_sock.accept()
        log(f"Connected by gNB: {addr}")
        threading.Thread(target=handle_gnb_connection, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    main()

