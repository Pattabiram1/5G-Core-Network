import json
import socket
import threading
import sqlite3
import ssl
import struct
import subprocess
from datetime import datetime
import httpx
from flask import Flask, request, jsonify
import logging

# ========== CONFIG ========== 
UPF_IP = "192.168.1.106"
UPF_HTTP_PORT = 9005
UPF_GTPU_PORT = 2152
NRF_URL = "https://192.168.1.106:8000"

DATABASE_FILE = "upf_database.db"
# ============================

# Logging 
logging.basicConfig(level=logging.INFO, format="%(asctime)s - UPF: %(message)s")
log = logging.info

# Flask App
app = Flask(__name__)

# Initialize SQLite DB
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS sessions
                   (imsi TEXT PRIMARY KEY, ip TEXT)''')
    conn.commit()
    conn.close()

# Register with NRF
def register_with_nrf():
    payload = {
        "nf_type": "UPF",
        "nf_id": "UPF_001",
        "ip": UPF_IP,
        "port": UPF_HTTP_PORT,
        "status": "available",
        "services": [
            {
                "serviceName": "N4SessionManagement",
                "ip": UPF_IP,
                "port": UPF_HTTP_PORT,
                "protocol": "https",
                "api": "/ip_allocation"
            },
            {
                "serviceName": "GTPUTunnel",
                "ip": UPF_IP,
                "port": UPF_GTPU_PORT,
                "protocol": "udp"
            }
        ]
    }

    log(f"Sending to NRF /register_nf: {json.dumps(payload, indent=2)}")

    try:
        with httpx.Client(http2=True, verify=False) as client:
            response = client.post(f"{NRF_URL}/register_nf", json=payload)
            log(f"NRF Response [{response.status_code}]: {response.text}")
            if response.status_code == 200:
                log("Registered with NRF successfully (with services).")
            else:
                log(f"Failed to register with NRF: {response.status_code}")
    except Exception as e:
        log(f"Error during NRF registration: {e}")

# Heartbeat to NRF
def send_heartbeat():
    while True:
        try:
            payload = {
                "nf_type": "UPF",
                "nf_id": "UPF_001",
                "status": "available",
                "timestamp": datetime.utcnow().isoformat()
            }
            with httpx.Client(http2=True, verify=False) as client:
                response = client.post(f"{NRF_URL}/heartbeat_nf", json=payload)
                if response.status_code == 200:
                    log("Heartbeat sent to NRF.")
        except Exception as e:
            log(f"Heartbeat error: {e}")
        import time
        time.sleep(30)

# GTP-U Server with real ping logic
def start_gtpu_server():
    def parse_gtpu_packet(packet):
        if len(packet) < 8:
            return None, None
        flags, msg_type, length = struct.unpack("!BBH", packet[:4])
        teid = struct.unpack("!I", packet[4:8])[0]
        payload = packet[8:].decode()
        return teid, payload

    def ping_real_destination(payload):
        try:
            data = json.loads(payload)
            dst_ip = data.get("dst", "")
            if not dst_ip:
                return json.dumps({"error": "Missing 'dst' IP in payload"})

            # Perform actual ping to the destination
            output = subprocess.check_output(
                ["ping", "-c", "1", dst_ip],
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=5
            )
            log(f"Ping to {dst_ip} successful.")
            return json.dumps({"ping_reply": output.splitlines()})  # Clean output into lines for clarity
        except subprocess.CalledProcessError as e:
            log(f"Ping failed: {e.output}")
            return json.dumps({"ping_reply": f"Ping failed: {e.output.splitlines()}"})
        except Exception as e:
            log(f"Ping error: {e}")
            return json.dumps({"ping_reply": f"Ping error: {str(e)}"})

    def build_gtpu_response(teid, payload):
        flags = 0x30
        msg_type = 0xFF  # G-PDU
        payload_bytes = payload.encode()  # Convert JSON payload to bytes
        header = struct.pack("!BBH", flags, msg_type, len(payload_bytes)) + struct.pack("!I", teid)
        return header + payload_bytes

    def handle_gtpu():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((UPF_IP, UPF_GTPU_PORT))
        log(f"Listening for GTP-U packets on {UPF_IP}:{UPF_GTPU_PORT}...")

        while True:
            try:
                packet, addr = sock.recvfrom(2048)
                log(f"GTP-U packet received from {addr}")

                teid, payload = parse_gtpu_packet(packet)
                if not payload:
                    log("Invalid GTP-U packet received.")
                    continue

                log(f"Parsed TEID: {hex(teid)}, Payload: {payload}")

                response_payload = ping_real_destination(payload)
                response_packet = build_gtpu_response(teid, response_payload)

                sock.sendto(response_packet, addr)
                log(f"GTP-U response sent to {addr}: {response_payload}")

            except Exception as e:
                log(f"GTP-U server error: {e}")

    threading.Thread(target=handle_gtpu, daemon=True).start()

# HTTPS API for SMF to allocate IP
@app.route('/ip_allocation', methods=['POST'])
def allocate_ip():
    try:
        content = request.json
        imsi = content.get("imsi")
        ip = content.get("ip")
        if not imsi or not ip:
            return jsonify({"error": "Missing imsi or ip"}), 400
        conn = sqlite3.connect(DATABASE_FILE)
        cur = conn.cursor()
        cur.execute("REPLACE INTO sessions (imsi, ip) VALUES (?, ?)", (imsi, ip))
        conn.commit()
        conn.close()
        log(f"Session added for IMSI: {imsi} with IP: {ip}")
        return jsonify({"result": "Session added"}), 200
    except Exception as e:
        log(f"Error in IP allocation API: {e}")
        return jsonify({"error": str(e)}), 500

# Start Everything
if __name__ == "__main__":
    init_db()
    register_with_nrf()
    threading.Thread(target=send_heartbeat, daemon=True).start()
    start_gtpu_server()
    log("Starting UPF HTTPS server (Flask) + GTP-U UDP server...")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('cert.pem', 'key.pem')
    app.run(host=UPF_IP, port=UPF_HTTP_PORT, ssl_context=context)

