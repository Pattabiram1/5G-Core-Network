from flask import Flask, request, jsonify, Response
import sqlite3
import httpx
import threading
import time
import logging
import asyncio
import hypercorn.asyncio
import hypercorn.config
from datetime import datetime

app = Flask(__name__)

# === Configuration ===
SMF_IP = "192.168.1.105"
SMF_PORT = 9004
NRF_URL = "https://192.168.1.106:8000"
SMF_DB = "smf.db"

# === Logging Setup ===
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - SMF: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger()

def log(msg): logger.info(msg)

# === NRF Registration & Heartbeats ===
def register_with_nrf():
    payload = {
        "nf_type": "SMF",
        "nf_id": "SMF_001",
        "ip": SMF_IP,
        "port": SMF_PORT,
        "status": "available",
        "services": [
            {
                "serviceName": "N11SessionManagement",
                "ip": SMF_IP,
                "port": SMF_PORT,
                "protocol": "https",
                "api": "/session_establishment"
            },
            {
                "serviceName": "N11SessionTermination",
                "ip": SMF_IP,
                "port": SMF_PORT,
                "protocol": "https",
                "api": "/session_termination"
            }
        ]
    }
    try:
        with httpx.Client(http2=True, verify=False, timeout=5) as client:
            resp = client.post(f"{NRF_URL}/register_nf", json=payload)
            if resp.status_code == 200:
                log("Registered with NRF successfully.")
            else:
                log(f"NRF registration failed: {resp.status_code}")
    except Exception as e:
        log(f"NRF registration exception: {e}")

def heartbeat_to_nrf():
    payload = {
        "nf_type": "SMF",
        "nf_id": "SMF_001",
        "status": "available",
        "timestamp": datetime.utcnow().isoformat()
    }
    while True:
        try:
            with httpx.Client(http2=True, verify=False, timeout=5) as client:
                client.post(f"{NRF_URL}/heartbeat_nf", json=payload)
        except Exception as e:
            log(f"Heartbeat error: {e}")
        time.sleep(30)

def start_nrf_tasks():
    threading.Thread(target=register_with_nrf, daemon=True).start()
    threading.Thread(target=heartbeat_to_nrf, daemon=True).start()

# === Discover NF from NRF ===
def get_nf_from_nrf(nf_type):
    try:
        with httpx.Client(http2=True, verify=False, timeout=5) as client:
            resp = client.get(f"{NRF_URL}/get_nf", params={"nf_type": nf_type})
        if resp.status_code == 200:
            nf_info = resp.json()
            log(f"Discovered {nf_type}: {nf_info}")
            return nf_info
    except Exception as e:
        log(f"Error discovering {nf_type}: {e}")
    return None

# === IP Management ===
def allocate_ip_from_db(imsi):
    try:
        conn = sqlite3.connect(SMF_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM ip_pool WHERE status = 'free' LIMIT 1")
        result = cursor.fetchone()
        if result:
            ip = result[0]
            cursor.execute("UPDATE ip_pool SET status = 'allocated', imsi = ? WHERE ip_address = ?", (imsi, ip))
            conn.commit()
            log(f"Allocated IP {ip} to IMSI {imsi}")
            return ip
        else:
            log("No free IPs available.")
            return None
    except sqlite3.Error as e:
        log(f"Database error during IP allocation: {e}")
        return None
    finally:
        conn.close()

# === Session Establishment Endpoint ===
@app.route('/session_establishment', methods=['POST'])
def session():
    try:
        req = request.get_json()
        imsi = req["SessionRequest"]["IMSI"]
        log(f"Session Request from AMF for IMSI: {imsi}")

        # Step 1: Allocate IP from DB
        allocated_ip = allocate_ip_from_db(imsi)
        if not allocated_ip:
            return jsonify({"error": "No IP available"}), 503

        # Step 2: Discover UPF from NRF
        upf = get_nf_from_nrf("UPF")
        if not upf or "services" not in upf:
            return jsonify({"error": "UPF not available"}), 503

        n4_service = next((s for s in upf["services"] if s.get("serviceName") == "N4SessionManagement"), None)
        gtpu_service = next((s for s in upf["services"] if s.get("serviceName") == "GTPUTunnel"), None)

        if not n4_service or not gtpu_service:
            return jsonify({"error": "UPF missing required services"}), 500

        # Step 3: Notify UPF via HTTPS
        notify_payload = {"imsi": imsi, "ip": allocated_ip}
        notify_url = f"{n4_service['protocol']}://{n4_service['ip']}:{n4_service['port']}{n4_service.get('api', '/ip_allocation')}"

        try:
            with httpx.Client(http2=True, verify=False, timeout=5) as client:
                notify_resp = client.post(notify_url, json=notify_payload)
                if notify_resp.status_code != 200:
                    log(f"UPF notification failed: {notify_resp.status_code}")
        except Exception as e:
            log(f"Error notifying UPF: {e}")

        # Step 4: Respond to AMF
        response_payload = {
            "SessionResponse": {
                "AllocatedIP": allocated_ip,
                "UPF": {
                    "gtpu_ip": gtpu_service["ip"],
                    "gtpu_port": gtpu_service["port"]
                }
            }
        }
        return jsonify(response_payload), 200

    except Exception as e:
        log(f"Session establishment error: {e}")
        return Response("Session error", status=500, mimetype="text/plain")

# === Session Termination Endpoint ===
@app.route('/session_termination', methods=['POST'])
def session_termination():
    try:
        req = request.get_json()
        imsi = req.get("SessionRelease", {}).get("IMSI")
        log(f"Session Termination Request received for IMSI: {imsi}")

        if not imsi:
            return jsonify({"error": "Missing IMSI"}), 400

        # Step 1: Get allocated IP from DB
        conn = sqlite3.connect(SMF_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM ip_pool WHERE imsi = ? AND status = 'allocated'", (imsi,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            log(f"No active session found for IMSI {imsi}")
            return jsonify({"message": "No active session found"}), 404

        ip_address = row[0]

        # Step 2: Release the IP
        cursor.execute("UPDATE ip_pool SET status = 'free', imsi = NULL WHERE ip_address = ?", (ip_address,))
        conn.commit()
        conn.close()
        log(f"Released IP {ip_address} for IMSI {imsi}")

        # Step 3: Notify UPF
        upf = get_nf_from_nrf("UPF")
        if not upf or "services" not in upf:
            return jsonify({"error": "UPF not available"}), 503

        n4_service = next((s for s in upf["services"] if s.get("serviceName") == "N4SessionManagement"), None)
        if not n4_service:
            return jsonify({"error": "N4 service not available in UPF"}), 500

        notify_url = f"{n4_service['protocol']}://{n4_service['ip']}:{n4_service['port']}{n4_service.get('api', '/ip_release')}"
        notify_payload = {"imsi": imsi, "ip": ip_address}

        try:
            with httpx.Client(http2=True, verify=False, timeout=5) as client:
                resp = client.post(notify_url, json=notify_payload)
                if resp.status_code != 200:
                    log(f"UPF IP release failed: {resp.status_code}")
        except Exception as e:
            log(f"Failed to notify UPF for session release: {e}")

        return jsonify({"message": "Session terminated successfully"}), 200

    except Exception as e:
        log(f"Session termination error: {e}")
        return Response("Session termination error", status=500, mimetype="text/plain")

# === Start Server ===
if __name__ == "__main__":
    start_nrf_tasks()
    config = hypercorn.config.Config()
    config.bind = [f"{SMF_IP}:{SMF_PORT}"]
    config.certfile = "server.crt"
    config.keyfile = "server.key"
    config.alpn_protocols = ["h2"]
    log("Starting SMF with HTTP/2 support...")
    asyncio.run(hypercorn.asyncio.serve(app, config))

