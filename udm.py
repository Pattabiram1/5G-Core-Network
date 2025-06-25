from flask import Flask, request, jsonify, Response
import sqlite3
from datetime import datetime
import logging
import asyncio
import hypercorn.asyncio
import hypercorn.config
import httpx
import time

app = Flask(__name__)

# === Configuration ===
UDM_IP = "192.168.1.104"
UDM_PORT = 9003
DATABASE_FILE = "udm.db"
NRF_URL = "https://192.168.1.106:8000"  # NRF base URL

# === Logging Setup ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - UDM: %(message)s")
logger = logging.getLogger()

def log(message):
    logger.info(message)

def init_db():
    """Initialize the UDM database by creating the imsi_data table if it doesn't exist."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS imsi_data (
            imsi TEXT PRIMARY KEY,
            shared_key TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    log("Initialized UDM database: imsi_data table created.")

def query_shared_key(imsi):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT shared_key FROM users WHERE imsi = ?", (imsi,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

@app.route('/query', methods=['POST'])
def query():
    # Expected JSON: {"imsi": "<imsi>", "rand": "<rand>"}
    try:
        req = request.get_json()
        imsi = req["imsi"]
        rand = req["rand"]
    except Exception as e:
        log(f"Error parsing query: {e}")
        return Response("Invalid request", status=400, mimetype="text/plain")
    
    shared_key = query_shared_key(imsi)
    if shared_key:
        response_payload = {"shared_key": shared_key}
        log(f"Returning shared key for IMSI {imsi}")
        return jsonify(response_payload), 200
    else:
        log(f"IMSI {imsi} not found")
        return Response("IMSI_Not_Found", status=404, mimetype="text/plain")

# --- NRF Registration & Heartbeat for UDM ---
def register_with_nrf():
    payload = {
        "nf_type": "UDM",
        "nf_id": "UDM_001",
        "ip": UDM_IP,
        "port": UDM_PORT,
        "status": "available"
    }
    try:
        with httpx.Client(http2=True, verify=False, timeout=5) as client:
            url = f"{NRF_URL}/register_nf"
            response = client.post(url, json=payload)
            if response.status_code == 200:
                log("UDM registered with NRF successfully.")
            else:
                log(f"UDM NRF registration failed: {response.status_code}")
    except Exception as e:
        log(f"Exception during UDM NRF registration: {e}")

def heartbeat_to_nrf():
    payload = {
        "nf_type": "UDM",
        "nf_id": "UDM_001",
        "status": "available",
        "timestamp": datetime.utcnow().isoformat()
    }
    while True:
        try:
            with httpx.Client(http2=True, verify=False, timeout=5) as client:
                url = f"{NRF_URL}/heartbeat_nf"
                response = client.post(url, json=payload)
                if response.status_code == 200:
                    log("UDM heartbeat sent to NRF.")
                else:
                    log(f"UDM NRF heartbeat failed: {response.status_code}")
        except Exception as e:
            log(f"Exception during UDM NRF heartbeat: {e}")
        time.sleep(30)

def start_nrf_tasks():
    import threading
    threading.Thread(target=register_with_nrf, daemon=True).start()
    threading.Thread(target=heartbeat_to_nrf, daemon=True).start()

if __name__ == "__main__":
    # Initialize database (create table if not exists)
    init_db()
    
    import hypercorn.asyncio
    import hypercorn.config
    config = hypercorn.config.Config()
    config.bind = [f"{UDM_IP}:{UDM_PORT}"]
    config.certfile = "cert.pem"
    config.keyfile = "key.pem"
    config.alpn_protocols = ["h2"]
    log("Starting UDM with HTTP/2 support...")
    start_nrf_tasks()
    register_with_nrf()
    asyncio.run(hypercorn.asyncio.serve(app, config))

