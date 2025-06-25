from quart import Quart, request, jsonify, Response
import sqlite3
import hashlib
import time
from datetime import datetime
import logging
import httpx
import asyncio
import hypercorn.asyncio
import hypercorn.config

app = Quart(__name__)

# === Configuration ===
AUSF_IP = "192.168.1.103"
AUSF_PORT = 9002
DATABASE_FILE = "ausf.db"
NRF_URL = "https://192.168.1.106:8000"  # NRF base URL

# === Logging Setup ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - AUSF: %(message)s")
logger = logging.getLogger()

def log(message):
    logger.info(message)

def generate_rand():
    return hashlib.sha256(str(time.time()).encode()).hexdigest()

def generate_xres(rand, shared_key):
    return hashlib.sha256((rand + shared_key).encode()).hexdigest()

def store_auth_data(imsi, rand, xres):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS authentication_data (imsi TEXT PRIMARY KEY, rand TEXT, xres TEXT)")
    cursor.execute("REPLACE INTO authentication_data (imsi, rand, xres) VALUES (?, ?, ?)", (imsi, rand, xres))
    conn.commit()
    conn.close()
    log(f"Stored IMSI: {imsi}, RAND: {rand}, XRES: {xres}")

async def query_udm(imsi, rand):
    """Discover available UDM from NRF and query it for shared key."""
    UDM_URL = "https://192.168.1.104:9003/query"
    try:
        async with httpx.AsyncClient(http2=True, verify=False, timeout=5) as client:
            payload = {"imsi": imsi, "rand": rand}
            response = await client.post(UDM_URL, json=payload)
            log(f"UDM response: {response.text}")
            return response.json()
    except Exception as e:
        log(f"Error querying UDM: {e}")
        return {"error": "UDM query failed"}

@app.route('/registration', methods=['POST'])
async def registration():
    try:
        req = await request.get_json()
        imsi = req["RegistrationRequest"]["imsi"]
    except Exception as e:
        log(f"Error parsing registration request: {e}")
        return Response("Invalid request", status=400)
    
    rand = generate_rand()
    log(f"Generated RAND: {rand}")
    
    udm_response = await query_udm(imsi, rand)
    if "shared_key" in udm_response:
        shared_key = udm_response["shared_key"]
        xres = generate_xres(rand, shared_key)
        store_auth_data(imsi, rand, xres)
        response_payload = {"AuthenticationChallenge": {"rand": rand}}
        return jsonify(response_payload), 200
    else:
        log("IMSI not found in UDM")
        return Response("AuthenticationResult,IMSI_Not_Found", status=404, mimetype="text/plain")

@app.route('/authresponse', methods=['POST'])
async def auth_response():
    try:
        req = await request.get_json()
        res = req["AuthenticationResponse"]["res"]
        imsi = req["AuthenticationResponse"]["imsi"]
    except Exception as e:
        log(f"Error parsing auth response: {e}")
        return Response("AuthenticationResult,Failure", status=400)
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT xres FROM authentication_data WHERE imsi = ?", (imsi,))
    result = cursor.fetchone()
    conn.close()
    if not result:
        log("No stored authentication data for IMSI")
        return Response("AuthenticationResult,Failure", status=404)
    stored_xres = result[0]
    if res == stored_xres:
        log("Authentication successful")
        return jsonify({"authentication_result": "Success"}), 200
    else:
        log("Authentication failed")
        return jsonify({"authentication_result": "Failure"}), 200

# --- NRF Registration & Heartbeat for AUSF ---
async def async_register_with_nrf():
    payload = {
        "nf_type": "AUSF",
        "nf_id": "AUSF_001",
        "ip": AUSF_IP,
        "port": AUSF_PORT,
        "status": "available"
    }
    try:
        async with httpx.AsyncClient(http2=True, verify=False, timeout=5) as client:
            url = f"{NRF_URL}/register_nf"
            response = await client.post(url, json=payload)
            if response.status_code == 200:
                log("AUSF registered with NRF successfully.")
            else:
                log(f"AUSF NRF registration failed: {response.status_code}")
    except Exception as e:
        log(f"Exception during AUSF NRF registration: {e}")

async def async_heartbeat_to_nrf():
    payload = {
        "nf_type": "AUSF",
        "nf_id": "AUSF_001",
        "status": "available",
        "timestamp": datetime.utcnow().isoformat()
    }
    while True:
        try:
            async with httpx.AsyncClient(http2=True, verify=False, timeout=5) as client:
                url = f"{NRF_URL}/heartbeat_nf"
                response = await client.post(url, json=payload)
                if response.status_code == 200:
                    log("AUSF heartbeat sent to NRF.")
                else:
                    log(f"AUSF NRF heartbeat failed: {response.status_code}")
        except Exception as e:
            log(f"Exception during AUSF NRF heartbeat: {e}")
        await asyncio.sleep(30)

async def main():
    # Register and start heartbeat
    await async_register_with_nrf()
    asyncio.create_task(async_heartbeat_to_nrf())

    # Hypercorn config
    config = hypercorn.config.Config()
    config.bind = [f"{AUSF_IP}:{AUSF_PORT}"]
    config.certfile = "cert.pem"
    config.keyfile = "key.pem"
    config.alpn_protocols = ["h2"]

    log("Starting AUSF with HTTP/2 + TLS support...")
    await hypercorn.asyncio.serve(app, config)

if __name__ == "__main__":
    asyncio.run(main())

