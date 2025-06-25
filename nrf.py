from flask import Flask, request, jsonify, Response
import logging
from datetime import datetime
import asyncio
import hypercorn.asyncio
import hypercorn.config

app = Flask(__name__)

# NRF configuration
NRF_IP = "192.168.1.106"
NRF_PORT = 8000

# Logging setup
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - NRF: %(message)s",
                    handlers=[logging.StreamHandler()])
logger = logging.getLogger()

def log(message):
    logger.info(message)

# In-memory registry for all NF's
# Structure: { nf_type: [ { "nf_id": <id>, "ip": <ip>, "port": <port>, "status": <status>, "last_updated": <timestamp>, "services": <services> }, ... ] }
nf_registry = {}

@app.route('/register_nf', methods=['POST'])
def register_nf():
    try:
        data = request.get_json()
        nf_type = data.get("nf_type")
        nf_id = data.get("nf_id")
        ip = data.get("ip")
        port = data.get("port")
        status = data.get("status")
        services = data.get("services", [])
        if not all([nf_type, nf_id, ip, port, status]):
            return Response("Invalid registration data", status=400, mimetype="text/plain")
        entry = {
            "nf_id": nf_id,
            "ip": ip,
            "port": port,
            "status": status,
            "last_updated": datetime.utcnow().isoformat(),
            "services": services
        }
        nf_registry.setdefault(nf_type, [])
        # Remove any previous registration with the same nf_id
        nf_registry[nf_type] = [nf for nf in nf_registry[nf_type] if nf["nf_id"] != nf_id]
        nf_registry[nf_type].append(entry)
        log(f"Registered {nf_type}: {nf_id}, IP: {ip}, Port: {port}, Status: {status}, Services: {services}")
        return jsonify({"result": "Registered"}), 200
    except Exception as e:
        log(f"Error during registration: {e}")
        return Response("Error", status=500, mimetype="text/plain")

@app.route('/heartbeat_nf', methods=['POST'])
def heartbeat_nf():
    try:
        data = request.get_json()
        nf_type = data.get("nf_type")
        nf_id = data.get("nf_id")
        status = data.get("status")
        timestamp = data.get("timestamp")
        if not all([nf_type, nf_id, status, timestamp]):
            return Response("Invalid heartbeat data", status=400, mimetype="text/plain")
        if nf_type in nf_registry:
            updated = False
            for nf in nf_registry[nf_type]:
                if nf["nf_id"] == nf_id:
                    nf["status"] = status
                    nf["last_updated"] = timestamp
                    updated = True
                    break
            if updated:
                log(f"Heartbeat received for {nf_type} {nf_id}")
                return jsonify({"result": "Heartbeat received"}), 200
            else:
                return Response("NF not registered", status=404, mimetype="text/plain")
        else:
            return Response("NF type not registered", status=404, mimetype="text/plain")
    except Exception as e:
        log(f"Error during heartbeat: {e}")
        return Response("Error", status=500, mimetype="text/plain")

@app.route('/get_nf', methods=['GET'])
def get_nf():
    nf_type = request.args.get("nf_type")
    if not nf_type:
        return Response("NF type required", status=400, mimetype="text/plain")
    if nf_type not in nf_registry or not nf_registry[nf_type]:
        return Response("No NF registered for this type", status=404, mimetype="text/plain")
    # For simplicity, return the first NF with status "available"
    for nf in nf_registry[nf_type]:
        if nf["status"] == "available":
            log(f"Allocating {nf_type}: {nf['nf_id']}")
            return jsonify(nf), 200
    return Response("No available NF of requested type", status=404, mimetype="text/plain")

@app.route('/release_nf', methods=['POST'])
def release_nf():
    try:
        data = request.get_json()
        nf_type = data.get("nf_type")
        nf_id = data.get("nf_id")
        status = data.get("status")
        if not all([nf_type, nf_id, status]):
            return Response("Invalid release data", status=400, mimetype="text/plain")
        if nf_type in nf_registry:
            updated = False
            for nf in nf_registry[nf_type]:
                if nf["nf_id"] == nf_id:
                    nf["status"] = status
                    nf["last_updated"] = datetime.utcnow().isoformat()
                    updated = True
                    break
            if updated:
                log(f"Released {nf_type} {nf_id}")
                return jsonify({"result": "Released"}), 200
            else:
                return Response("NF not found", status=404, mimetype="text/plain")
        else:
            return Response("NF type not registered", status=404, mimetype="text/plain")
    except Exception as e:
        log(f"Error during NF release: {e}")
        return Response("Error", status=500, mimetype="text/plain")

@app.route('/get_all_nfs', methods=['GET'])
def get_all_nfs():
    return jsonify(nf_registry), 200

if __name__ == "__main__":
    import hypercorn.asyncio
    import hypercorn.config
    config = hypercorn.config.Config()
    config.bind = [f"{NRF_IP}:{NRF_PORT}"]
    config.certfile = "cert.pem"
    config.keyfile = "key.pem"
    config.alpn_protocols = ["h2"]
    log("Starting NRF with HTTP/2 support...")
    asyncio.run(hypercorn.asyncio.serve(app, config))

