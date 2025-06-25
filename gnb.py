import socket
import sctp  # Install with: pip install pysctp
import json
from datetime import datetime
import sys
import struct

def log(message):
    print(f"{datetime.now()} - gNB: {message}")

ue_sessions = {}

def create_bound_sctp_socket(local_ip, local_port=0):
    sock = sctp.sctpsocket_tcp(socket.AF_INET)
    sock.bind((local_ip, local_port))
    return sock

def create_connected_sctp_socket(local_ip, remote_host, remote_port):
    sock = create_bound_sctp_socket(local_ip)
    sock.connect((remote_host, remote_port))
    return sock

def build_gtpu_packet(teid, payload):
    flags = 0x30  # Version=1, PT=1
    msg_type = 0xFF  # G-PDU
    length = len(payload)
    header = struct.pack("!BBH", flags, msg_type, length) + struct.pack("!I", teid)
    return header + payload.encode()

def forward_to_upf(message):
    try:
        json_data = json.loads(message)
        packet_info = json_data.get("Packet", {})
        imsi = None

        # Try to find IMSI from active sessions by matching source IP
        src_ip = packet_info.get("src")
        for k, v in ue_sessions.items():
            if v.get("ip") == src_ip:
                imsi = k
                break

        if not imsi or imsi not in ue_sessions:
            log("No matching IMSI for the source IP. Dropping packet.")
            return "Unknown IMSI"

        upf_ip = ue_sessions[imsi]["upf_ip"]
        upf_port = ue_sessions[imsi]["upf_port"]

        teid = 0xABCD1234
        payload = json.dumps(packet_info)
        gtpu_packet = build_gtpu_packet(teid, payload)

        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.sendto(gtpu_packet, (upf_ip, upf_port))
        log(f"Sent GTP-U packet to UPF {upf_ip}:{upf_port}")

        # Waiting for response from UPF
        response_data, _ = udp_socket.recvfrom(4096)
        log("Received response from UPF")

        # GTP-U header is 8 bytes
        if len(response_data) >= 8:
            payload = response_data[8:]  # Skip GTP-U header
            try:
                return payload.decode('utf-8')
            except UnicodeDecodeError:
                log("Failed to decode GTP-U payload as UTF-8.")
                return "Invalid payload from UPF"
        else:
            return "Invalid GTP-U response (too short)"

    except Exception as e:
        log(f"Error in GTP-U forwarding: {e}")
        return "Error forwarding to UPF"

def handle_ue_connection(conn, addr, amf_host, amf_port, gnb_ip):
    try:
        while True:
            try:
                data = conn.recv(4096).decode()
            except Exception as e:
                log(f"Error receiving data: {e}")
                break

            if not data:
                break

            log(f"Received from UE: {data}")

            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                log("Invalid JSON received.")
                continue

            if "RegistrationRequest" in message:
                imsi = message["RegistrationRequest"].get("imsi", "")
                try:
                    amf_socket = create_connected_sctp_socket(gnb_ip, amf_host, amf_port)
                    amf_socket.send(json.dumps(message).encode())
                    log(f"Sent Registration to AMF")
                except Exception as e:
                    log(f"AMF connection failed: {e}")
                    continue

                try:
                    challenge_data = amf_socket.recv(4096).decode()
                    conn.send(challenge_data.encode())
                    log("Forwarded challenge to UE")
                except Exception as e:
                    log(f"Challenge forward failed: {e}")
                    amf_socket.close()
                    break

                try:
                    auth_response = conn.recv(4096).decode()
                    log(f"AuthResponse from UE: {auth_response}")
                    amf_socket.send(auth_response.encode())
                except Exception as e:
                    log(f"Failed to handle AuthResponse: {e}")
                    amf_socket.close()
                    continue

                try:
                    auth_result = amf_socket.recv(4096).decode()
                    conn.send(auth_result.encode())
                    log("Auth result forwarded to UE")
                except Exception as e:
                    log(f"Failed to send auth result: {e}")
                    amf_socket.close()
                    continue

                try:
                    parsed_auth = json.loads(auth_result)
                    if parsed_auth.get("authentication_result") == "Success":
                        session_request = conn.recv(4096).decode()
                        amf_socket.send(session_request.encode())
                        ip_allocation = amf_socket.recv(4096).decode()
                        conn.send(ip_allocation.encode())

                        try:
                            parsed_session = json.loads(ip_allocation)
                            session_data = parsed_session.get("SessionResponse", {})
                            allocated_ip = session_data.get("AllocatedIP")
                            upf_info = session_data.get("UPF", {})
                            upf_ip = upf_info.get("gtpu_ip")
                            upf_port = upf_info.get("gtpu_port")

                            if not all([allocated_ip, upf_ip, upf_port]):
                                raise ValueError("Incomplete session data")

                            ue_sessions[imsi] = {
                                "ip": allocated_ip,
                                "upf_ip": upf_ip,
                                "upf_port": upf_port,
                                "conn": conn
                            }
                            log(f"Stored session for IMSI {imsi} with IP {allocated_ip}, UPF {upf_ip}:{upf_port}")

                        except Exception as e:
                            log(f"Failed to parse session response or store session: {e}")

                    amf_socket.close()
                except Exception as e:
                    log(f"Session handling error: {e}")
                    amf_socket.close()

            elif "Packet" in message:
                response = forward_to_upf(data)
                try:
                    conn.send(response.encode())
                    log(f"Packet response to UE: {response}")
                except Exception as e:
                    log(f"Send packet error: {e}")

            elif "SessionTerminationRequest" in message:
                try:
                    imsi = message["SessionTerminationRequest"].get("IMSI", "")
                    amf_socket = create_connected_sctp_socket(gnb_ip, amf_host, amf_port)
                    amf_socket.send(json.dumps(message).encode())
                    log(f"Forwarded session termination to AMF for IMSI {imsi}")

                    termination_response = amf_socket.recv(4096).decode()
                    log(f"Received termination response from AMF: {termination_response}")

                    conn.send(termination_response.encode())
                    log("Sent termination response to UE")

                    if imsi in ue_sessions:
                        del ue_sessions[imsi]
                        log(f"Removed local session for IMSI {imsi}")

                    amf_socket.close()
                except Exception as e:
                    log(f"Error in handling session termination: {e}")

    except Exception as e:
        log(f"UE handler crashed: {e}")
    finally:
        conn.close()

def main():
    gnb_ip = '192.168.1.101'
    gnb_port = 8080
    amf_host = '192.168.1.102'
    amf_port = 9000

    try:
        gnb_socket = create_bound_sctp_socket(gnb_ip, gnb_port)
        gnb_socket.listen(5)
        log("gNB is listening for UE connections (SCTP)...")
    except Exception as e:
        log(f"gNB startup error: {e}")
        sys.exit(1)

    while True:
        try:
            conn, addr = gnb_socket.accept()
            log(f"New UE connected: {addr}")
            handle_ue_connection(conn, addr, amf_host, amf_port, gnb_ip)
        except Exception as e:
            log(f"Connection accept error: {e}")

if __name__ == "__main__":
    main()

