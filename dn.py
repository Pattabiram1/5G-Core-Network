import socket
from datetime import datetime

DN_PORT = 9006

def log(message):
    print(f"{datetime.now()} - DN: {message}")

def dn_server():
    """DN server receives packets and sends acknowledgment."""
    log("Starting DN server...")
    dn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dn_socket.bind(('192.168.1.107', DN_PORT))
    dn_socket.listen(5)
    log(f"Listening on port {DN_PORT}...")

    while True:
        conn, addr = dn_socket.accept()
        log(f"Connected: {addr}")

        try:
            data = conn.recv(1024).decode()
            log(f"Received: {data}")

            if data.startswith("Packet"):
                conn.sendall("ACK,Received".encode())

        except Exception as e:
            log(f"Error: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    dn_server()

