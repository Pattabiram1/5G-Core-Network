# 5G-Core-Network
Restful-api Based 5G Core Network with Minimal Nodes


# 📡 5G Core Network Simulation (Ubuntu-Based)

This repository contains a complete simulation of a **5G Core Network** built in **Python** using SCTP, HTTPS REST APIs, and SQLite. The project models essential 5G control and user plane behavior, enabling registration, authentication, session management, and data transfer. The **Data Network (DN)** is simulated using Google's public DNS server (8.8.8.8).

> ✅ Developed on **Ubuntu Linux**, this simulation follows 3GPP architecture using modular network functions and supports multithreading, secure RESTful communication, and session state management via databases.

---

## 🧱 Updated Architecture

```
                       +--------+                 +--------+
                       |   UE   |<==SCTP========> |  gNB   |
                       +--------+                 +--------+
                                                      ||
                                                      || SCTP
                                                      \/
                                                  +--------+
                                                  |  AMF   |
                                                  +--------+
                                                    ||  ▲
     +------------+           +------------+        ||  ||
     |    AUSF    |<==HTTPS==>|    UDM     |        ||  || HTTPS
     +------------+           +------------+        ||  ||
                                                    \/  ||
                                                  +--------+
                                                  |  SMF   |
                                                  +--------+
                                                      ||
                                                      || HTTPS
                                                      \/
                                                  +--------+
                                                  |  UPF   |
                                                  +--------+
                                                      ||
                                                      || Simulated HTTP
                                                      \/
                                                +----------------+
                                                | DN (Google.com)|
                                                +----------------+

                       ↳ NRF connects to: AMF, AUSF, SMF, UDM, UPF
                         ↳ Registers services, sends heartbeats
```

---

## 🔧 What This Project Demonstrates

- 🧩 Modular 5G Core NFs (AMF, AUSF, UDM, SMF, UPF, NRF)
- 📡 SCTP communication between UE ↔ gNB and gNB ↔ AMF
- 🔐 5G-AKA authentication using REST APIs (AMF ↔ AUSF ↔ UDM)
- 🌐 PDU Session Setup and IP allocation via AMF ↔ SMF ↔ UPF
- 🗂️ Per-node SQLite DBs for storing UE profiles, IP allocations, logs, and sessions
- 🔁 NRF heartbeat system with per-node service registration
- 🛰️ Simulated Data Transfer through UPF using live `requests.get("https://www.google.com")`

---

## ⚙️ Static IP Setup (Ubuntu)

Assign these IPs to your local network interface (use `ip a` to check interface name):

```bash
sudo ip addr add 192.168.70.101/24 dev <NW Interface>  # SMF
sudo ip addr add 192.168.70.102/24 dev <NW Interface>  # UPF
sudo ip addr add 192.168.70.103/24 dev <NW Interface>  # AMF
sudo ip addr add 192.168.70.104/24 dev <NW Interface>  # AUSF
sudo ip addr add 192.168.70.105/24 dev <NW Interface>  # UDM
sudo ip addr add 192.168.70.106/24 dev <NW Interface>  # NRF
sudo ip addr add 192.168.70.107/24 dev <NW Interface>  # gNB
sudo ip addr add 192.168.70.108/24 dev <NW Interface>  # UE
```

Make them persistent in `/etc/netplan/01-netcfg.yaml`.

---

## 🛠️ Installation

```bash
sudo apt update
sudo apt install python3 python3-pip libsctp-dev lksctp-tools net-tools
pip3 install pysctp flask httpx
```

---

## 🚀 Running the Simulation

> Run each node in a separate terminal in this order:

### 1. Start NRF
```bash
python3 nrf_main.py
```

### 2. Start Core NFs
```bash
# AMF
python3 amf_main.py

# AUSF
python3 ausf_main.py

# UDM
python3 udm_main.py

# SMF
python3 smf_main.py

# UPF
python3 upf_main.py
```

### 3. Start RAN Components
```bash
# gNB
python3 gnb_main.py

# UE
python3 ue_main.py
```

---

## 📂 Project Structure

```
5G-Core-Simulation/
├── AMF                 # Access & Mobility Function
├── AUSF                # Authentication Server Function
├── gNB                 # RAN Node
├── NRF                 # Network Repository Function
├── SMF                 # Session Management Function
├── UDM                 # User Data Management
├── UE                  # Simulated User Equipment
├── UPF                 # User Plane Function
├── common              # TLS certs, utils
├── logs                # Per-node logs
├── ip_pool.db          # SMF IP allocation DB
└── README.md
```

---

## 📈 Complete Workflow

1. **Node Initialization**
   - NRF starts first and listens on HTTP(S)
   - AMF, SMF, AUSF, UDM, UPF register themselves with NRF

2. **UE Registration**
   - UE sends NAS registration message to gNB (via SCTP)
   - gNB forwards to AMF
   - AMF uses NRF to find AUSF and UDM for authentication

3. **Authentication (5G-AKA)**
   - AUSF requests user vectors from UDM
   - AMF challenges UE → UE responds → verified

4. **Session Establishment**
   - AMF requests IP allocation from SMF
   - SMF assigns IP, informs UPF
   - AMF sends session info to gNB and UE

5. **Data Transfer**
   - UE sends packet to gNB
   - gNB forwards to UPF with session info
   - UPF simulates external data request to `google.com`

6. **Session Termination**
   - UE initiates release
   - AMF and SMF clean up session state
   - UPF deletes IP mapping

---

## 🧪 Logs and Debugging

- Logs are written in `logs/` directory per node
- Use `tcpdump` or `wireshark` to capture SCTP and HTTPS
- Verify DN reachability by checking UPF's GET request to `google.com`

---

## 🔒 Security Features

- TLS-based REST communication between NFs
- Token-based REST auth (configurable)
- Per-session IMSI and IP verification
- Heartbeat with retry/failure detection via NRF

---

## 🧭 Future Enhancements

- ASN.1-based NGAP/NAS encoding using `asn1tools`
- Real GTP-U implementation (UDP encapsulation)
- UERANSIM integration testing
- GUI dashboard for NF status and packet trace
- Enhanced brute-force/replay prevention in AMF/AUSF

---

## 📜 License

MIT License — Open for academic and research use.

---

## 🙌 Acknowledgements

- 3GPP TS 23.501 / 23.502
- OpenAirInterface, Free5GC, UERANSIM
- Developed entirely in Python for modular understanding
