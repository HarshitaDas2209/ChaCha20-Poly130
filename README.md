# Lightweight Secure IoT Framework using ChaCha20-Poly1305 and LoRa

## Overview
This project implements a lightweight secure communication framework for LoRa-based IoT networks using:

- ChaCha20-Poly1305 authenticated encryption
- Adaptive Rolling Key Schedule (ARKS)
- Replay attack prevention using packet counters
- ESP32 + SX1278 LoRa modules
- Real-time monitoring dashboard

---

# Hardware Requirements

- ESP32-WROOM-32
- SX1278 (Ra-02) LoRa Module
- USB Cable
- 3.3V Power Supply
- LEDs / Relay Module (optional)

---

# Software Requirements

- Python 3.10+
- Arduino IDE 2.x
- ESP32 Arduino Core
- Required Python Libraries:
  - pyserial
  - cryptography
  - dearpygui

Install dependencies using:

pip install -r requirements.txt

---

# Sender Node Setup

1. Connect ESP32 transmitter hardware
2. Upload `sender_esp32.ino`
3. Run:

python sender.py

4. Enter message and click:
   "Send Secure Message"

---

# Receiver Node Setup

1. Connect ESP32 receiver hardware
2. Upload `receiver_esp32.ino`
3. Run:

python receiver.py

4. Receiver dashboard displays:
   - Encrypted packets
   - Decrypted message
   - RSSI graph
   - Decryption time

---

# Security Features

- ChaCha20 → Confidentiality
- Poly1305 → Integrity
- ARKS → Dynamic Session Keys
- HWM Counter → Replay Protection

---

# Experimental Results

- 32% reduction in encryption latency
- 18% reduction in energy consumption
- 98.6% packet delivery ratio
- Successful replay attack detection

---

# Authors

[Your Name]
