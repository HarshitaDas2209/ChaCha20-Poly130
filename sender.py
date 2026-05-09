import serial
import time
import os
import hashlib
from serial.tools import list_ports
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import dearpygui.dearpygui as dpg


# ==========================
# CONFIG
# ==========================

BAUD_RATE = 115200
MASTER_KEY = b"LORA_MASTER_KEY_32BYTE_SECRET_KEY"

rssi_values = []
packet_index = []


# ==========================
# AUTO DETECT ESP32
# ==========================

def detect_esp32():

    ports = list_ports.comports()

    for p in ports:

        desc = p.description.lower()

        if ("cp210" in desc or
            "ch340" in desc or
            "usb serial" in desc or
            "silicon labs" in desc):

            return p.device

    if len(ports) > 0:
        return ports[0].device

    return None


# ==========================
# KEY DERIVATION
# ==========================

def derive_key(timestamp):

    data = MASTER_KEY + str(timestamp).encode()

    key = hashlib.sha256(data).digest()

    return key[:32]


# ==========================
# ENCRYPT
# ==========================

def encrypt_message(msg):

    start = time.time()

    timestamp = int(time.time())

    key = derive_key(timestamp)

    nonce = os.urandom(12)

    cipher = ChaCha20Poly1305(key)

    ciphertext = cipher.encrypt(nonce, msg.encode(), None)

    packet = str(timestamp) + "|" + (nonce + ciphertext).hex()

    enc_time = (time.time() - start) * 1000

    return packet, key.hex()[:16], enc_time


# ==========================
# DECRYPT
# ==========================

def decrypt_message(packet):

    start = time.time()

    try:

        timestamp, hexdata = packet.split("|")

        key = derive_key(int(timestamp))

        data = bytes.fromhex(hexdata)

        nonce = data[:12]
        ciphertext = data[12:]

        cipher = ChaCha20Poly1305(key)

        plaintext = cipher.decrypt(nonce, ciphertext, None)

        dec_time = (time.time() - start) * 1000

        return plaintext.decode(), dec_time

    except:
        return None, None


# ==========================
# SERIAL CONNECT
# ==========================

print("Starting Secure LoRa Dashboard...")

port = detect_esp32()

if port is None:
    print("ESP32 not detected")
    exit()

print("ESP32 detected on:", port)

ser = serial.Serial(port, BAUD_RATE, timeout=1)

time.sleep(2)


# ==========================
# SEND MESSAGE
# ==========================

def send_message():

    msg = dpg.get_value("msg_input")

    if msg == "":
        return

    packet, key, enc_time = encrypt_message(msg)

    ser.write((packet + "\n").encode())

    dpg.set_value("key_text", "Key Used: " + key)

    dpg.set_value("enc_time", f"Encryption Time: {enc_time:.2f} ms")

    dpg.add_text("Encrypted Packet: " + packet, parent="log_window")

    dpg.set_value("msg_input", "")


# ==========================
# SERIAL READER
# ==========================

def serial_update():

    while ser.in_waiting:

        line = ser.readline().decode(errors="ignore").strip()

        dpg.add_text("ESP32: " + line, parent="log_window")

        # decrypt received packet
        if "Received:" in line:

            packet = line.split("Received:")[1].strip()

            msg, dec_time = decrypt_message(packet)

            if msg:

                dpg.set_value("ack_text", "ACK: Decryption SUCCESS")

                dpg.set_value("dec_time", f"Decryption Time: {dec_time:.2f} ms")

                dpg.add_text("Decrypted: " + msg, parent="log_window")

        # parse RSSI
        if "RSSI:" in line:

            try:

                rssi = int(line.split("RSSI:")[1].split("dBm")[0].strip())

                rssi_values.append(rssi)

                packet_index.append(len(packet_index))

                dpg.set_value("rssi_series", [packet_index, rssi_values])

            except:
                pass


# ==========================
# GUI
# ==========================

dpg.create_context()

with dpg.window(label="Secure LoRa Dashboard", width=900, height=600):

    dpg.add_input_text(tag="msg_input", hint="Enter message")

    dpg.add_button(label="Send Secure Message", callback=send_message)

    dpg.add_text("Key Used:", tag="key_text")

    dpg.add_text("Encryption Time:", tag="enc_time")

    dpg.add_text("Decryption Time:", tag="dec_time")

    dpg.add_text("ACK:", tag="ack_text")

    dpg.add_separator()

    with dpg.plot(label="LoRa RSSI Live Plot", height=250):

        dpg.add_plot_axis(dpg.mvXAxis, label="Packet")

        y_axis = dpg.add_plot_axis(dpg.mvYAxis, label="RSSI")

        dpg.add_line_series(packet_index, rssi_values, parent=y_axis, tag="rssi_series")

    dpg.add_separator()

    dpg.add_child_window(tag="log_window", height=200)


dpg.create_viewport(title="Secure LoRa Dashboard", width=900, height=600)

dpg.setup_dearpygui()

dpg.show_viewport()


# ==========================
# MAIN LOOP
# ==========================

while dpg.is_dearpygui_running():

    serial_update()

    dpg.render_dearpygui_frame()


dpg.destroy_context()
