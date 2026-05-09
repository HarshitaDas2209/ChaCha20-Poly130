import serial
import time
import hashlib
from serial.tools import list_ports
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import dearpygui.dearpygui as dpg


# ==========================
# CONFIGURATION
# ==========================

BAUD_RATE = 115200
MASTER_KEY = b"LORA_MASTER_KEY_32BYTE_SECRET_KEY"

rssi_values = []
packet_index = []
log_lines = []
MAX_LOG_LINES = 100


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
# DECRYPT MESSAGE
# ==========================

def decrypt_message(packet):

    start = time.time()

    try:

        packet = packet.strip()

        if packet.count("|") != 1:
            print("Invalid packet format:", packet)
            return None, None, None

        timestamp_str, hexdata = packet.split("|")

        timestamp_str = timestamp_str.strip()
        hexdata = hexdata.strip()

        if not timestamp_str.isdigit():
            print("Invalid timestamp:", timestamp_str)
            return None, None, None

        key = derive_key(int(timestamp_str))

        data = bytes.fromhex(hexdata)

        if len(data) < 12:
            print("Packet too short")
            return None, None, None

        nonce = data[:12]
        ciphertext = data[12:]

        cipher = ChaCha20Poly1305(key)

        plaintext = cipher.decrypt(nonce, ciphertext, None)

        dec_time = (time.time() - start) * 1000

        return plaintext.decode(), key.hex()[:16], dec_time

    except Exception as e:

        print("Decryption Error:", e)

        return None, None, None


# ==========================
# CLEAN PACKET HELPER
# ==========================

def clean_packet(line):

    line = line.strip()

    if ":" in line and "|" in line:

        colon_pos = line.index(":")
        pipe_pos = line.index("|")

        if colon_pos < pipe_pos:
            line = line[colon_pos + 1:].strip()

    return line


# ==========================
# LOG HELPER
# ==========================

def add_log(text):
    """Add a line to log, keep max 100 lines, refresh log display."""

    log_lines.append(text)

    if len(log_lines) > MAX_LOG_LINES:
        log_lines.pop(0)

    # Clear and re-render log window
    dpg.delete_item("log_window", children_only=True)

    for line in log_lines:
        dpg.add_text(line, parent="log_window")


# ==========================
# SERIAL CONNECT
# ==========================

print("Starting LoRa Receiver Dashboard...")

port = detect_esp32()

if port is None:
    print("ESP32 not detected")
    exit()

print("ESP32 detected on:", port)

ser = serial.Serial(port, BAUD_RATE, timeout=1)

time.sleep(2)


# ==========================
# SERIAL READER
# ==========================

def serial_update():

    while ser.in_waiting:

        line = ser.readline().decode(errors="ignore").strip()

        if not line:
            continue

        # Show raw ESP32 output in log
        add_log("ESP32: " + line)

        # ==========================
        # ENCRYPTED PACKET DETECTION
        # ==========================

        if "|" in line:

            packet = clean_packet(line)

            add_log("Encrypted Packet: " + packet)

            msg, key, dec_time = decrypt_message(packet)

            if msg:

                # Update always-visible top status labels
                dpg.set_value("key_text",  "Key Used:         " + key)
                dpg.set_value("dec_time",  f"Decryption Time:  {dec_time:.2f} ms")
                dpg.set_value("msg_text",  "Last Message:     " + msg)
                dpg.set_value("ack_text",  "ACK: Message Decrypted Successfully")

                add_log(">>> Decrypted Message: " + msg)

                print(f"[OK] Decrypted: {msg} | Key: {key} | Time: {dec_time:.2f} ms")

            else:

                dpg.set_value("ack_text", "ACK: Decryption Failed")
                add_log(">>> Decryption FAILED for packet: " + packet)

                print(f"[FAIL] Could not decrypt: {packet}")

        # ==========================
        # RSSI PARSING
        # ==========================

        if "RSSI:" in line:

            try:

                rssi = int(
                    line.split("RSSI:")[1]
                    .split("dBm")[0]
                    .strip()
                )

                rssi_values.append(rssi)
                packet_index.append(len(packet_index))

                dpg.set_value(
                    "rssi_series",
                    [packet_index, rssi_values]
                )

            except:
                pass


# ==========================
# GUI
# ==========================

dpg.create_context()

with dpg.window(
    label="LoRa Secure Receiver Dashboard",
    width=950,
    height=650
):

    dpg.add_text(
        "LoRa Secure Receiver — Waiting for packets...",
        color=(100, 200, 255)
    )

    dpg.add_separator()

    # Always-visible status panel at top
    dpg.add_text("Key Used:         —", tag="key_text")
    dpg.add_text("Decryption Time:  —", tag="dec_time")

    # Decrypted message shown in GREEN — always visible, never hidden in scroll
    dpg.add_text("Last Message:     —", tag="msg_text", color=(50, 220, 50))

    dpg.add_text("ACK: —", tag="ack_text", color=(255, 200, 50))

    dpg.add_separator()

    # ==========================
    # RSSI PLOT
    # ==========================

    with dpg.plot(
        label="Live RSSI Signal Strength",
        height=200,
        width=-1
    ):

        dpg.add_plot_axis(
            dpg.mvXAxis,
            label="Packet Index"
        )

        y_axis = dpg.add_plot_axis(
            dpg.mvYAxis,
            label="RSSI (dBm)"
        )

        dpg.add_line_series(
            packet_index,
            rssi_values,
            parent=y_axis,
            tag="rssi_series"
        )

    dpg.add_separator()

    dpg.add_text("Serial Log:", color=(180, 180, 180))

    # ==========================
    # LOG WINDOW (scrollable)
    # ==========================

    dpg.add_child_window(
        tag="log_window",
        height=220,
        width=-1
    )


# ==========================
# VIEWPORT
# ==========================

dpg.create_viewport(
    title="LoRa Secure Receiver",
    width=950,
    height=650
)

dpg.setup_dearpygui()

dpg.show_viewport()


# ==========================
# MAIN LOOP
# ==========================

while dpg.is_dearpygui_running():

    serial_update()

    dpg.render_dearpygui_frame()


# ==========================
# CLEANUP
# ==========================

dpg.destroy_context()
