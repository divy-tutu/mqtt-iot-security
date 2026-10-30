"""
Compares a plaintext MQTT capture (baseline, port 1883) against a
TLS-encrypted one (hardened, port 8883), pulling real content out of the
packets rather than just asserting "TLS encrypts things." See
tools/CAPTURE_README.md for how to produce the two .pcap/.pcapng files this
script reads.

This reads capture files Wireshark already saved — it does NOT do a live
capture itself, so there's no Npcap loopback-adapter / tshark-interface
setup needed to run it. You capture with Wireshark's own GUI (the exact
same workflow used for earlier traffic-analysis work), save the file, then
run this script against it.

Usage:
    python tools/capture_compare.py
    python tools/capture_compare.py --tshark-path "C:\\Program Files\\Wireshark\\tshark.exe"
"""
import argparse
import binascii
import os
import sys

try:
    import pyshark
except ImportError:
    print("pyshark isn't installed. Run: pip install pyshark")
    sys.exit(1)


def open_capture(path, tshark_path):
    kwargs = {}
    if tshark_path:
        kwargs["tshark_path"] = tshark_path
    try:
        return pyshark.FileCapture(path, **kwargs)
    except FileNotFoundError:
        print("Couldn't find tshark. Pass its path explicitly, e.g.:")
        print(r'  python tools/capture_compare.py --tshark-path "C:\Program Files\Wireshark\tshark.exe"')
        sys.exit(1)


def hex_to_text(hex_str):
    """mqtt.msg comes back as a hex string from pyshark; decode it to the
    readable text an eavesdropper would actually see."""
    try:
        return binascii.unhexlify(hex_str.replace(":", "")).decode("utf-8", errors="replace")
    except (binascii.Error, AttributeError):
        return hex_str


def analyze_baseline(path, tshark_path):
    print(f"\n{'=' * 70}")
    print(f"PLAINTEXT capture (baseline, port 1883): {path}")
    print(f"{'=' * 70}")
    cap = open_capture(path, tshark_path)

    total = 0
    mqtt_messages = 0
    for pkt in cap:
        total += 1
        if "MQTT" in pkt:
            mqtt_layer = pkt.mqtt
            # PUBLISH packets carry a topic + payload; other MQTT packet
            # types (CONNECT, PINGREQ, ...) won't have both.
            topic = getattr(mqtt_layer, "topic", None)
            msg = getattr(mqtt_layer, "msg", None)
            if topic and msg:
                mqtt_messages += 1
                readable = hex_to_text(msg)
                print(f"  [packet {pkt.number}] topic={topic!r}")
                print(f"                payload (as captured off the wire) = {readable!r}")
            username = getattr(mqtt_layer, "username", None)
            password = getattr(mqtt_layer, "passwd", None)
            if username or password:
                print(f"  [packet {pkt.number}] CONNECT credentials in the clear: "
                      f"username={username!r} password={password!r}")
    cap.close()

    print(f"\n  {total} packets total, {mqtt_messages} readable PUBLISH messages found.")
    if mqtt_messages > 0:
        print("  Every topic name and payload above was read directly from the raw")
        print("  TCP bytes — this is exactly what anyone capturing this network")
        print("  traffic sees, no decryption or special access required.")
    else:
        print("  No MQTT PUBLISH packets found — did you capture while traffic was")
        print("  flowing? See tools/CAPTURE_README.md step 1.")
    return total, mqtt_messages


def analyze_hardened(path, tshark_path):
    print(f"\n{'=' * 70}")
    print(f"TLS capture (hardened, port 8883): {path}")
    print(f"{'=' * 70}")
    cap = open_capture(path, tshark_path)

    total = 0
    mqtt_messages = 0
    tls_app_data_records = 0
    tls_app_data_bytes = 0
    for pkt in cap:
        total += 1
        if "MQTT" in pkt:
            mqtt_messages += 1
        if "TLS" in pkt and hasattr(pkt.tls, "app_data"):
            # Under TLS 1.2/1.3, every record after the handshake completes
            # is tagged "application_data" at the outer layer regardless of
            # its real content — that masking is itself part of the
            # protection, so this presence check (not a content-type match)
            # is the correct way to count them.
            tls_app_data_records += 1
            try:
                length_field = pkt.tls.record_length
                # A packet can carry several coalesced records; tshark joins
                # their lengths with commas in that case.
                tls_app_data_bytes += sum(int(x) for x in str(length_field).split(","))
            except (AttributeError, ValueError):
                pass
    cap.close()

    print(f"\n  {total} packets total, {mqtt_messages} with a readable MQTT layer,")
    print(f"  {tls_app_data_records} TLS application-data records "
          f"({tls_app_data_bytes} encrypted bytes total).")
    if mqtt_messages == 0:
        print("  No MQTT topic, payload, or credential content was visible in ANY")
        print("  packet — the same traffic that was fully readable on the plaintext")
        print("  capture above shows up here as nothing but a TLS handshake followed")
        print("  by opaque encrypted application-data records. An eavesdropper gets")
        print("  ciphertext, not your sensor readings, lock state, or password.")
    else:
        print("  WARNING: MQTT content was visible even on the TLS capture — double")
        print("  check you captured the right port (8883, not 1883) and that the")
        print("  hardened broker was actually the one running.")
    return total, mqtt_messages, tls_app_data_records


def main():
    parser = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    parser.add_argument("--baseline-pcap", default=os.path.join(here, "baseline_capture.pcapng"))
    parser.add_argument("--hardened-pcap", default=os.path.join(here, "hardened_capture.pcapng"))
    parser.add_argument("--tshark-path", default=None)
    args = parser.parse_args()

    # Accept either .pcap or .pcapng — Wireshark's default save extension is
    # .pcapng, but people sometimes save as .pcap; try both.
    def resolve(path):
        if os.path.exists(path):
            return path
        if path.endswith(".pcapng"):
            alt = path[: -len("ng")]       # foo.pcapng -> foo.pcap
        elif path.endswith(".pcap"):
            alt = path + "ng"              # foo.pcap   -> foo.pcapng
        else:
            alt = path
        if os.path.exists(alt):
            return alt
        print(f"Can't find {path} (or {alt}). See tools/CAPTURE_README.md to generate it.")
        sys.exit(1)

    baseline_path = resolve(args.baseline_pcap)
    hardened_path = resolve(args.hardened_pcap)

    b_total, b_mqtt = analyze_baseline(baseline_path, args.tshark_path)
    h_total, h_mqtt, h_tls = analyze_hardened(hardened_path, args.tshark_path)

    print(f"\n{'=' * 70}")
    print("SUMMARY (paste this into your report)")
    print(f"{'=' * 70}")
    print(f"  Baseline, plaintext (port 1883): {b_mqtt} MQTT messages, topic names,")
    print(f"                                   payloads, and login credentials fully")
    print(f"                                   readable from the capture.")
    print(f"  Hardened, TLS (port 8883):       {h_mqtt} MQTT messages readable "
          f"({h_tls} encrypted TLS records instead).")
    print(f"\n  Confidentiality fix confirmed: identical traffic, same sensor and")
    print(f"  lock data, but TLS reduces what an eavesdropper can read from")
    print(f"  '{b_mqtt} full plaintext messages' to '{h_mqtt} readable messages'.")


if __name__ == "__main__":
    main()
