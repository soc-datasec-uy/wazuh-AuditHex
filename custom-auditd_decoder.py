#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
# Copyright (C) 2015-2025, Wazuh

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
import copy

# Config
INTEGRATION_TAG = "custom-auditd_decoder"
DEBUG_ENABLED = True

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f"{BASE_DIR}/logs/integrations.log"
SOCKET_ADDR = f"{BASE_DIR}/queue/sockets/queue"


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S %Z")


def debug(msg):
    if not DEBUG_ENABLED:
        return
    if isinstance(msg, (dict, list)):
        try:
            msg = json.dumps(msg, ensure_ascii=False)
        except Exception:
            msg = str(msg)
    line = f"{now()}: {msg}\n"
    try:
        print(line, end="")
    except Exception:
        pass
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def decode_hex(s):
    if not s:
        return s
    try:
        s = s.strip()
        if len(s) % 2 != 0:
            s = "0" + s
        b = bytes.fromhex(s)
        return b.decode("utf-8", "replace")
    except Exception as e:
        debug(f"# decode_hex error: {e}")
        return s  # fallback


def create_alert(decoded_string, original_alert):
    # Clone the the whole tree 'audit' from the source event
    original_audit = copy.deepcopy(
        (original_alert.get("data") or {}).get("audit", {})
    )

    # Add levels and the decoded field
    proctitle = original_audit.setdefault("proctitle", {})
    if decoded_string is not None:
        decoded_clean = decoded_string.replace("\x00", " ").strip()
        proctitle["decoded"] = decoded_clean

    # Generate the new event
    alert_output = {
        "integration": INTEGRATION_TAG,
        "derived": True,
        "source": {
            "id": original_alert.get("id"),
            "rule_id": (original_alert.get("rule") or {}).get("id"),
        },
        "agent": original_alert.get("agent"),
        "audit": original_audit
    }

    debug("# new event (preview)")
    debug(alert_output)
    return alert_output


def send_event(msg, agent=None):
    try:
        payload = json.dumps(msg, separators=(",", ":"), ensure_ascii=False)
    except Exception as e:
        debug(f"# json.dumps error: {e}")
        return

    # Manager vs agent
    if not agent or agent.get("id") == "000":
        wire = f"1:{INTEGRATION_TAG}:{payload}"
    else:
        aid = agent.get("id")
        aname = agent.get("name")
        aip = agent.get("ip", "any")
        wire = f"1:[{aid}] ({aname}) {aip}->{INTEGRATION_TAG}:{payload}"

    debug(f"# send_event -> {wire[:400]}{'...' if len(wire)>400 else ''}")

    sock = socket(AF_UNIX, SOCK_DGRAM)
    try:
        sock.connect(SOCKET_ADDR)
        sock.send(wire.encode("utf-8"))
    finally:
        sock.close()


def main(argv):
    if len(argv) < 2:
        debug("# Exiting: Bad arguments (need alert file path)")
        sys.exit(1)

    # optional debug flag
    global DEBUG_ENABLED
    DEBUG_ENABLED = any(a.lower() == "debug" for a in argv[2:]) or DEBUG_ENABLED

    alert_file_location = argv[1]
    debug(f"# Starting, file={alert_file_location}")

    with open(alert_file_location, "r", encoding="utf-8") as alert_file:
        original_alert = json.load(alert_file)

    # Robust path to hex field
    hex_string = (
        (original_alert.get("data") or {})
        .get("audit", {})
        .get("proctitle", {})
        .get("msg")
    )

    decoded_string = decode_hex(hex_string) if hex_string else None
    msg = create_alert(decoded_string, original_alert)
    send_event(msg, original_alert.get("agent"))



if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as e:
        debug(f"# fatal: {e}")
        raise
