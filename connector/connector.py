#!/usr/bin/env python3
"""Echo connector — sends a phone system's call signals to Echo.

Installed by connect.sh on the phone system's own computer.
Listens on 127.0.0.1:9062 for HEPv3 packets (the phone system's
copy of its call signals — Asterisk res_hep, FreeSWITCH Sofia
capture, Kamailio siptrace) and forwards them over an encrypted
connection to the Echo backend, which shows the activity in the
Echo dashboard as a connected node.

What it does, exactly:
  1. Receives HEPv3 packets on loopback UDP/TCP (127.0.0.1:9062)
  2. Batches them and POSTs them to the Echo endpoint (TLS)
  3. Sends a heartbeat every 60 seconds so Echo can show this
     node as connected

What it never does:
  - never opens a port to the internet (loopback only)
  - never touches audio — call signals only, no sound
  - never downloads or runs anything else at runtime
  - never talks to any server other than the Echo endpoint

Standard library only. Nothing to install, nothing to fetch.
"""
import base64
import gzip
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request

LISTEN_HOST = os.environ.get("ECHO_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("ECHO_LISTEN_PORT", "9062"))
ECHO_ENDPOINT = os.environ.get("ECHO_ENDPOINT", "https://echo.echoguard.ca")
NODE_KEY = os.environ.get("ECHO_NODE_KEY", "")
NODE_ID = os.environ.get("ECHO_NODE_ID", "")
PLATFORM = os.environ.get("ECHO_PLATFORM", "unknown")
VERSION = "1.0.0"

STATE_DIR = "/var/lib/echo-connector"
STATE_FILE = os.path.join(STATE_DIR, "state.json")
LOG_FILE = "/var/log/echo-connector/agent.log"

BATCH_INTERVAL = 1.0
BATCH_MAX = 200
MAX_QUEUE = 5000
HEARTBEAT_SECONDS = 60

# HEPv3 TLV types as emitted by Asterisk res_hep / FreeSWITCH /
# Kamailio siptrace (verified against live captures).
HEP_PROTOCOL_ID = 0x0001
HEP_TRANSPORT = 0x0002
HEP_SRC_IP4 = 0x0003
HEP_DST_IP4 = 0x0004
HEP_SRC_IP6 = 0x0005
HEP_DST_IP6 = 0x0006
HEP_SRC_PORT = 0x0007
HEP_DST_PORT = 0x0008
HEP_TIMESTAMP = 0x0009
HEP_CAPTURE_ID = 0x000C
HEP_PAYLOAD = 0x000D
HEP_PAYLOAD_GZ = 0x000E
HEP_PAYLOAD_ALT = 0x000F
HEP_CALL_ID = 0x0011

HEP_PROTO_NAMES = {1: "sip", 2: "sip", 20: "rtcp", 21: "rtcp-xr"}
TRANSPORT_NAMES = {6: "tcp", 17: "udp"}

state = {"last_hep": 0, "last_send_ok": 0, "sent_total": 0, "errors": 0}
state_lock = threading.Lock()


def log(msg):
    line = "[echo-connector] %s" % msg
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + line + "\n")
    except Exception:
        pass


def save_state():
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, STATE_FILE)
    except Exception:
        pass


def load_state():
    try:
        with open(STATE_FILE) as f:
            state.update(json.load(f))
    except Exception:
        pass


# ---------- HEPv3 parsing (same proven parser as the lab agent) ----------

def parse_hep(data):
    """Parse a HEPv3 packet into a dict of {tlv_type: value_bytes}."""
    if len(data) < 8 or data[0:4] != b"HEP3":
        return None
    fields = {}
    offset = 8
    while offset + 4 <= len(data):
        tlv_type, tlv_len = struct.unpack(">HH", data[offset:offset + 4])
        if tlv_len < 4:
            break
        end = min(offset + tlv_len, len(data))  # final TLV can overshoot
        fields[tlv_type] = data[offset + 4:end]
        offset += tlv_len
    return fields


def ip4_str(raw):
    return socket.inet_ntop(socket.AF_INET, raw[:4]) if len(raw) >= 4 else raw.hex()


def ip6_str(raw):
    return socket.inet_ntop(socket.AF_INET6, raw[:16]) if len(raw) >= 16 else raw.hex()


def endpoint_ip(fields, v4_type, v6_type):
    if v4_type in fields:
        return ip4_str(fields[v4_type])
    if v6_type in fields:
        return ip6_str(fields[v6_type])
    return "?"


def be16(raw, default=0):
    if len(raw) < 2:
        return default
    return struct.unpack(">H", raw[:2])[0]


def be32(raw, default=0):
    if len(raw) < 4:
        return default
    return struct.unpack(">I", raw[:4])[0]


def extract_sip(payload):
    """Extract summary fields from a raw SIP message."""
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return None
    lines = text.split("\r\n")
    summary = {"first_line": (lines[0] if lines else "")[:140]}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _, val = line.partition(":")
        name = name.strip().lower()
        if name in ("from", "to", "call-id", "cseq", "via"):
            summary[name] = val.strip()[:220]
    cseq = summary.get("cseq", "")
    if cseq:
        summary["method"] = cseq.split()[-1].upper()
    else:
        fl = summary["first_line"].split()
        if fl:
            summary["method"] = "RESPONSE" if fl[0].startswith("SIP/") else fl[0].upper()
    return summary


def describe_packet(data):
    """Parse one HEPv3 datagram into a plain description dict."""
    fields = parse_hep(data)
    if fields is None:
        return None
    pid_raw = fields.get(HEP_PROTOCOL_ID, b"")
    proto_id = pid_raw[0] if pid_raw else 0
    proto_name = HEP_PROTO_NAMES.get(proto_id, "proto%d" % proto_id)
    payload = fields.get(HEP_PAYLOAD, fields.get(HEP_PAYLOAD_ALT, b""))
    gz = fields.get(HEP_PAYLOAD_GZ)
    if not payload and gz:
        try:
            payload = gzip.decompress(gz)
        except Exception:
            payload = b""
    src = "%s:%d" % (endpoint_ip(fields, HEP_SRC_IP4, HEP_SRC_IP6),
                     be16(fields.get(HEP_SRC_PORT, b"")))
    dst = "%s:%d" % (endpoint_ip(fields, HEP_DST_IP4, HEP_DST_IP6),
                     be16(fields.get(HEP_DST_PORT, b"")))
    tp_raw = fields.get(HEP_TRANSPORT, b"")
    transport = TRANSPORT_NAMES.get(tp_raw[0] if tp_raw else 0, "unknown")
    ts = be32(fields.get(HEP_TIMESTAMP, b""))
    capture_id = be32(fields.get(HEP_CAPTURE_ID, b""))
    call_id = fields.get(HEP_CALL_ID, b"").decode("utf-8", errors="replace").rstrip("\x00 ").strip()
    out = {
        "proto": proto_name,
        "transport": transport,
        "src": src,
        "dst": dst,
        "ts": ts,
        "capture_id": capture_id,
        "call_id": call_id,
    }
    if proto_name == "sip":
        sip = extract_sip(payload)
        if not sip:
            return None
        out["method"] = sip.get("method", "UNKNOWN")[:32]
        out["first"] = sip.get("first_line", "")
        out["from"] = sip.get("from", "")
        out["to"] = sip.get("to", "")
        out["cseq"] = sip.get("cseq", "")
    return out


# ---------- delivery ----------

def post_json(path, obj, timeout=10):
    url = ECHO_ENDPOINT.rstrip("/") + path
    body = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if NODE_KEY:
        req.add_header("X-Echo-Node-Key", NODE_KEY)
    req.add_header("User-Agent", "echo-connector/%s" % VERSION)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")[:400]
    except Exception as exc:
        return None, str(exc)


class Connector:
    def __init__(self):
        self.batch = []
        self.lock = threading.Lock()
        self.last_push = time.time()
        self.backoff = 5.0

    def handle_packet(self, data):
        desc = describe_packet(data)
        if desc is None:
            return
        with state_lock:
            state["last_hep"] = time.time()
        with self.lock:
            if len(self.batch) < MAX_QUEUE:
                self.batch.append(base64.b64encode(data).decode())

    def flush(self):
        with self.lock:
            if not self.batch:
                return
            batch, self.batch = self.batch, []
        status, text = post_json("/api/hep", {"packets": batch})
        if status in (200, 201, 204):
            with state_lock:
                state["sent_total"] += len(batch)
                state["last_send_ok"] = time.time()
            self.backoff = 5.0
        else:
            with state_lock:
                state["errors"] += 1
            # put them back, oldest first, and back off
            with self.lock:
                self.batch = (batch + self.batch)[:MAX_QUEUE]
            self.backoff = min(self.backoff * 2, 60.0)
            log("send failed (status %s): %s — retrying in %ds"
                % (status, text[:200], self.backoff))

    def batcher(self):
        while True:
            time.sleep(0.5)
            with self.lock:
                n = len(self.batch)
            if n >= BATCH_MAX or (n > 0 and time.time() - self.last_push >= BATCH_INTERVAL):
                self.flush()
                self.last_push = time.time()
                save_state()
            elif self.backoff > 5.0 and n > 0:
                # still retrying a failed batch
                if time.time() - self.last_push >= self.backoff:
                    self.flush()
                    self.last_push = time.time()

    def heartbeat(self):
        while True:
            time.sleep(HEARTBEAT_SECONDS)
            status, text = post_json("/api/nodes/heartbeat",
                                     {"platform": PLATFORM, "version": VERSION})
            if status not in (200, 201, 204):
                log("heartbeat failed (status %s): %s" % (status, text[:200]))
            save_state()

    def serve_udp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LISTEN_HOST, LISTEN_PORT))
        log("listening for phone-system signals on %s:%d (UDP)" % (LISTEN_HOST, LISTEN_PORT))
        while True:
            data, _addr = s.recvfrom(65536)
            try:
                self.handle_packet(data)
            except Exception as exc:
                log("packet error: %s" % exc)

    def serve_tcp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LISTEN_HOST, LISTEN_PORT))
        s.listen(8)
        log("listening for phone-system signals on %s:%d (TCP)" % (LISTEN_HOST, LISTEN_PORT))
        while True:
            conn, _addr = s.accept()
            threading.Thread(target=self.tcp_reader, args=(conn,), daemon=True).start()

    def tcp_reader(self, conn):
        buf = b""
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= 8 and buf[0:4] == b"HEP3":
                    length = struct.unpack(">H", buf[4:6])[0]
                    if length < 8 or len(buf) < length:
                        break
                    self.handle_packet(buf[:length])
                    buf = buf[length:]
                if len(buf) >= 8 and buf[0:4] != b"HEP3":
                    buf = b""
        except Exception as exc:
            log("tcp error: %s" % exc)
        finally:
            conn.close()


def build_test_packet():
    """One synthetic HEPv3 REGISTER used by --self-test."""
    def tlv(t, v):
        if isinstance(v, str):
            v = v.encode()
        return struct.pack(">HH", t, len(v) + 4) + v

    payload = (b"REGISTER sip:echo.example SIP/2.0\r\n"
               b"From: <sip:connector-test@echo.example>;tag=test\r\n"
               b"To: <sip:connector-test@echo.example>\r\n"
               b"Call-ID: echo-connector-self-test\r\n"
               b"CSeq: 1 REGISTER\r\n\r\n")
    tlvs = (tlv(HEP_PROTOCOL_ID, b"\x02") +
            tlv(HEP_TRANSPORT, b"\x11") +
            tlv(HEP_SRC_IP4, socket.inet_aton("127.0.0.1")) +
            tlv(HEP_DST_IP4, socket.inet_aton("127.0.0.1")) +
            tlv(HEP_SRC_PORT, struct.pack(">H", 5060)) +
            tlv(HEP_DST_PORT, struct.pack(">H", LISTEN_PORT)) +
            tlv(HEP_TIMESTAMP, struct.pack(">I", int(time.time()))) +
            tlv(HEP_CALL_ID, b"echo-connector-self-test") +
            tlv(HEP_PAYLOAD_ALT, payload))
    header = b"HEP3" + struct.pack(">HH", len(tlvs) + 8, 0)
    return header + tlvs


def self_test():
    if not NODE_KEY:
        print("no node key configured — run through connect.sh")
        return 1
    packet = build_test_packet()
    status, text = post_json("/api/hep", {"packets": [base64.b64encode(packet).decode()]})
    if status in (200, 201, 204):
        print("self-test OK: Echo accepted a test signal from this node")
        return 0
    print("self-test FAILED (status %s): %s" % (status, text[:300]))
    return 1


def show_status():
    load_state()
    print(json.dumps({
        "node_id": NODE_ID,
        "platform": PLATFORM,
        "endpoint": ECHO_ENDPOINT,
        "listen": "%s:%d" % (LISTEN_HOST, LISTEN_PORT),
        "state": dict(state),
    }, indent=2))


def main():
    args = sys.argv[1:]
    if "--self-test" in args:
        return self_test()
    if "--status" in args:
        show_status()
        return 0

    load_state()
    if not NODE_KEY:
        log("no node key in agent.env — cannot connect to Echo")
        return 1
    log("echo-connector %s starting (node %s, platform %s)" % (VERSION, NODE_ID, PLATFORM))
    conn = Connector()
    threading.Thread(target=conn.batcher, daemon=True).start()
    threading.Thread(target=conn.heartbeat, daemon=True).start()
    threading.Thread(target=conn.serve_udp, daemon=True).start()
    conn.serve_tcp()
    return 0


if __name__ == "__main__":
    sys.exit(main())
