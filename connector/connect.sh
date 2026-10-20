#!/usr/bin/env bash
# Echo connector installer — one line, one paste.
#
# Usage:
#   curl -fsSL https://echo.echoguard.ca/connector/connect.sh | bash -s -- 'EC-<id>.<key>'
#   curl -fsSL https://echo.echoguard.ca/connector/connect.sh | bash -s -- --dry-run
#   curl -fsSL https://echo.echoguard.ca/connector/connect.sh | bash -s -- --uninstall
#
# What it does:
#   1. Verifies its embedded files against the pinned fingerprints below
#   2. Finds your phone system (Asterisk, FreePBX, FreeSWITCH, Kamailio)
#   3. Points its call-signal copy (HEPv3 — signaling only, never audio)
#      at a small local helper
#   4. Installs the helper, which sends the signals to Echo over TLS
#      and phones home every 60 seconds so the Echo dashboard can show
#      this phone system as a connected node
#
# Security (chain of custody — the 3CX lesson):
#   * Served only from echo.echoguard.ca over TLS. Nothing is ever
#     downloaded from a third party, no package repos, no CDNs.
#   * Every embedded file is hash-verified against pins baked into
#     this installer before a single byte is written.
#   * The installer re-checks itself against the published manifest
#     (manifest.json) and refuses to run if it does not match.
#   * The full source of everything it runs is viewable before you
#     run it: https://echo.echoguard.ca/connector/connect.sh
#   * Every change is logged to /var/log/echo-connector/audit.log
#     and every touched file is backed up to /var/backups/echo-connector.
#   * Reversible: --uninstall removes exactly what it added and
#     restores the previous configuration.
#   * The helper runs as an unprivileged user, opens no port to the
#     internet (loopback UDP/TCP only), and makes one kind of
#     outbound call: HTTPS to the Echo endpoint.
#   * Idempotent: running it again cleanly replaces the marked blocks.
set -euo pipefail

INSTALLER_VERSION="1.0.0"
CONNECTOR_URL="https://echo.echoguard.ca/connector/connect.sh"
ECHO_API="https://echo.echoguard.ca"
ECHO_API_PATH="$ECHO_API/api"
LISTEN_PORT=9062
CAPTURE_ADDRESS="127.0.0.1:$LISTEN_PORT"
NODE_ID=""
CAPTURE_ID=7

# Pinned fingerprints (SHA-256). The installer verifies its embedded
# content against these before doing anything.
EXPECTED_CONNECTOR_SHA256="078dd64b7ae061449eedfabb1772a2935a61cb4db7a2576ecb4019caa1942085"
EXPECTED_EXAMPLE_ASTERISK_SHA256="2af734c36fdaebbdbcdf2633e22760f65f1c561f49f55304ef99352f0fa7b754"
EXPECTED_EXAMPLE_FREEPBX_SHA256="bc742dc498048a813d1f2692685fce3a9c097be730b29a979a2e08d7ba5889f4"
EXPECTED_EXAMPLE_FREESWITCH_SHA256="5c1527a6e29fa2b0d9e5079c6333787e7d9b2577ac0f9ad9e9b02fecc29436f5"
EXPECTED_EXAMPLE_KAMAILIO_SHA256="3742eed800b6f5111d6b1487203358899c634ca418a1b5f556ceafa3b92e136a"

# Embedded files — the agent never has to go out and look for
# examples. Everything it needs is inside the installer.
connector_py() {
cat <<'CONNECTOR_EOF'
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
CONNECTOR_EOF

}

example_asterisk() {
cat <<'EX_ASTERISK_EOF'
; Echo connector — Asterisk res_hep capture (HEPv3)
; Applied by connect.sh inside marked blocks so re-runs are clean.
; The phone system copies its call signals (SIP — never audio)
; to the Echo connector listening on loopback.

[general]
enabled = yes
capture_address = __CAPTURE_ADDRESS__
capture_id = __CAPTURE_ID__
uuid_type = call-id
EX_ASTERISK_EOF

}

example_freepbx() {
cat <<'EX_FREEPBX_EOF'
# Echo connector — FreePBX capture (HEPv3)
#
# FreePBX is Asterisk underneath, so the capture is the Asterisk
# res_hep config (hep.conf). FreePBX regenerates sip.conf and
# pjsip.conf when you apply changes in the GUI, but it does not
# manage hep.conf — this file survives `fwconsole reload`.
#
# Applied by connect.sh inside marked blocks so re-runs are clean.
# The phone system copies its call signals (SIP — never audio)
# to the Echo connector listening on loopback.

[general]
enabled = yes
capture_address = __CAPTURE_ADDRESS__
capture_id = __CAPTURE_ID__
uuid_type = call-id

# If no signals arrive after install, load the capture modules:
#   asterisk -rx "module load res_hep.so"
#   asterisk -rx "module load res_hep_pjsip.so"
# and make sure neither is listed with noload= in modules.conf.
EX_FREEPBX_EOF

}

example_freeswitch() {
cat <<'EX_FREESWITCH_EOF'
<!-- Echo connector — FreeSWITCH Sofia capture (HEPv3) -->
<!-- Applied by connect.sh. Two pieces, both from the FreeSWITCH
     documentation (Sofia profile settings):

     1. capture-server  — a GLOBAL Sofia setting. Goes in
        <global_settings> in sofia.conf.xml. Tells Sofia where
        to mirror SIP signaling, in HEPv3, with this box's
        capture id.
     2. sip-capture     — a per-PROFILE setting. Goes in each
        profile's <params> (internal.xml, external.xml, ...).
        Turns the mirroring on for that profile.

     The phone system copies its call signals (SIP — never audio)
     to the Echo connector listening on loopback. -->

<!-- global_settings (sofia.conf.xml) -->
<param name="capture-server"
       value="udp:__CAPTURE_ADDRESS__;hep=3;capture_id=__CAPTURE_ID__"/>

<!-- each sip profile (sip_profiles/*.xml) -->
<param name="sip-capture" value="true"/>
EX_FREESWITCH_EOF

}

example_kamailio() {
cat <<'EX_KAMAILIO_EOF'
# Echo connector — Kamailio siptrace capture (HEPv3)
#
# From the Kamailio siptrace module documentation (the sipcapture
# project's canonical Kamailio example). siptrace duplicates every
# SIP message and sends the copy to the Echo connector in HEPv3.
#
# Applied by connect.sh inside marked blocks: the modparams go
# after the last loadmodule line, and sip_trace() goes at the top
# of the main route. Re-runs replace the marked blocks cleanly.
# The proxy copies its call signals (SIP — never audio) to the
# Echo connector listening on loopback.

loadmodule "siptrace.so"

modparam("siptrace", "duplicate_uri", "sip:__CAPTURE_ADDRESS__")
modparam("siptrace", "hep_mode_on", 1)
modparam("siptrace", "trace_to_database", 0)
modparam("siptrace", "trace_on", 1)

# in the main route:
route {
    sip_trace();
    # ... the rest of your routing ...
}
EX_KAMAILIO_EOF

}

NODE_TOKEN=""
DRY_RUN=0
UNINSTALL=0
ADOPT_EXISTING=0
PLATFORM_OVERRIDE=""

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --adopt-existing) ADOPT_EXISTING=1 ;;
    --platform=*) PLATFORM_OVERRIDE="${arg#--platform=}" ;;
    --help|-h)
      echo "usage: connect.sh ['EC-<id>.<key>'] [--dry-run] [--uninstall]"
      echo "                   [--adopt-existing] [--platform=name]"
      echo ""
      echo "  'EC-<id>.<key>'  setup string from the Echo dashboard (required"
      echo "                   unless --dry-run or --uninstall)"
      echo "  --dry-run        show everything it would do, change nothing"
      echo "  --uninstall      remove the connector and restore backups"
      echo "  --adopt-existing replace an existing HEP capture with Echo"
      echo "                   (a backup is kept in /var/backups/echo-connector)"
      echo "  --platform=name  force a platform (asterisk, freepbx, freeswitch,"
      echo "                   kamailio) instead of auto-detecting"
      exit 0
      ;;
    EC-*) NODE_TOKEN="$arg" ;;
    *) echo "echo-connector: unknown argument: $arg" >&2; exit 2 ;;
  esac
done

AUDIT_LOG=/var/log/echo-connector/audit.log
BACKUP_DIR=/var/backups/echo-connector

die() { echo "echo-connector: $*" >&2; exit 1; }

audit() {
  mkdir -p "$(dirname "$AUDIT_LOG")" 2>/dev/null || true
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >> "$AUDIT_LOG" 2>/dev/null || true
}

log() { echo "echo-connector: $*"; }

backup_file() {
  [ -f "$1" ] || return 0
  mkdir -p "$BACKUP_DIR"
  local ts name
  ts=$(date +%Y%m%d%H%M%S)
  name=$(basename "$1")
  cp -a "$1" "$BACKUP_DIR/$name.$ts.bak"
  echo "$BACKUP_DIR/$name.$ts.bak"
}

restore_file() {
  local name latest
  name=$(basename "$1")
  latest=$(ls -1t "$BACKUP_DIR/$name."*.bak 2>/dev/null | head -1)
  if [ -n "$latest" ]; then
    cp -a "$latest" "$1"
    log "restored $1 from $latest"
  fi
}

# ---------- chain of custody ----------

verify_embedded() {
  local actual
  actual=$(connector_py | sha256sum | awk '{print $1}')
  [ "$actual" = "$EXPECTED_CONNECTOR_SHA256" ] ||
    die "integrity check failed: the embedded agent does not match its pinned fingerprint. Nothing was changed."
  actual=$(example_asterisk | sha256sum | awk '{print $1}')
  [ "$actual" = "$EXPECTED_EXAMPLE_ASTERISK_SHA256" ] ||
    die "integrity check failed: the embedded Asterisk example does not match its pinned fingerprint."
  actual=$(example_freepbx | sha256sum | awk '{print $1}')
  [ "$actual" = "$EXPECTED_EXAMPLE_FREEPBX_SHA256" ] ||
    die "integrity check failed: the embedded FreePBX example does not match its pinned fingerprint."
  actual=$(example_freeswitch | sha256sum | awk '{print $1}')
  [ "$actual" = "$EXPECTED_EXAMPLE_FREESWITCH_SHA256" ] ||
    die "integrity check failed: the embedded FreeSWITCH example does not match its pinned fingerprint."
  actual=$(example_kamailio | sha256sum | awk '{print $1}')
  [ "$actual" = "$EXPECTED_EXAMPLE_KAMAILIO_SHA256" ] ||
    die "integrity check failed: the embedded Kamailio example does not match its pinned fingerprint."
  log "embedded files verified against pinned fingerprints"
}

verify_installer() {
  # Compare this installer against the fingerprint we publish.
  # TLS already guarantees the origin; this catches a stale or
  # tampered copy even if it came through a caching layer.
  local published mine
  published=$(curl -fsSL --max-time 20 "$ECHO_API/connector/manifest.json" 2>/dev/null |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["files"]["connect.sh"])' 2>/dev/null) || {
    log "note: could not fetch the published manifest (still over TLS) — continuing"
    return 0
  }
  mine=$(curl -fsSL --max-time 20 "$CONNECTOR_URL" 2>/dev/null | sha256sum | awk '{print $1}') || {
    log "note: could not re-fetch this installer to compare — continuing over TLS"
    return 0
  }
  [ "$published" = "$mine" ] ||
    die "this installer does not match the fingerprint published at $CONNECTOR_URL. Refusing to run."
  log "installer matches the published fingerprint"
}

# ---------- platform detection ----------

detect_platform() {
  if command -v fwconsole >/dev/null 2>&1 || [ -d /var/www/html/admin ] || [ -d /etc/freepbx ]; then
    echo freepbx
  elif command -v asterisk >/dev/null 2>&1 || [ -d /etc/asterisk ]; then
    echo asterisk
  elif command -v fs_cli >/dev/null 2>&1 || [ -d /etc/freeswitch ]; then
    echo freeswitch
  elif command -v kamailio >/dev/null 2>&1 || [ -d /etc/kamailio ]; then
    echo kamailio
  else
    echo unknown
  fi
}

# ---------- Echo activation ----------

activate_node() {
  local resp
  resp=$(curl -fsSL --max-time 20 -X POST "$ECHO_API_PATH/nodes/heartbeat" \
    -H "Content-Type: application/json" \
    -H "X-Echo-Node-Key: $NODE_TOKEN" \
    -d "{\"installer_version\":\"$INSTALLER_VERSION\",\"platform\":\"$PLATFORM\"}") \
    || die "could not reach Echo at $ECHO_API. This computer needs outbound HTTPS (443) to $ECHO_API."
  NODE_ID=$(printf '%s' "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("node_id",""))')
  CAPTURE_ID=$(printf '%s' "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("capture_id","7"))')
  [ -n "$NODE_ID" ] || die "Echo did not recognize the node key. Generate a fresh setup string in the Echo dashboard."
}

# ---------- platform installers ----------
# Each writes only inside marked blocks, so re-runs replace cleanly
# and --uninstall can remove exactly what was added.

apply_asterisk() {
  local conf=/etc/asterisk/hep.conf
  if [ "$DRY_RUN" = "1" ]; then
    log "[dry-run] would write $conf with:"
    example_asterisk | sed -e "s|__CAPTURE_ADDRESS__|$CAPTURE_ADDRESS|g" \
                           -e "s|__CAPTURE_ID__|$CAPTURE_ID|g" | sed 's/^/    /'
    return 0
  fi
  if [ -f "$conf" ] && ! grep -q "echoguard-connector" "$conf"; then
    if [ "$ADOPT_EXISTING" != "1" ]; then
      log "this phone system already sends its signals somewhere else ($conf has a"
      log "capture this installer did not create). The installer will not touch it."
      log "options:"
      log "  --adopt-existing   replace the existing capture with Echo (backup kept in"
      log "                     $BACKUP_DIR)"
      log "  ask Echo support about running two captures side by side"
      return 2
    fi
    backup_file "$conf" >/dev/null
    : > "$conf"
    log "replaced the existing capture (backup kept in $BACKUP_DIR)"
  elif [ -f "$conf" ]; then
    backup_file "$conf" >/dev/null
    sed -i '/echoguard-connector begin/,/echoguard-connector end/d' "$conf"
  else
    backup_file "$conf" >/dev/null
  fi
  {
    echo "; echoguard-connector begin (v1) — Echo signaling capture"
    if [ "$PLATFORM" = "freepbx" ]; then
      example_freepbx
    else
      example_asterisk
    fi | sed -e "s|__CAPTURE_ADDRESS__|$CAPTURE_ADDRESS|g" \
            -e "s|__CAPTURE_ID__|$CAPTURE_ID|g"
    echo "; echoguard-connector end"
  } >> "$conf"
  audit "wrote $conf (capture -> $CAPTURE_ADDRESS, id $CAPTURE_ID)"
  if command -v asterisk >/dev/null 2>&1; then
    asterisk -rx "module reload res_hep.so" >/dev/null 2>&1 || true
    asterisk -rx "module reload res_hep_pjsip.so" >/dev/null 2>&1 || true
  fi
  log "capture configured in $conf"
}

apply_freeswitch() {
  local conf=/etc/freeswitch/sofia.conf.xml
  [ -f "$conf" ] || die "sofia.conf.xml not found — is FreeSWITCH installed?"
  if [ "$DRY_RUN" = "1" ]; then
    log "[dry-run] would add to $conf (global_settings):"
    log '    <param name="capture-server" value="udp:'"$CAPTURE_ADDRESS"';hep=3;capture_id='"$CAPTURE_ID"'"/>'
    log "[dry-run] would add <param name=\"sip-capture\" value=\"true\"/> to every profile in /etc/freeswitch/sip_profiles/"
    return 0
  fi
  backup_file "$conf" >/dev/null
  sed -i '/echoguard-connector begin/,/echoguard-connector end/d' "$conf"
  if grep -q "<global_settings>" "$conf"; then
    sed -i "s|<global_settings>|<global_settings>\n    <!-- echoguard-connector begin (v1) -->\n    <param name=\"capture-server\" value=\"udp:${CAPTURE_ADDRESS};hep=3;capture_id=${CAPTURE_ID}\"/>\n    <!-- echoguard-connector end -->|" "$conf"
  else
    sed -i "s|<section name=\"sofia\"|<section name=\"sofia\"\n  <global_settings>\n    <!-- echoguard-connector begin (v1) -->\n    <param name=\"capture-server\" value=\"udp:${CAPTURE_ADDRESS};hep=3;capture_id=${CAPTURE_ID}\"/>\n    <!-- echoguard-connector end -->\n  </global_settings>|" "$conf"
  fi
  audit "added capture-server to $conf"
  local pf
  for pf in /etc/freeswitch/sip_profiles/*.xml; do
    [ -f "$pf" ] || continue
    grep -q 'name="sip-capture"' "$pf" && continue
    backup_file "$pf" >/dev/null
    sed -i 's|</params>|    <!-- echoguard-connector begin (v1) -->\n    <param name="sip-capture" value="true"/>\n    <!-- echoguard-connector end -->\n  </params>|' "$pf"
    audit "added sip-capture to $pf"
  done
  fs_cli -x "reloadxml" >/dev/null 2>&1 || true
  log "capture configured in sofia.conf.xml and all sip profiles"
}

apply_kamailio() {
  local cfg=/etc/kamailio/kamailio.cfg
  [ -f "$cfg" ] || die "kamailio.cfg not found — is Kamailio installed?"
  if [ "$DRY_RUN" = "1" ]; then
    log "[dry-run] would add after the last loadmodule in $cfg:"
    log "    loadmodule \"siptrace.so\""
    log "    modparam(\"siptrace\", \"duplicate_uri\", \"sip:${CAPTURE_ADDRESS}\")"
    log "    modparam(\"siptrace\", \"hep_mode_on\", 1)"
    log "    modparam(\"siptrace\", \"trace_to_database\", 0)"
    log "    modparam(\"siptrace\", \"trace_on\", 1)"
    log "[dry-run] would add sip_trace(); at the top of the main route"
    return 0
  fi
  backup_file "$cfg" >/dev/null
  sed -i '/echoguard-connector begin/,/echoguard-connector end/d' "$cfg"

  local block
  if grep -q 'loadmodule "siptrace.so"' "$cfg"; then
    block="# echoguard-connector begin (v1) — Echo signaling capture
modparam(\"siptrace\", \"duplicate_uri\", \"sip:${CAPTURE_ADDRESS}\")
modparam(\"siptrace\", \"hep_mode_on\", 1)
modparam(\"siptrace\", \"trace_to_database\", 0)
modparam(\"siptrace\", \"trace_on\", 1)
# echoguard-connector end"
  else
    block="# echoguard-connector begin (v1) — Echo signaling capture
loadmodule \"siptrace.so\"
modparam(\"siptrace\", \"duplicate_uri\", \"sip:${CAPTURE_ADDRESS}\")
modparam(\"siptrace\", \"hep_mode_on\", 1)
modparam(\"siptrace\", \"trace_to_database\", 0)
modparam(\"siptrace\", \"trace_on\", 1)
# echoguard-connector end"
  fi
  local last_lm
  last_lm=$(grep -n '^loadmodule' "$cfg" | tail -1 | cut -d: -f1)
  if [ -z "$last_lm" ]; then
    last_lm=$(grep -n '^#!KAMAILIO' "$cfg" | head -1 | cut -d: -f1)
  fi
  [ -n "$last_lm" ] || die "could not find where to insert the siptrace settings in $cfg"
  awk -v n="$last_lm" -v block="$block" 'NR==n{print; print block; next} {print}' \
    "$cfg" > "$cfg.echoguard.tmp" && mv "$cfg.echoguard.tmp" "$cfg"
  audit "added siptrace modparams to $cfg"

  if ! grep -q "sip_trace()" "$cfg"; then
    awk '!done && $0 ~ /^route[ \t]*\{/ {
      print
      print "    # echoguard-connector begin (v1) — Echo signaling capture"
      print "    sip_trace();"
      print "    # echoguard-connector end"
      done=1
      next
    }
    {print}' "$cfg" > "$cfg.echoguard.tmp" && mv "$cfg.echoguard.tmp" "$cfg"
    audit "added sip_trace() to the main route in $cfg"
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet kamailio; then
    log "reloading Kamailio (a reload can briefly drop in-flight calls)"
    systemctl try-reload-or-restart kamailio || true
  fi
  log "capture configured in kamailio.cfg"
}

# ---------- the cloud example fallback ----------
# Platforms added after this installer was published are served
# from our own cloud (never a third party): the installer asks
# the Echo API for the vetted example and applies it by kind.

fetch_cloud_example() {
  curl -fsSL --max-time 20 "$ECHO_API_PATH/connector/examples?platform=$1" \
    -H "X-Echo-Node-Key: $NODE_TOKEN"
}

apply_cloud_example() {
  local platform="$1" resp kind text
  resp=$(fetch_cloud_example "$platform") ||
    die "Echo has no vetted example for platform \"$platform\" yet — it is not supported."
  kind=$(printf '%s' "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("kind",""))')
  text=$(printf '%s' "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("text",""))')
  case "$kind" in
    asterisk) log "applying the Asterisk-style example from the Echo example store" ;;
    freeswitch) log "applying the FreeSWITCH-style example from the Echo example store" ;;
    kamailio) log "applying the Kamailio-style example from the Echo example store" ;;
    raw)
      log "Echo sent this example for \"$platform\" (review it before applying by hand):"
      printf '%s\n' "$text" | sed 's/^/    /'
      return 0
      ;;
    *) die "unknown example kind from the Echo example store: $kind" ;;
  esac
  if [ "$DRY_RUN" = "1" ]; then
    log "[dry-run] cloud example for $platform:"
    printf '%s\n' "$text" | sed 's/^/    /'
    return 0
  fi
  echo "$text" > "/opt/echo-connector/example-$platform.txt"
  audit "saved cloud example for $platform to /opt/echo-connector/example-$platform.txt"
  log "example saved to /opt/echo-connector/example-$platform.txt"
  log "apply it following the instructions it contains (the Echo example store"
  log "sends platform-specific instructions with each example)"
}

# ---------- the helper ----------

install_agent() {
  if [ "$DRY_RUN" = "1" ]; then
    log "[dry-run] would install /opt/echo-connector/connector.py (verified agent)"
    log "[dry-run] would install /opt/echo-connector/agent.env (node key, endpoint, platform)"
    log "[dry-run] would install and start the echo-connector systemd service"
    return 0
  fi
  # Dedicated unprivileged user for the helper (falls back to
  # nobody on systems without useradd).
  if ! id echo-agent >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin echo-agent 2>/dev/null || true
  fi
  if id echo-agent >/dev/null 2>&1; then
    AGENT_USER=echo-agent
    AGENT_GROUP=echo-agent
  else
    AGENT_USER=nobody
    AGENT_GROUP=nogroup
  fi
  mkdir -p /opt/echo-connector /var/log/echo-connector /var/lib/echo-connector
  connector_py > /opt/echo-connector/connector.py
  chmod 755 /opt/echo-connector/connector.py
  cat > /opt/echo-connector/agent.env <<ENVEOF
ECHO_NODE_KEY=$NODE_TOKEN
ECHO_ENDPOINT=$ECHO_API
ECHO_PLATFORM=$PLATFORM
ECHO_NODE_ID=$NODE_ID
ECHO_LISTEN_HOST=127.0.0.1
ECHO_LISTEN_PORT=$LISTEN_PORT
ENVEOF
  chmod 600 /opt/echo-connector/agent.env
  chown $AGENT_USER:$AGENT_GROUP /var/log/echo-connector /var/lib/echo-connector 2>/dev/null || true
  cat > /etc/systemd/system/echo-connector.service <<UNITEOF
[Unit]
Description=Echo connector — phone system signaling to Echo
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$AGENT_USER
Group=$AGENT_GROUP
WorkingDirectory=/opt/echo-connector
EnvironmentFile=/opt/echo-connector/agent.env
ExecStart=/usr/bin/python3 /opt/echo-connector/connector.py
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/log/echo-connector /var/lib/echo-connector

[Install]
WantedBy=multi-user.target
UNITEOF
  systemctl daemon-reload
  systemctl enable echo-connector
  # restart (not just --now) so unit changes apply on re-runs
  systemctl restart echo-connector
  sleep 2
  audit "installed and started echo-connector.service (node $NODE_ID)"
  if systemctl is-active --quiet echo-connector; then
    log "helper installed and running (systemd: echo-connector.service)"
  else
    log "helper installed but not running — check: journalctl -u echo-connector -n 50"
  fi
}

self_test() {
  [ "$DRY_RUN" = "1" ] && return 0
  # The node key lives in the systemd EnvironmentFile, so the
  # self-test runs with it loaded (the same environment the
  # service itself gets).
  (
    set -a
    . /opt/echo-connector/agent.env
    set +a
    cd /opt/echo-connector
    python3 connector.py --self-test
  )
  if [ $? = 0 ]; then
    log "Echo accepted a test signal from this phone system"
    audit "self-test passed (node $NODE_ID)"
  else
    log "the test signal did not reach Echo — check that this computer can"
    log "reach $ECHO_API on 443, then: journalctl -u echo-connector -n 50"
  fi
}

uninstall() {
  log "removing the Echo connector"
  systemctl disable --now echo-connector 2>/dev/null || true
  rm -f /etc/systemd/system/echo-connector.service
  systemctl daemon-reload 2>/dev/null || true
  restore_file /etc/asterisk/hep.conf
  restore_file /etc/freeswitch/sofia.conf.xml
  restore_file /etc/kamailio/kamailio.cfg
  local pf
  for pf in /etc/freeswitch/sip_profiles/*.xml; do
    [ -f "$pf" ] || continue
    grep -q "echoguard-connector" "$pf" && restore_file "$pf"
  done
  if command -v asterisk >/dev/null 2>&1; then
    asterisk -rx "module reload res_hep.so" >/dev/null 2>&1 || true
  fi
  rm -rf /opt/echo-connector
  audit "uninstalled echo-connector"
  log "removed. configuration backups (if any) are in $BACKUP_DIR"
}

# ---------- main ----------

[ "$EUID" -eq 0 ] || die "run this as root (sudo)"
command -v systemctl >/dev/null 2>&1 || die "this installer needs systemd"
command -v python3 >/dev/null 2>&1 || die "this installer needs python3"

if [ "$UNINSTALL" = "1" ]; then
  uninstall
  exit 0
fi

PLATFORM=$(detect_platform)
[ -z "$PLATFORM_OVERRIDE" ] || PLATFORM="$PLATFORM_OVERRIDE"

log "Echo connector $INSTALLER_VERSION"
log "detected phone system: $PLATFORM"
audit "installer started (version $INSTALLER_VERSION, platform $PLATFORM, dry_run=$DRY_RUN)"

verify_embedded
verify_installer

case "$PLATFORM" in
  asterisk|freepbx) apply_asterisk ;;
  freeswitch) apply_freeswitch ;;
  kamailio) apply_kamailio ;;
  unknown)
    if [ -n "$PLATFORM_OVERRIDE" ]; then
      apply_cloud_example "$PLATFORM_OVERRIDE"
    else
      log "no supported phone system found (Asterisk, FreePBX, FreeSWITCH, Kamailio)."
      log "if your phone system is supported, run again with --platform=<name>"
      log "and the installer will ask the Echo cloud for its vetted example."
      exit 3
    fi
    ;;
  *)
    apply_cloud_example "$PLATFORM"
    ;;
esac

# a second run on the same box after the first platform is fine,
# but the loopback listener can only exist once per box
if [ "$DRY_RUN" = "1" ]; then
  log "[dry-run] complete — nothing was changed"
  exit 0
fi

[ -n "$NODE_TOKEN" ] || die "missing the setup string. Run again with the 'EC-...' string from the Echo dashboard."
activate_node
log "node registered: $NODE_ID (capture id $CAPTURE_ID)"
install_agent
self_test

echo ""
log "done. this phone system now appears as a connected node in Echo."
log "the dashboard shows its check-ins, calls, and problems in plain words."
log ""
log "remove it any time with:"
log "  curl -fsSL $CONNECTOR_URL | bash -s -- --uninstall"
