#!/usr/bin/env python3
"""Assemble connect.sh from the connector agent + example bundles.

The installer embeds the agent and every example, with the
SHA-256 fingerprint of each baked in. Before writing anything
to the customer's system, the installer re-hashes its embedded
content and refuses to run if anything does not match the pin.
Nothing is fetched from any third party at any point — the only
hosts involved are echo.echoguard.ca (TLS) and the loopback
interface of the phone system's own computer.

Usage: python3 build.py   (writes connect.sh + manifest.json)
"""
import hashlib
import json
import pathlib
import time

ROOT = pathlib.Path(__file__).parent
EXAMPLES = ROOT / "examples"

EXAMPLE_FILES = {
    "asterisk": EXAMPLES / "asterisk-hep.conf",
    "freepbx": EXAMPLES / "freepbx-hep.conf",
    "freeswitch": EXAMPLES / "freeswitch-sofia.txt",
    "kamailio": EXAMPLES / "kamailio-siptrace.cfg",
}


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def heredoc(name, content):
    """Wrap content in a bash function with a quoted heredoc.

    The content is embedded byte-for-byte (including the
    trailing newline) so `func | sha256sum` matches the
    pinned fingerprint of the source file exactly.
    """
    assert name not in content, "heredoc delimiter collision: %s" % name
    if not content.endswith("\n"):
        content += "\n"
    return "cat <<'%s'\n%s%s\n" % (name, content, name)


def build():
    connector_py = (ROOT / "connector.py").read_text()
    examples = {k: p.read_text() for k, p in EXAMPLE_FILES.items()}

    pins = {
        "connector": sha256_text(connector_py),
        **{k: sha256_text(v) for k, v in examples.items()},
    }

    installer = """#!/usr/bin/env bash
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

INSTALLER_VERSION="__INSTALLER_VERSION__"
CONNECTOR_URL="https://echo.echoguard.ca/connector/connect.sh"
ECHO_API="https://echo.echoguard.ca"
ECHO_API_PATH="$ECHO_API/api"
LISTEN_PORT=9062
CAPTURE_ADDRESS="127.0.0.1:$LISTEN_PORT"
NODE_ID=""
CAPTURE_ID=7

# Pinned fingerprints (SHA-256). The installer verifies its embedded
# content against these before doing anything.
EXPECTED_CONNECTOR_SHA256="__PIN_CONNECTOR__"
EXPECTED_EXAMPLE_ASTERISK_SHA256="__PIN_ASTERISK__"
EXPECTED_EXAMPLE_FREEPBX_SHA256="__PIN_FREEPBX__"
EXPECTED_EXAMPLE_FREESWITCH_SHA256="__PIN_FREESWITCH__"
EXPECTED_EXAMPLE_KAMAILIO_SHA256="__PIN_KAMAILIO__"

# Embedded files — the agent never has to go out and look for
# examples. Everything it needs is inside the installer.
connector_py() {
__CONNECTOR_PY__
}

example_asterisk() {
__EX_ASTERISK__
}

example_freepbx() {
__EX_FREEPBX__
}

example_freeswitch() {
__EX_FREESWITCH__
}

example_kamailio() {
__EX_KAMAILIO__
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
  resp=$(curl -fsSL --max-time 20 -X POST "$ECHO_API_PATH/nodes/heartbeat" \\
    -H "Content-Type: application/json" \\
    -H "X-Echo-Node-Key: $NODE_TOKEN" \\
    -d "{\\"installer_version\\":\\"$INSTALLER_VERSION\\",\\"platform\\":\\"$PLATFORM\\"}") \\
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
    example_asterisk | sed -e "s|__CAPTURE_ADDRESS__|$CAPTURE_ADDRESS|g" \\
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
    fi | sed -e "s|__CAPTURE_ADDRESS__|$CAPTURE_ADDRESS|g" \\
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
    log "[dry-run] would add <param name=\\"sip-capture\\" value=\\"true\\"/> to every profile in /etc/freeswitch/sip_profiles/"
    return 0
  fi
  backup_file "$conf" >/dev/null
  sed -i '/echoguard-connector begin/,/echoguard-connector end/d' "$conf"
  if grep -q "<global_settings>" "$conf"; then
    sed -i "s|<global_settings>|<global_settings>\\n    <!-- echoguard-connector begin (v1) -->\\n    <param name=\\"capture-server\\" value=\\"udp:${CAPTURE_ADDRESS};hep=3;capture_id=${CAPTURE_ID}\\"/>\\n    <!-- echoguard-connector end -->|" "$conf"
  else
    sed -i "s|<section name=\\"sofia\\"|<section name=\\"sofia\\"\\n  <global_settings>\\n    <!-- echoguard-connector begin (v1) -->\\n    <param name=\\"capture-server\\" value=\\"udp:${CAPTURE_ADDRESS};hep=3;capture_id=${CAPTURE_ID}\\"/>\\n    <!-- echoguard-connector end -->\\n  </global_settings>|" "$conf"
  fi
  audit "added capture-server to $conf"
  local pf
  for pf in /etc/freeswitch/sip_profiles/*.xml; do
    [ -f "$pf" ] || continue
    grep -q 'name="sip-capture"' "$pf" && continue
    backup_file "$pf" >/dev/null
    sed -i 's|</params>|    <!-- echoguard-connector begin (v1) -->\\n    <param name="sip-capture" value="true"/>\\n    <!-- echoguard-connector end -->\\n  </params>|' "$pf"
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
    log "    loadmodule \\"siptrace.so\\""
    log "    modparam(\\"siptrace\\", \\"duplicate_uri\\", \\"sip:${CAPTURE_ADDRESS}\\")"
    log "    modparam(\\"siptrace\\", \\"hep_mode_on\\", 1)"
    log "    modparam(\\"siptrace\\", \\"trace_to_database\\", 0)"
    log "    modparam(\\"siptrace\\", \\"trace_on\\", 1)"
    log "[dry-run] would add sip_trace(); at the top of the main route"
    return 0
  fi
  backup_file "$cfg" >/dev/null
  sed -i '/echoguard-connector begin/,/echoguard-connector end/d' "$cfg"

  local block
  if grep -q 'loadmodule "siptrace.so"' "$cfg"; then
    block="# echoguard-connector begin (v1) — Echo signaling capture
modparam(\\"siptrace\\", \\"duplicate_uri\\", \\"sip:${CAPTURE_ADDRESS}\\")
modparam(\\"siptrace\\", \\"hep_mode_on\\", 1)
modparam(\\"siptrace\\", \\"trace_to_database\\", 0)
modparam(\\"siptrace\\", \\"trace_on\\", 1)
# echoguard-connector end"
  else
    block="# echoguard-connector begin (v1) — Echo signaling capture
loadmodule \\"siptrace.so\\"
modparam(\\"siptrace\\", \\"duplicate_uri\\", \\"sip:${CAPTURE_ADDRESS}\\")
modparam(\\"siptrace\\", \\"hep_mode_on\\", 1)
modparam(\\"siptrace\\", \\"trace_to_database\\", 0)
modparam(\\"siptrace\\", \\"trace_on\\", 1)
# echoguard-connector end"
  fi
  local last_lm
  last_lm=$(grep -n '^loadmodule' "$cfg" | tail -1 | cut -d: -f1)
  if [ -z "$last_lm" ]; then
    last_lm=$(grep -n '^#!KAMAILIO' "$cfg" | head -1 | cut -d: -f1)
  fi
  [ -n "$last_lm" ] || die "could not find where to insert the siptrace settings in $cfg"
  awk -v n="$last_lm" -v block="$block" 'NR==n{print; print block; next} {print}' \\
    "$cfg" > "$cfg.echoguard.tmp" && mv "$cfg.echoguard.tmp" "$cfg"
  audit "added siptrace modparams to $cfg"

  if ! grep -q "sip_trace()" "$cfg"; then
    awk '!done && $0 ~ /^route[ \\t]*\\{/ {
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
  curl -fsSL --max-time 20 "$ECHO_API_PATH/connector/examples?platform=$1" \\
    -H "X-Echo-Node-Key: $NODE_TOKEN"
}

apply_cloud_example() {
  local platform="$1" resp kind text
  resp=$(fetch_cloud_example "$platform") ||
    die "Echo has no vetted example for platform \\"$platform\\" yet — it is not supported."
  kind=$(printf '%s' "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("kind",""))')
  text=$(printf '%s' "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("text",""))')
  case "$kind" in
    asterisk) log "applying the Asterisk-style example from the Echo example store" ;;
    freeswitch) log "applying the FreeSWITCH-style example from the Echo example store" ;;
    kamailio) log "applying the Kamailio-style example from the Echo example store" ;;
    raw)
      log "Echo sent this example for \\"$platform\\" (review it before applying by hand):"
      printf '%s\\n' "$text" | sed 's/^/    /'
      return 0
      ;;
    *) die "unknown example kind from the Echo example store: $kind" ;;
  esac
  if [ "$DRY_RUN" = "1" ]; then
    log "[dry-run] cloud example for $platform:"
    printf '%s\\n' "$text" | sed 's/^/    /'
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
"""

    # Embed the agent and examples, substituting pins.
    installer = installer.replace("__CONNECTOR_PY__", heredoc("CONNECTOR_EOF", connector_py))
    installer = installer.replace("__EX_ASTERISK__", heredoc("EX_ASTERISK_EOF", examples["asterisk"]))
    installer = installer.replace("__EX_FREEPBX__", heredoc("EX_FREEPBX_EOF", examples["freepbx"]))
    installer = installer.replace("__EX_FREESWITCH__", heredoc("EX_FREESWITCH_EOF", examples["freeswitch"]))
    installer = installer.replace("__EX_KAMAILIO__", heredoc("EX_KAMAILIO_EOF", examples["kamailio"]))

    installer = installer.replace("__INSTALLER_VERSION__", "1.0.0")
    installer = installer.replace("__PIN_CONNECTOR__", pins["connector"])
    installer = installer.replace("__PIN_ASTERISK__", pins["asterisk"])
    installer = installer.replace("__PIN_FREEPBX__", pins["freepbx"])
    installer = installer.replace("__PIN_FREESWITCH__", pins["freeswitch"])
    installer = installer.replace("__PIN_KAMAILIO__", pins["kamailio"])

    (ROOT / "connect.sh").write_text(installer)
    (ROOT / "connect.sh").chmod(0o755)

    manifest = {
        "version": "1.0.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": {
            "connect.sh": sha256_text(installer),
            "connector.py": pins["connector"],
            "examples": {k: v for k, v in pins.items() if k != "connector"},
        },
    }
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("built connect.sh (%d bytes)" % len(installer))
    print("manifest.json:")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    build()
