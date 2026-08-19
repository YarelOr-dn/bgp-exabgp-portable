#!/usr/bin/env bash
# install-bgp.sh — portable /BGP client (Cursor only). ExaBGP stays on --host.
set -euo pipefail

HOME_DIR="${HOME:?HOME not set}"
DRY_RUN=0
UNINSTALL=0
EXABGP_HOST="${BGP_EXABGP_HOST:-}"
MCP_URL="${BGP_MCP_URL:-http://127.0.0.1:9304/sse}"

usage() {
  cat <<'EOF'
install-bgp.sh — install portable /BGP into this user's Cursor

Options:
  --host HOST     ExaBGP/DNAAS host (SSH tunnel target)
  --mcp-url URL   MCP SSE URL (default http://127.0.0.1:9304/sse)
  --dry-run       Print actions only
  --uninstall     Remove copied command/skills (does not touch ExaBGP host)
  -h, --help

After install:
  ssh -N -L 9304:127.0.0.1:9304 <host>
  Reload Cursor, then /BGP (first load AskQuestions your global VLAN)
EOF
}

log() { printf '[BGP-INSTALL] %s\n' "$*"; }
die() { printf '[BGP-INSTALL][ERROR] %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) EXABGP_HOST="$2"; shift 2 ;;
    --mcp-url) MCP_URL="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] $*"
  else
    "$@"
  fi
}

if [[ "$UNINSTALL" -eq 1 ]]; then
  log "uninstall copies under $HOME_DIR/.cursor/commands/BGP.md and skills/bgp-*"
  run rm -f "$HOME_DIR/.cursor/commands/BGP.md"
  exit 0
fi

run mkdir -p "$HOME_DIR/.cursor/commands" "$HOME_DIR/.cursor/skills" "$HOME_DIR/.cursor/secrets"
run chmod 700 "$HOME_DIR/.cursor/secrets" 2>/dev/null || true

if [[ -f "$SCRIPT_DIR/commands/BGP.md" ]]; then
  log "copy commands/BGP.md -> $HOME_DIR/.cursor/commands/BGP.md"
  run cp -a "$SCRIPT_DIR/commands/BGP.md" "$HOME_DIR/.cursor/commands/BGP.md"
else
  die "missing $SCRIPT_DIR/commands/BGP.md"
fi

for s in bgp-tool bgp-peering-tool bgp-session-protection bgp-preflight-mcp-verification; do
  if [[ -d "$SCRIPT_DIR/skills/$s" ]]; then
    log "copy skill $s"
    run mkdir -p "$HOME_DIR/.cursor/skills/$s"
    run cp -a "$SCRIPT_DIR/skills/$s/." "$HOME_DIR/.cursor/skills/$s/"
  fi
done

MCP_JSON="$HOME_DIR/.cursor/mcp.json"
log "MCP stanza user-exabgp-mcp url=$MCP_URL host=${EXABGP_HOST:-unset}"
if [[ "$DRY_RUN" -eq 1 ]]; then
  log "[dry-run] merge $MCP_JSON"
else
  python3 - <<PY
import json, os, tempfile
from pathlib import Path
path = Path(os.path.expanduser("$MCP_JSON"))
data = {}
if path.exists():
    try:
        data = json.loads(path.read_text())
    except Exception:
        bak = path.with_suffix(path.suffix + ".bak_bgp")
        path.replace(bak)
        data = {}
servers = data.get("mcpServers") or data.get("mcp_servers") or {}
servers["user-exabgp-mcp"] = {"url": "$MCP_URL", "type": "sse"}
data["mcpServers"] = servers
fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".mcp_", suffix=".tmp")
os.close(fd)
Path(tmp).write_text(json.dumps(data, indent=2) + "\n")
os.replace(tmp, path)
print("wrote", path)
PY
fi

log "tunnel helper: ssh -N -L 9304:127.0.0.1:9304 ${EXABGP_HOST:-<exabgp-host>}"
log "do NOT install ExaBGP, systemd MCP, or crontab on this laptop"
log "next: reload Cursor, run /BGP (AskQuestion global VLAN on first load)"
exit 0
