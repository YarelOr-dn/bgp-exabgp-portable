#!/usr/bin/env bash
# Local-forward the host user-exabgp-mcp SSE port. ExaBGP stays on the host.
set -euo pipefail
HOST="${1:-${BGP_EXABGP_HOST:-}}"
if [[ -z "$HOST" ]]; then
  printf '[BGP-TUNNEL][ERROR] usage: bgp-tunnel.sh <exabgp-host>\n' >&2
  exit 1
fi
printf '[BGP-TUNNEL] ssh -N -L 9304:127.0.0.1:9304 %s\n' "$HOST"
exec ssh -N -L 9304:127.0.0.1:9304 "$HOST"
