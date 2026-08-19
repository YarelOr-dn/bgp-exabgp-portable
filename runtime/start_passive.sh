#!/bin/bash
# Start ExaBGP in passive mode (listens on port 1179, iptables redirects 179->1179)
# PE-4 initiates the connection to us.

set -e

LOGFILE="/home/dn/SCALER/FLOWSPEC_VPN/exabgp/logs/pe_4_exabgp.log"
CONFFILE="/tmp/exabgp_pe_4.conf"
PIPE="/run/exabgp/exabgp.in"

# Kill any existing ExaBGP
pkill -9 -f "exabgp" 2>/dev/null || true
sleep 1

# Ensure pipe directory and named pipe exist
mkdir -p /run/exabgp 2>/dev/null || true
[ -p "$PIPE" ] || mkfifo "$PIPE"

# Ensure iptables redirect is in place (179 -> 1179)
if ! sudo iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir.*1179"; then
    sudo iptables -t nat -A PREROUTING -p tcp --dport 179 -j REDIRECT --to-port 1179
    echo "[OK] iptables redirect 179 -> 1179 added"
else
    echo "[OK] iptables redirect already in place"
fi

echo "[INFO] Starting ExaBGP in PASSIVE mode (listening on port 1179)..."
echo "[INFO] Config: $CONFFILE"
echo "[INFO] Log: $LOGFILE"

export exabgp_api_cli=false
export exabgp_bgp_passive=true
export exabgp_tcp_bind=100.64.6.134
export exabgp_tcp_port=1179
export exabgp_daemon_daemonize=false
export exabgp_daemon_drop=false
export exabgp_log_all=true
export exabgp_log_enable=true
export exabgp_api_pipename=exabgp

exec python3 /home/dn/.local/bin/exabgp "$CONFFILE" 2>&1 | tee "$LOGFILE"
