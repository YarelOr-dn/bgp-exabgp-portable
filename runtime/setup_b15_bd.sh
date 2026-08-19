#!/bin/bash
# Configure g_mgmt_v999 bridge-domain on DNAAS-LEAF-B15 for RR-SA-2
# RR-SA-2 connects to B15 via ge100-0/0/6 (and ge100-0/0/7)
# We need a .999 sub-interface on ge100-0/0/6 with vlan-id 999 in g_mgmt_v999

B15_IP="100.64.101.6"
B15_USER="dnroot"
B15_PASS="dnroot"

echo "[1] Checking if g_mgmt_v999 exists on B15..."
EXISTING=$(sshpass -p "$B15_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -o PreferredAuthentications=keyboard-interactive,password \
    "$B15_USER@$B15_IP" \
    "show config network-services bridge-domain instance g_mgmt_v999 | no-more" 2>/dev/null)
echo "Existing config: '$EXISTING'"

echo ""
echo "[2] Checking ge100-0/0/6 sub-interfaces..."
SUBIFS=$(sshpass -p "$B15_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -o PreferredAuthentications=keyboard-interactive,password \
    "$B15_USER@$B15_IP" \
    "show interfaces | include ge100-0/0/6 | no-more" 2>/dev/null)
echo "$SUBIFS"

echo ""
echo "[3] Checking hostname..."
HOSTNAME=$(sshpass -p "$B15_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -o PreferredAuthentications=keyboard-interactive,password \
    "$B15_USER@$B15_IP" \
    "show system name | no-more" 2>/dev/null)
echo "Hostname: '$HOSTNAME'"

echo ""
echo "[4] Checking bundle-60000 sub-interfaces (DNAAS fabric)..."
BUNDLE=$(sshpass -p "$B15_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -o PreferredAuthentications=keyboard-interactive,password \
    "$B15_USER@$B15_IP" \
    "show interfaces | include bundle-60000.999 | no-more" 2>/dev/null)
echo "bundle-60000.999: '$BUNDLE'"
