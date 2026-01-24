#!/bin/bash
#===============================================================================
# Network Fix Script for Rocky 9 -> 10 Upgrade
#
# Fixes interface naming change (enp* -> ens*) for:
# - Main ethernet connection
# - VLAN parent interface references
#
# Run this BEFORE rebooting after distro-sync!
#
# Usage: ./fix-network-post-upgrade.sh [OLD_INTERFACE] [NEW_INTERFACE]
# Example: ./fix-network-post-upgrade.sh enp6s18 ens18
#===============================================================================

set -e

OLD_IFACE="${1:-enp6s18}"
NEW_IFACE="${2:-ens18}"

NM_DIR="/etc/NetworkManager/system-connections"
MODIFIED=0

echo "=== Network Interface Fix Script ==="
echo "Changing interface: ${OLD_IFACE} -> ${NEW_IFACE}"
echo ""

# Create backup
BACKUP_DIR="/root/nm-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp ${NM_DIR}/*.nmconnection "$BACKUP_DIR/" 2>/dev/null || true
echo "Backup created: $BACKUP_DIR"
echo ""

#--- Fix 1: Main ethernet connection file ---
OLD_FILE="${NM_DIR}/${OLD_IFACE}.nmconnection"
NEW_FILE="${NM_DIR}/${NEW_IFACE}.nmconnection"

if [[ -f "$OLD_FILE" ]]; then
    echo "Fixing main ethernet connection..."

    # Update interface-name inside the file
    sed -i "s/interface-name=${OLD_IFACE}/interface-name=${NEW_IFACE}/g" "$OLD_FILE"
    sed -i "s/^id=${OLD_IFACE}$/id=${NEW_IFACE}/g" "$OLD_FILE"

    # Rename the file
    mv "$OLD_FILE" "$NEW_FILE"
    echo "  Renamed: ${OLD_IFACE}.nmconnection -> ${NEW_IFACE}.nmconnection"
    echo "  Updated: interface-name=${NEW_IFACE}"
    MODIFIED=1
fi

#--- Fix 2: VLAN parent references ---
echo ""
echo "Checking VLAN configurations..."

VLAN_FILES=$(grep -l "parent=${OLD_IFACE}" ${NM_DIR}/*.nmconnection 2>/dev/null || true)

if [[ -n "$VLAN_FILES" ]]; then
    for file in $VLAN_FILES; do
        sed -i "s/parent=${OLD_IFACE}/parent=${NEW_IFACE}/g" "$file"
        echo "  Modified VLAN parent in: $(basename $file)"
        MODIFIED=1
    done
else
    echo "  No VLAN configurations found (OK for non-VLAN setups)"
fi

#--- Summary ---
echo ""
if [[ $MODIFIED -eq 0 ]]; then
    echo "No changes needed - interface names already correct or not found."
else
    echo "Reloading NetworkManager..."
    nmcli connection reload
    echo ""
    echo "Current network interfaces:"
    ip -br link show | grep -E "^(en|eth|vlan)" || true
fi

echo ""
echo "=== Done ==="
echo ""
echo "After reboot, the interface should be named: ${NEW_IFACE}"
