#!/bin/bash
#===============================================================================
# Kea DHCP Fix Script for Rocky 9 -> 10 Upgrade
#
# Fixes compatibility issues when upgrading from custom-compiled Kea
# to official Rocky 10 Kea packages.
#
# Issues addressed:
#   1. Custom systemd services pointing to /usr/local/kea/
#   2. Socket paths changed from /var/run/ to /run/kea/
#   3. Hooks library paths changed to /usr/lib64/kea/hooks/
#   4. Run script location changed to /usr/share/kea/scripts/
#   5. Log paths must be under /var/log/kea/
#   6. Config file permissions for 'kea' user
#
# Usage: ./fix-kea-post-upgrade.sh
#
# Prerequisites:
#   - Rocky Linux 10 with official Kea packages installed
#   - Existing Kea configuration in /etc/kea/
#
#===============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Kea DHCP Post-Upgrade Fix Script ===${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Check if Kea is installed from repo
if ! rpm -q kea &>/dev/null; then
    echo -e "${RED}Kea package not found. Install official Kea first:${NC}"
    echo "  dnf install kea kea-hooks -y"
    exit 1
fi

KEA_VERSION=$(rpm -q kea --qf '%{VERSION}')
echo "Detected Kea version: ${KEA_VERSION}"
echo ""

#------------------------------------------------------------------------------
# Step 1: Backup existing configuration
#------------------------------------------------------------------------------
echo -e "${YELLOW}[1/7] Creating configuration backup...${NC}"
BACKUP_DIR="/root/kea-config-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r /etc/kea/* "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/systemd/system/kea*.service "$BACKUP_DIR/" 2>/dev/null || true
echo "  Backup created: $BACKUP_DIR"

#------------------------------------------------------------------------------
# Step 2: Remove custom systemd service files
#------------------------------------------------------------------------------
echo -e "${YELLOW}[2/7] Removing custom systemd service files...${NC}"
CUSTOM_SERVICES=(
    "/etc/systemd/system/kea-dhcp4.service"
    "/etc/systemd/system/kea-dhcp6.service"
    "/etc/systemd/system/kea-ctrl-agent.service"
    "/etc/systemd/system/kea-dhcp-ddns.service"
)

for svc in "${CUSTOM_SERVICES[@]}"; do
    if [[ -f "$svc" ]]; then
        rm -f "$svc"
        echo "  Removed: $svc"
    fi
done
systemctl daemon-reload
echo "  Systemd reloaded"

#------------------------------------------------------------------------------
# Step 3: Update socket paths in configuration files
#------------------------------------------------------------------------------
echo -e "${YELLOW}[3/7] Updating socket paths (/var/run -> /run/kea)...${NC}"
for conf in /etc/kea/*.conf; do
    if grep -q "/var/run/" "$conf" 2>/dev/null; then
        # Update socket paths
        sed -i 's|/var/run/kea4-ctrl-socket|/run/kea/kea4-ctrl-socket|g' "$conf"
        sed -i 's|/var/run/kea6-ctrl-socket|/run/kea/kea6-ctrl-socket|g' "$conf"
        sed -i 's|/var/run/kea-ddns-ctrl-socket|/run/kea/kea-ddns-ctrl-socket|g' "$conf"
        echo "  Updated: $(basename $conf)"
    fi
done

#------------------------------------------------------------------------------
# Step 4: Update hooks library paths
#------------------------------------------------------------------------------
echo -e "${YELLOW}[4/7] Updating hooks library paths...${NC}"
for conf in /etc/kea/*.conf; do
    if grep -q "/usr/local/kea/lib/kea/hooks" "$conf" 2>/dev/null; then
        sed -i 's|/usr/local/kea/lib/kea/hooks|/usr/lib64/kea/hooks|g' "$conf"
        echo "  Updated hooks path in: $(basename $conf)"
    fi
done

#------------------------------------------------------------------------------
# Step 5: Move run_script hooks scripts
#------------------------------------------------------------------------------
echo -e "${YELLOW}[5/7] Relocating hook scripts to /usr/share/kea/scripts/...${NC}"
SCRIPTS_DIR="/usr/share/kea/scripts"
mkdir -p "$SCRIPTS_DIR"

# Find and move scripts referenced in config
for conf in /etc/kea/*.conf; do
    # Extract script paths from run_script hook configuration
    SCRIPT_PATHS=$(grep -oP '"name":\s*"\K/var/lib/kea/[^"]+' "$conf" 2>/dev/null || true)
    for script_path in $SCRIPT_PATHS; do
        script_name=$(basename "$script_path")
        if [[ -f "$script_path" ]]; then
            cp "$script_path" "$SCRIPTS_DIR/"
            chmod +x "$SCRIPTS_DIR/$script_name"
            echo "  Copied: $script_name -> $SCRIPTS_DIR/"
        fi
        # Update config to use new path
        sed -i "s|$script_path|$SCRIPTS_DIR/$script_name|g" "$conf"
        echo "  Updated path in: $(basename $conf)"
    done
done

#------------------------------------------------------------------------------
# Step 6: Update log paths
#------------------------------------------------------------------------------
echo -e "${YELLOW}[6/7] Updating log paths (/var/log -> /var/log/kea)...${NC}"
for conf in /etc/kea/*.conf; do
    # Fix log paths that are not under /var/log/kea/
    if grep -q '"output":\s*"/var/log/[^k]' "$conf" 2>/dev/null || \
       grep -q '"output":\s*"/var/log/kea[^/]' "$conf" 2>/dev/null; then
        # Update kea-ctrl-agent.log
        sed -i 's|"/var/log/kea-ctrl-agent.log"|"/var/log/kea/kea-ctrl-agent.log"|g' "$conf"
        # Update kea-dhcp4.log
        sed -i 's|"/var/log/kea-dhcp4.log"|"/var/log/kea/kea-dhcp4.log"|g' "$conf"
        # Update kea-dhcp6.log
        sed -i 's|"/var/log/kea-dhcp6.log"|"/var/log/kea/kea-dhcp6.log"|g' "$conf"
        # Update kea-dhcp-ddns.log
        sed -i 's|"/var/log/kea-dhcp-ddns.log"|"/var/log/kea/kea-dhcp-ddns.log"|g' "$conf"
        echo "  Updated log path in: $(basename $conf)"
    fi
done

# Ensure log directory exists with proper permissions
mkdir -p /var/log/kea
chown kea:kea /var/log/kea
chmod 750 /var/log/kea

#------------------------------------------------------------------------------
# Step 7: Fix configuration file permissions
#------------------------------------------------------------------------------
echo -e "${YELLOW}[7/7] Fixing configuration file permissions...${NC}"
chown -R root:kea /etc/kea
chmod 750 /etc/kea
chmod 640 /etc/kea/*.conf
echo "  Set ownership to root:kea, mode 640 for config files"

#------------------------------------------------------------------------------
# Start services
#------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}=== Starting Kea Services ===${NC}"

# Determine which services to start based on config files
SERVICES_TO_START=""

if [[ -f /etc/kea/kea-dhcp4.conf ]]; then
    SERVICES_TO_START="$SERVICES_TO_START kea-dhcp4"
fi

if [[ -f /etc/kea/kea-dhcp6.conf ]] && grep -q '"Dhcp6"' /etc/kea/kea-dhcp6.conf 2>/dev/null; then
    # Only start if DHCPv6 is actually configured (not just default file)
    if ! grep -q '"subnet6": \[\]' /etc/kea/kea-dhcp6.conf 2>/dev/null; then
        SERVICES_TO_START="$SERVICES_TO_START kea-dhcp6"
    fi
fi

if [[ -f /etc/kea/kea-ctrl-agent.conf ]]; then
    SERVICES_TO_START="$SERVICES_TO_START kea-ctrl-agent"
fi

if [[ -f /etc/kea/kea-dhcp-ddns.conf ]]; then
    SERVICES_TO_START="$SERVICES_TO_START kea-dhcp-ddns"
fi

for svc in $SERVICES_TO_START; do
    echo -n "  Starting $svc... "
    if systemctl enable --now "$svc" 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        echo "  Check: journalctl -u $svc -n 20"
    fi
done

#------------------------------------------------------------------------------
# Verify
#------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}=== Verification ===${NC}"
echo ""
echo "Service Status:"
for svc in $SERVICES_TO_START; do
    STATUS=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
    if [[ "$STATUS" == "active" ]]; then
        echo -e "  $svc: ${GREEN}$STATUS${NC}"
    else
        echo -e "  $svc: ${RED}$STATUS${NC}"
    fi
done

# Check HA status if available
if systemctl is-active kea-dhcp4 &>/dev/null && systemctl is-active kea-ctrl-agent &>/dev/null; then
    echo ""
    echo "HA Status:"
    HA_STATUS=$(curl -s http://localhost:8112/ -H "Content-Type: application/json" \
        -d '{"command": "ha-heartbeat", "service": ["dhcp4"]}' 2>/dev/null | \
        grep -oP '"state":\s*"\K[^"]+' || echo "N/A")
    echo "  DHCP4 HA State: $HA_STATUS"
fi

echo ""
echo -e "${GREEN}=== Done ===${NC}"
echo ""
echo "Backup location: $BACKUP_DIR"
echo ""
echo "If any service failed to start, check the logs:"
echo "  journalctl -u kea-dhcp4 -n 50"
echo "  journalctl -u kea-ctrl-agent -n 50"
echo ""
