#!/bin/bash
#===============================================================================
# Rocky Linux 9.x to 10.x Upgrade Script
# With Samba AD DC Support (RADS-compatible)
#
# Author: Generated based on successful upgrade of dc04.sloto.space
# Date: 2026-01-24
# Tested: Rocky Linux 9.7 -> 10.1
#
# REQUIREMENTS:
#   - Rocky Linux 9.x system
#   - x86-64-v3 CPU support (required for Rocky 10)
#   - Minimum 10GB free disk space
#   - System backup/snapshot recommended
#   - For Samba AD DC: RADS-based installation
#
# USAGE:
#   chmod +x rocky9-to-10-upgrade.sh
#   ./rocky9-to-10-upgrade.sh [--phase1|--phase2|--phase3]
#
# PHASES:
#   Phase 1: Pre-upgrade preparation and distro-sync
#   Phase 2: Post-upgrade fixes (run BEFORE reboot)
#   Phase 3: Samba DC rebuild (run AFTER reboot)
#
#===============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="/var/log/rocky-upgrade-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

#===============================================================================
# CONFIGURATION - Adjust these for your environment
#===============================================================================

# Network interface that will be renamed (enp* -> ens*)
OLD_INTERFACE="enp6s18"
NEW_INTERFACE="ens18"

# VLAN connection file pattern
VLAN_PATTERN="vlan0.*.nmconnection"

# Samba local repo path
SAMBA_REPO_PATH="/root/.samba"

# Rocky 10 release package URLs (check for latest version)
ROCKY10_REPO_URL="https://download.rockylinux.org/pub/rocky/10/BaseOS/x86_64/os/Packages/r"
ROCKY10_RELEASE_VER="10.1-1.4"

#===============================================================================
# PRE-FLIGHT CHECKS
#===============================================================================

preflight_checks() {
    log_info "Running pre-flight checks..."

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi

    # Check current OS version
    if ! grep -q "Rocky Linux" /etc/os-release; then
        log_error "This script is only for Rocky Linux"
        exit 1
    fi

    CURRENT_VERSION=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2 | cut -d'.' -f1)
    if [[ "$CURRENT_VERSION" != "9" ]]; then
        log_error "This script is for upgrading from Rocky Linux 9.x"
        log_error "Current version: $CURRENT_VERSION"
        exit 1
    fi

    # Check CPU support for x86-64-v3
    if ! /lib64/ld-linux-x86-64.so.2 --help 2>&1 | grep -q "x86-64-v3.*supported"; then
        log_error "CPU does not support x86-64-v3 (required for Rocky 10)"
        exit 1
    fi
    log_info "CPU x86-64-v3 support: OK"

    # Check disk space
    FREE_SPACE=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [[ "$FREE_SPACE" -lt 10 ]]; then
        log_error "Insufficient disk space. Need at least 10GB, have ${FREE_SPACE}GB"
        exit 1
    fi
    log_info "Disk space: ${FREE_SPACE}GB available"

    # Check for Samba AD DC
    if rpm -q samba-dc &>/dev/null || rpm -q samba-dc-libs &>/dev/null; then
        log_info "Samba AD DC detected - will include DC rebuild steps"
        SAMBA_DC=true
    else
        SAMBA_DC=false
    fi

    log_info "Pre-flight checks passed"
}

#===============================================================================
# PHASE 1: Upgrade to Rocky 10
#===============================================================================

phase1_upgrade() {
    log_info "=========================================="
    log_info "PHASE 1: Rocky Linux 9 -> 10 Upgrade"
    log_info "=========================================="

    # Update current system
    log_info "Updating current system..."
    dnf update -y

    # Clear version locks if any
    dnf versionlock clear 2>/dev/null || true

    # Download Rocky 10 release packages
    log_info "Downloading Rocky 10 release packages..."
    cd /tmp

    curl -LO "${ROCKY10_REPO_URL}/rocky-release-${ROCKY10_RELEASE_VER}.el10.noarch.rpm"
    curl -LO "${ROCKY10_REPO_URL}/rocky-repos-${ROCKY10_RELEASE_VER}.el10.noarch.rpm"
    curl -LO "${ROCKY10_REPO_URL}/rocky-gpg-keys-${ROCKY10_RELEASE_VER}.el10.noarch.rpm"

    # Install release packages (force to bypass conflicts)
    log_info "Installing Rocky 10 release packages..."
    rpm -Uvh --nodeps --force \
        rocky-gpg-keys-${ROCKY10_RELEASE_VER}.el10.noarch.rpm \
        rocky-release-${ROCKY10_RELEASE_VER}.el10.noarch.rpm \
        rocky-repos-${ROCKY10_RELEASE_VER}.el10.noarch.rpm

    # Handle repo file conflicts
    if [[ -f /etc/yum.repos.d/rocky.repo.rpmnew ]]; then
        mv /etc/yum.repos.d/rocky.repo.rpmnew /etc/yum.repos.d/rocky.repo
    fi

    # Remove old logos
    rm -rf /usr/share/redhat-logos 2>/dev/null || true

    # Main upgrade - distro-sync
    log_info "Starting distro-sync (this will take a while)..."
    dnf -y --releasever=10 --allowerasing --setopt=deltarpm=false distro-sync

    # Rebuild RPM database
    log_info "Rebuilding RPM database..."
    rpm --rebuilddb

    log_info "Phase 1 complete!"
    log_info "Now run: $0 --phase2"
}

#===============================================================================
# PHASE 2: Post-upgrade fixes (BEFORE reboot)
#===============================================================================

phase2_fixes() {
    log_info "=========================================="
    log_info "PHASE 2: Post-upgrade fixes (before reboot)"
    log_info "=========================================="

    # Fix VLAN interface names (enp* -> ens*)
    log_info "Fixing VLAN interface names..."
    VLAN_FILES=$(ls /etc/NetworkManager/system-connections/${VLAN_PATTERN} 2>/dev/null || true)

    if [[ -n "$VLAN_FILES" ]]; then
        # Backup
        BACKUP_DIR="/root/nm-backup-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp /etc/NetworkManager/system-connections/${VLAN_PATTERN} "$BACKUP_DIR/" 2>/dev/null || true
        log_info "Network config backed up to: $BACKUP_DIR"

        # Replace interface name
        sed -i "s/parent=${OLD_INTERFACE}/parent=${NEW_INTERFACE}/g" \
            /etc/NetworkManager/system-connections/${VLAN_PATTERN}

        MODIFIED=$(grep -l "parent=${NEW_INTERFACE}" /etc/NetworkManager/system-connections/${VLAN_PATTERN} 2>/dev/null | wc -l)
        log_info "Modified $MODIFIED VLAN connection files"

        # Reload NetworkManager
        nmcli connection reload
    else
        log_info "No VLAN configurations found to fix"
    fi

    # Remove old el9 kernel packages
    log_info "Removing old el9 kernels..."
    OLD_KERNELS=$(rpm -qa | grep kernel | grep el9 || true)
    if [[ -n "$OLD_KERNELS" ]]; then
        rpm -e $OLD_KERNELS 2>/dev/null || log_warn "Some kernel packages could not be removed"
    fi

    # Remove remaining el9 packages
    log_info "Checking for remaining el9 packages..."
    EL9_PKGS=$(rpm -qa | grep "\.el9\." | grep -v samba || true)

    if [[ -n "$EL9_PKGS" ]]; then
        log_info "Removing el9 packages..."
        # Install replacement for gpgmepp if needed
        dnf install gpgmepp -y 2>/dev/null || true
        rpm -e $(rpm -qa | grep "\.el9\.") --nodeps 2>/dev/null || log_warn "Some el9 packages could not be removed"
    fi

    log_info "Phase 2 complete!"
    log_info ""
    log_info "=========================================="
    log_info "REBOOT NOW: reboot"
    log_info "=========================================="
    log_info ""
    log_info "After reboot, run: $0 --phase3"
}

#===============================================================================
# PHASE 3: Samba DC rebuild (AFTER reboot)
#===============================================================================

phase3_samba() {
    log_info "=========================================="
    log_info "PHASE 3: Samba AD DC rebuild for Rocky 10"
    log_info "=========================================="

    # Verify we're on Rocky 10
    if ! grep -q 'VERSION_ID="10' /etc/os-release; then
        log_error "This phase must be run after upgrading to Rocky 10"
        exit 1
    fi

    # Check if Samba DC rebuild is needed
    SAMBA_VER=$(rpm -q samba --qf '%{VERSION}-%{RELEASE}' 2>/dev/null || echo "not installed")
    if echo "$SAMBA_VER" | grep -q "\.dc"; then
        log_info "Samba DC already has .dc suffix: $SAMBA_VER"
        log_info "Checking if rebuild is needed..."
    fi

    # Install required dependencies
    log_info "Installing build dependencies..."
    dnf install mock mock-core-configs -y
    dnf --enablerepo=epel install python3-setproctitle -y
    dnf install bind -y
    dnf --enablerepo=crb install lmdb -y

    # Create custom mock config with EPEL
    log_info "Creating mock configuration with EPEL..."
    cat > /etc/mock/rocky-10-x86_64-epel.cfg << 'MOCKEOF'
include('rocky-10-x86_64.cfg')

config_opts['dnf.conf'] += """
[epel]
name=Extra Packages for Enterprise Linux 10 - $basearch
metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-10&arch=$basearch&infra=$infra&content=$contentdir
enabled=1
gpgcheck=0
"""
MOCKEOF

    # Download Samba source
    log_info "Downloading Samba source RPM..."
    cd /tmp
    rm -f samba-*.src.rpm
    dnf download samba --source

    SAMBA_SRPM=$(ls samba-*.src.rpm 2>/dev/null | head -1)
    if [[ -z "$SAMBA_SRPM" ]]; then
        log_error "Failed to download Samba source RPM"
        exit 1
    fi

    # Get version info
    source /etc/os-release
    MAJOROS=$(echo $VERSION_ID | cut -d. -f1)
    MINOROS=$(echo $VERSION_ID | cut -d. -f2)

    log_info "Building Samba DC for Rocky ${MAJOROS}.${MINOROS}..."
    log_info "This will take 30-60 minutes..."

    # Build with mock
    mock -r rocky-10-x86_64-epel \
        --enablerepo=devel \
        --define "dist .el${MAJOROS}_${MINOROS}.dc" \
        --with dc \
        "$SAMBA_SRPM"

    if [[ $? -ne 0 ]]; then
        log_error "Mock build failed! Check /var/lib/mock/rocky-10-x86_64/result/build.log"
        exit 1
    fi

    # Copy RPMs to local repo
    log_info "Setting up local Samba repository..."
    rm -rf ${SAMBA_REPO_PATH}/*.rpm 2>/dev/null || true
    mkdir -p "$SAMBA_REPO_PATH"
    cp /var/lib/mock/rocky-10-x86_64/result/*.rpm "$SAMBA_REPO_PATH/"

    # Create repo
    createrepo "$SAMBA_REPO_PATH"

    # Clean dnf cache
    dnf clean all
    dnf makecache

    # Install Samba DC packages
    log_info "Installing Samba DC packages..."
    dnf install samba-dc samba-dc-provision samba-dc-bind-dlz --nogpgcheck -y

    # Start Samba service
    log_info "Starting Samba AD DC service..."
    systemctl start samba
    systemctl enable samba

    # Verify
    log_info "Verifying Samba AD DC..."
    sleep 5
    samba-tool domain info 127.0.0.1

    log_info ""
    log_info "=========================================="
    log_info "PHASE 3 COMPLETE!"
    log_info "=========================================="
    log_info ""
    log_info "Samba AD DC is now running on Rocky Linux 10"
    log_info "Verify with: samba-tool drs showrepl"
    log_info "            samba-tool dbcheck"
}

#===============================================================================
# Updated RADS script for Rocky 10
#===============================================================================

create_rads_update_script() {
    log_info "Creating updated RADS update script..."

    cat > /root/.servman/SambaManager/sm-samba-dnf-pkg-update-rl10 << 'RADSEOF'
#!/bin/bash
#===============================================================================
# Samba DC Package Update Script - Rocky Linux 10 Compatible
# Based on RADS (Rocky Active Directory Script)
#
# This script rebuilds Samba packages with AD DC support when upstream
# releases a new version.
#
# FIXED: Version parsing for Rocky Linux 10+ (was broken for 2-digit versions)
#===============================================================================

TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
USER=$(whoami)

# FIXED: Proper version parsing for Rocky 10+
source /etc/os-release
majoros=$(echo $VERSION_ID | cut -d. -f1)
minoros=$(echo $VERSION_ID | cut -d. -f2)

# Get package versions
dnflocal=$(dnf provides samba 2>/dev/null | grep Provide | sed 's/.dc//' | sed '1d')
dnfremote=$(dnf provides samba 2>/dev/null | grep Provide | sed 's/.dc//' | sed '$d')
mocksmbver=$(dnf provides samba 2>/dev/null | grep samba | sed '2,4d' | cut -d: -f1 | cut -dx -f1)

echo "Detected OS: Rocky Linux ${majoros}.${minoros}"

# Check for root
if [ "$USER" != "root" ]; then
    echo "${RED}This program must be run as root${TEXTRESET}"
    exit 1
fi

clear
cat <<EOF
${GREEN}Samba Server Management${TEXTRESET}
${GREEN}Samba Mock Update (Rocky 10 Compatible)${TEXTRESET}

This script will update your Samba binary packages to the latest version
as prescribed from the upstream Rocky Provider.

It's suggested that you schedule downtime for this as the sources will
need to rebuild. It's suggested that you ${YELLOW}REBOOT${TEXTRESET} after the update.

The current local version on the system is:
$dnflocal

And the Version in the upstream repository is:
$dnfremote

Mock target: rocky-${majoros}-x86_64
Dist tag: .el${majoros}_${minoros}.dc

EOF

echo "${YELLOW}The Last log entry for the Samba replication log is:${TEXTRESET}"
tail -1 /var/log/dnf-smb-mon.log 2>/dev/null || echo "(no log found)"
echo ""

cat <<EOF
This process will:
    -Remove local packages
    -Download the new samba source
    -Use mock to compile the source rpm
    -Recreate the repo in the same location
    -Run dnf update to the new version of Samba, with dependencies
EOF

while true; do
    read -p "Would you like to update the system now? (y/n) " yn
    case $yn in
        [yY])
            # Delete old packages
            rm -rf /root/.samba/*.rpm

            # Download source
            cd /tmp
            dnf download samba --source

            # Build with mock (Rocky 10 compatible)
            mock -r rocky-${majoros}-x86_64-epel \
                --enablerepo=devel \
                --define "dist .el${majoros}_${minoros}.dc" \
                --with dc \
                ${mocksmbver}src.rpm

            # Copy to local repo
            cp /var/lib/mock/rocky-${majoros}-x86_64-epel/result/*.rpm /root/.samba/
            createrepo /root/.samba

            # Update
            dnf update --nogpgcheck -y

            # Clear MOTD notification
            sed -i d /etc/motd 2>/dev/null || true

            echo "${GREEN}Update complete! Please reboot.${TEXTRESET}"
            break
            ;;
        [nN])
            echo "${RED}Upgrade Cancelled${TEXTRESET}"
            exit 0
            ;;
        *)
            echo "Invalid response"
            ;;
    esac
done
RADSEOF

    chmod +x /root/.servman/SambaManager/sm-samba-dnf-pkg-update-rl10
    log_info "Created: /root/.servman/SambaManager/sm-samba-dnf-pkg-update-rl10"
}

#===============================================================================
# MAIN
#===============================================================================

show_usage() {
    cat << EOF
Rocky Linux 9 to 10 Upgrade Script

Usage: $0 [OPTION]

Options:
  --phase1    Run Phase 1: Pre-upgrade and distro-sync
  --phase2    Run Phase 2: Post-upgrade fixes (before reboot)
  --phase3    Run Phase 3: Samba DC rebuild (after reboot)
  --check     Run pre-flight checks only
  --help      Show this help message

Workflow:
  1. Create VM snapshot or backup
  2. Run: $0 --phase1
  3. Run: $0 --phase2
  4. Reboot the system
  5. Run: $0 --phase3 (if using Samba AD DC)

EOF
}

case "$1" in
    --phase1)
        preflight_checks
        phase1_upgrade
        ;;
    --phase2)
        phase2_fixes
        create_rads_update_script
        ;;
    --phase3)
        phase3_samba
        ;;
    --check)
        preflight_checks
        log_info "All checks passed. Ready for upgrade."
        ;;
    --help|-h|"")
        show_usage
        ;;
    *)
        log_error "Unknown option: $1"
        show_usage
        exit 1
        ;;
esac
