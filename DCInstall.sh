#!/usr/bin/env bash
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
CYAN="\e[36m"
RESET="\e[0m"
USER=$(whoami)
MAJOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')


clear
echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rocky ${CYAN}RADS FOREST${TEXTRESET} Builder ${YELLOW}Installation${TEXTRESET}"

# Checking for user permissions
if [ "$USER" = "root" ]; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Running as root user"
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] This program must be run as root."
  echo "Exiting..."
  exit 1
fi

# Checking for version information
if [ "$MAJOROS" -ge 9 ]; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Detected compatible OS version: Rocky 9.x or greater"
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] Sorry, but this installer only works on Rocky 9.X or greater"
  echo -e "Please upgrade to ${GREEN}Rocky 9.x${TEXTRESET} or later"
  echo "Exiting the installer..."
  exit 1
fi
# ========= CHECK FOR PRE-EXISTING SMB AND SAMBA SERVICE =========
check_samba_running() {
  # Check if either smb or samba service is active
  if systemctl is-active --quiet smb || systemctl is-active --quiet samba; then
    dialog --backtitle "Samba Check" --title "Samba Service Running" --msgbox "Samba (or SMB) is currently running on this system. A fresh install of the OS is required to install Samba.\n\nPlease perform a clean installation." 10 60
    exit 1
  fi
}


# ========= REMOVE BRACKETED PASTING =========
sed -i '8i set enable-bracketed-paste off' /etc/inputrc


# ========= INSERT INSTALLER INTO .bash_profile =========
PROFILE="/root/.bash_profile"
BACKUP="/root/.bash_profile.bak.$(date +%Y%m%d%H%M%S)"
INSTALLER="/root/ADDCInstaller/DCInstall.sh"

cat << 'EOF' >> "$PROFILE"

## Run RADS installer on every interactive login ##
if [[ $- == *i* ]]; then
  /root/ADDCInstaller/DCInstall.sh
fi
EOF
if [[ -f "$INSTALLER" ]]; then
  chmod +x "$INSTALLER"
else
  echo "WARNING: Installer not found at $INSTALLER"
fi


# ========= VALIDATION HELPERS =========
validate_cidr() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; }
validate_ip()   { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
validate_fqdn() { [[ "$1" =~ ^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$ ]]; }

is_host_ip() {
  local cidr="$1"
  local ip_part="${cidr%/*}"
  local mask="${cidr#*/}"

  IFS='.' read -r o1 o2 o3 o4 <<< "$ip_part"
  ip_dec=$(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))

  netmask=$(( 0xFFFFFFFF << (32 - mask) & 0xFFFFFFFF ))
  network=$(( ip_dec & netmask ))
  broadcast=$(( network | ~netmask & 0xFFFFFFFF ))

  [[ "$ip_dec" -eq "$network" || "$ip_dec" -eq "$broadcast" ]] && return 1 || return 0
}

check_hostname_in_domain() {
  local fqdn="$1"
  local hostname="${fqdn%%.*}"
  local domain="${fqdn#*.}"
  [[ ! "$domain" =~ (^|\.)"$hostname"(\.|$) ]]
}
isValidIP() {
  [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r o1 o2 o3 o4 <<< "$1"
  (( o1 <= 255 && o2 <= 255 && o3 <= 255 && o4 <= 255 )) || return 1
  return 0
}

isValidNetmask() {
  local valid=(
    255.255.255.0 255.255.0.0 255.0.0.0
    255.255.254.0 255.255.252.0 255.255.248.0 255.255.240.0
    255.255.224.0 255.255.192.0 255.255.128.0
  )
  [[ " ${valid[*]} " =~ " $1 " ]]
}

isIPInRange() {
  local ip=$1
  local ipnum=$(ipToNumber "$ip")
  local netnum=$(ipToNumber "$NETWORK")
  local broadnum=$(ipToNumber "$BROADCAST")
  [[ $ipnum -ge $netnum && $ipnum -le $broadnum ]]
}

# ========= SYSTEM CHECKS =========
check_root_and_os() {
  if [[ "$EUID" -ne 0 ]]; then
    dialog --aspect 9 --title "Permission Denied" --msgbox "This script must be run as root." 7 50
    clear; exit 1
  fi

  if [[ -f /etc/redhat-release ]]; then
    MAJOROS=$(grep -oP '\d+' /etc/redhat-release | head -1)
  else
    dialog --title "OS Check Failed" --msgbox "/etc/redhat-release not found. Cannot detect OS." 7 50
    exit 1
  fi

  if [[ "$MAJOROS" -lt 9 ]]; then
    dialog --title "Unsupported OS" --msgbox "This installer requires Rocky Linux 9.x or later." 7 50
    exit 1
  fi
}

# ========= SELINUX CHECK =========
check_and_enable_selinux() {
  local current_status=$(getenforce)

  if [[ "$current_status" == "Enforcing" ]]; then
    dialog --backtitle "Checking and Enabling SELinux" --title "SELinux Status" --infobox "SELinux is already enabled and enforcing." 6 50
    sleep 4
  else
    dialog --backtitle "Checking and Enabling SELinux" --title "SELinux Disabled" --msgbox "SELinux is not enabled. Enabling SELinux now..." 6 50
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
    setenforce 1

    if [[ "$(getenforce)" == "Enforcing" ]]; then
      dialog --backtitle "Checking and Enabling SELinux" --title "SELinux Enabled" --msgbox "SELinux has been successfully enabled and is now enforcing." 6 50
    else
      dialog --backtitle "Checking and Enabling SELinux" --title "SELinux Error" --msgbox "Failed to enable SELinux. Please check the configuration manually." 6 50
      exit 1
    fi
  fi
}

# ========= NETWORK DETECTION =========
detect_active_interface() {
  dialog --backtitle "Network Setup" --title "Interface Check" --infobox "Checking active network interface..." 5 50
  sleep 3

  # Attempt 1: Use nmcli to find connected Ethernet
  INTERFACE=$(nmcli -t -f DEVICE,TYPE,STATE device | grep "ethernet:connected" | cut -d: -f1 | head -n1)

  # Attempt 2: Fallback to any interface with an IP if nmcli fails
  if [[ -z "$INTERFACE" ]]; then
    INTERFACE=$(ip -o -4 addr show up | grep -v ' lo ' | awk '{print $2}' | head -n1)
  fi

  # Get the matching connection profile name
  if [[ -n "$INTERFACE" ]]; then
    CONNECTION=$(nmcli -t -f NAME,DEVICE connection show | grep ":$INTERFACE" | cut -d: -f1)
  fi

  # Log to /tmp in case of failure
  echo "DEBUG: INTERFACE=$INTERFACE" >> /tmp/kvm_debug.log
  echo "DEBUG: CONNECTION=$CONNECTION" >> /tmp/kvm_debug.log

  if [[ -z "$INTERFACE" || -z "$CONNECTION" ]]; then
    dialog --clear  --no-ok --backtitle "Network Setup"  --title "Interface Error" --aspect 9 --msgbox "No active network interface with IP found. Check /tmp/kvm_debug.log for d
etails." 5 70
    exit 1
  fi

  export INTERFACE CONNECTION
}

# ========= STATIC IP CONFIG =========
prompt_static_ip_if_dhcp() {
  IP_METHOD=$(nmcli -g ipv4.method connection show "$CONNECTION" | tr -d '' | xargs)

  if [[ "$IP_METHOD" == "manual" ]]; then
  dialog --title "Static IP Detected" --infobox "Interface '$INTERFACE' is already using a static IP" 6 70
  sleep 3
  return
elif [[ "$IP_METHOD" == "auto" ]]; then
    while true; do
      while true; do
        IPADDR=$(dialog --backtitle "Interface Setup" --title "Static IP Address Required" --inputbox "***DHCP DETECTED on '$INTERFACE'***\n\nEnter static IP in CIDR format (e.g., 192.168.1.100/24):" 8 80 3>&1 1>&2 2>&3)
        validate_cidr "$IPADDR" && break || dialog --msgbox "Invalid CIDR format. Try again." 6 40
      done

      while true; do
        GW=$(dialog --backtitle "Interface Setup" --title "Gateway" --inputbox "Enter default gateway:" 8 60 3>&1 1>&2 2>&3)
        validate_ip "$GW" && break || dialog --msgbox "Invalid IP address. Try again." 6 40
      done

      while true; do
        DNSSERVER=$(dialog --backtitle "Interface Setup" --title "DNS Server" --inputbox "Enter Upstream DNS server IP:" 8 60 3>&1 1>&2 2>&3)
        validate_ip "$DNSSERVER" && break || dialog --msgbox "Invalid IP address. Try again." 6 40
      done

      while true; do
        HOSTNAME=$(dialog --backtitle "Interface Setup" --title "FQDN" --inputbox "Enter FQDN (e.g., host.domain.com):" 8 60 3>&1 1>&2 2>&3)
        if validate_fqdn "$HOSTNAME" && check_hostname_in_domain "$HOSTNAME"; then break
        else dialog --msgbox "Invalid FQDN or hostname repeated in domain. Try again." 7 60
        fi
      done

      while true; do
        DNSSEARCH=$(dialog --backtitle "Interface Setup" --title "DNS Search" --inputbox "Enter domain search suffix (e.g., localdomain):" 8 60 3>&1 1>&2 2>&3)
        [[ -n "$DNSSEARCH" ]] && break || dialog --msgbox "Search domain cannot be blank." 6 40
      done

      dialog --backtitle "Interface Setup" --title "Confirm Settings" --yesno "Apply these settings?\n\nInterface: $INTERFACE\nIP: $IPADDR\nGW: $GW\nFQDN: $HOSTNAME\nDNS: $DNSSERVER\nSearch: $DNSSEARCH" 12 60

      if [[ $? -eq 0 ]]; then
        nmcli con mod "$CONNECTION" ipv4.address "$IPADDR"
        nmcli con mod "$CONNECTION" ipv4.gateway "$GW"
        nmcli con mod "$CONNECTION" ipv4.method manual
        nmcli con mod "$CONNECTION" ipv4.dns "$DNSSERVER"
        nmcli con mod "$CONNECTION" ipv4.dns-search "$DNSSEARCH"
        hostnamectl set-hostname "$HOSTNAME"


        dialog --clear --no-shadow --no-ok --backtitle "REBOOT REQUIRED" --title "Reboot Required" --aspect 9 --msgbox "Network stack set. The System will reboot. Reconnect at: ${IPADDR%%/*}" 5 95
        reboot
      fi
    done
  fi
}

# ========= UI SCREENS =========
show_welcome_screen() {
  clear
  echo -e "${GREEN}
                               .*((((((((((((((((*
                         .(((((((((((((((((((((((((((/
                      ,((((((((((((((((((((((((((((((((((.
                    (((((((((((((((((((((((((((((((((((((((/
                  (((((((((((((((((((((((((((((((((((((((((((/
                .(((((((((((((((((((((((((((((((((((((((((((((
               ,((((((((((((((((((((((((((((((((((((((((((((((((.
               ((((((((((((((((((((((((((((((/   ,(((((((((((((((
              /((((((((((((((((((((((((((((.        /((((((((((((*
              ((((((((((((((((((((((((((/              ((((((((((
              ((((((((((((((((((((((((                   *((((((/
              /((((((((((((((((((((*                        (((((*
               ((((((((((((((((((             (((*            ,((
               .((((((((((((((.            /(((((((
                 ((((((((((/             (((((((((((((/
                  *((((((.            /((((((((((((((((((.
                    *(*)            ,(((((((((((((((((((((((,
                                 (((((((((((((((((((((((/
                              /((((((((((((((((((((((.
                                ,((((((((((((((,
${RESET}"
  echo -e "                         ${GREEN}Rocky Linux${RESET} ${CYAN}RADS FOREST${RESET} ${YELLOW}Builder${RESET}"

  sleep 2
}

# ========= INTERNET CONNECTIVITY CHECK =========
check_internet_connectivity() {
  dialog --backtitle "Checking Internet Connectivity" --title "Network Test" --infobox "Checking internet connectivity..." 5 50
  sleep 2

  local dns_test="FAILED"
  local ip_test="FAILED"

  if ping -c 1 -W 2 google.com &>/dev/null; then
    dns_test="SUCCESS"
  fi

  if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
    ip_test="SUCCESS"
  fi

  dialog --backtitle "Checking Internet Connectivity" --title "Connectivity Test Results" --infobox "DNS Resolution: $dns_test
Direct IP (8.8.8.8): $ip_test " 7 50
  sleep 4

  if [[ "$dns_test" == "FAILED" || "$ip_test" == "FAILED" ]]; then
    dialog --backtitle "Checking Internet Connectivity" --title "Network Warning" --yesno "Internet connectivity issues detected. Do you want to continue?" 7 50
    if [[ $? -ne 0 ]]; then
      exit 1
    fi
  fi
}

# ========= HOSTNAME VALIDATION =========
validate_and_set_hostname() {
  local current_hostname
  current_hostname=$(hostname)

  if [[ "$current_hostname" == "localhost.localdomain" ]]; then
    while true; do
      NEW_HOSTNAME=$(dialog --backtitle "Configure Hostname" --title "Hostname Configuration" --inputbox \
        "Current hostname is '$current_hostname'. Please enter a new FQDN (e.g., server.example.com):" \
        8 60 3>&1 1>&2 2>&3)

      if validate_fqdn "$NEW_HOSTNAME" && check_hostname_in_domain "$NEW_HOSTNAME"; then
        hostnamectl set-hostname "$NEW_HOSTNAME"
        dialog --backtitle "Configure Hostname" --title "Hostname Set" --msgbox "Hostname updated to: $NEW_HOSTNAME" 6 50
        break
      else
        dialog --backtitle "Configure Hostname" --title "Invalid Hostname" --msgbox "Invalid hostname. Please try again." 6 50
      fi
    done
  else
    # Show a temporary info box with current hostname, no OK button
    dialog --backtitle "Configure Hostname" --title "Hostname Check" --infobox \
      "Hostname set to: $current_hostname" 6 60
    sleep 3
  fi
}

# ========= SHOW CHECKLIST TO USER =========

show_ad_server_checklist() {
  dialog --backtitle "Welcome to the RADS Domain/Forest Installer" --title "First AD Server Installation Checklist" --msgbox "\
*********************************************

This will Install the FIRST AD Server and build a new Forest/Domain

Checklist:
Before the Installer starts, please make sure you have the following information:

  1. An Administrator password that you want to use for the new DOMAIN
  2. An NTP Subnet for your clients. This server will provide synchronized time
  3. The beginning and ending lease range for DHCP (optional)
  4. The client default gateway IP Address for the DHCP Scope (optional)
  5. A Friendly name as a description to the DHCP scope created (optional)

*********************************************" 20 100
}


# ========= ASK FOR DOMAIN PASSWORD CREATION =========
TMP_FILE=$(mktemp)

show_password_requirements() {
  dialog --backtitle "Domain Administrator Password Setup" --title "Administrator Password Requirements" --msgbox \
"Please create the DOMAIN password for the Administrator Account

Your password must meet the following criteria:

- At least 8 characters
- At least 1 special character (!@#\$%^&)
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 number" 15 90
}

validate_admin_password() {
  local password="$1"

  if [ ${#password} -lt 8 ]; then
    echo "Password is too short (minimum 8 characters)."
    return 1
  fi
  if ! [[ "$password" =~ [0-9] ]]; then
    echo "Password must include at least one number."
    return 1
  fi
  if ! [[ "$password" =~ [\!\@\#\$\%\^\&\*] ]]; then
    echo "Password must include at least one special character (!@#\$%^&*)."
    return 1
  fi
  if ! [[ "$password" =~ [A-Z] && "$password" =~ [a-z] ]]; then
    echo "Password must contain both uppercase and lowercase letters."
    return 1
  fi

  return 0
}

prompt_admin_password() {
  show_password_requirements

  while true; do
    dialog --backtitle "Domain Administrator Password Setup" --insecure --passwordbox "Enter Administrator Password:" 10 60 2> "$TMP_FILE"
    ADMINPASS=$(<"$TMP_FILE")

    if [ -z "$ADMINPASS" ]; then
      dialog --backtitle "Domain Administrator Password Setup" --msgbox "Password cannot be blank. Please try again." 6 50
      continue
    fi

    error=$(validate_admin_password "$ADMINPASS" 2>&1)
    if ! validate_admin_password "$ADMINPASS"; then
      dialog --backtitle "Domain Administrator Password Setup" --msgbox "$error" 8 60
      continue
    fi

    dialog --backtitle "Domain Administrator Password Setup" --insecure --passwordbox "Confirm Administrator Password:" 10 60 2> "$TMP_FILE"
    VERIFYPASS=$(<"$TMP_FILE")

    if [ -z "$VERIFYPASS" ]; then
      dialog --backtitle "Domain Administrator Password Setup" --msgbox "Confirmation cannot be blank. Please try again." 6 50
      continue
    fi

    if [ "$ADMINPASS" = "$VERIFYPASS" ]; then
      dialog --backtitle "Domain Administrator Password Setup" --infobox "Password accepted and saved." 5 40
      sleep 2
      break
    else
      dialog --backtitle "Domain Administrator Password Setup" --msgbox "Passwords do not match. Please try again." 6 50
    fi
  done

  export ADMINPASS
  rm -f "$TMP_FILE"
}

# ========= CONFIGURE CHRONY =========
declare -a ADDR
LOG_NTP="/tmp/chrony_ntp_configure.log"
touch "$LOG_NTP"

log_ntp() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$LOG_NTP"
}

validate_cidr() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]
}

prompt_ntp_servers() {
    while true; do
        NTP_SERVERS=$(dialog --title "Chrony NTP Configuration" \
            --backtitle "Configure NTP" --inputbox "Enter up to 3 comma-separated NTP server IPs or FQDNs:" 8 60 \
            3>&1 1>&2 2>&3)
        exit_status=$?
        if [ $exit_status -eq 1 ] || [ $exit_status -eq 255 ]; then
            return 1
        fi

        if [[ -n "$NTP_SERVERS" ]]; then
            IFS=',' read -ra ADDR <<< "$NTP_SERVERS"
            if (( ${#ADDR[@]} > 3 )); then
                dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --msgbox "You may only enter up to 3 servers." 6 50
                continue
            fi
            return 0
        else
            dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --msgbox "The input cannot be blank. Please try again." 6 50
        fi
    done
}

prompt_allow_networks() {
    while true; do
        ALLOW_NET=$(dialog --title "Allow NTP Access" \
            --backtitle "Configure NTP" --inputbox "Enter the CIDR range to allow NTP access (e.g., 192.168.1.0/24):" 8 80 \
            3>&1 1>&2 2>&3)
        exit_status=$?
        if [ $exit_status -ne 0 ]; then
            return 1
        fi

        if validate_cidr "$ALLOW_NET"; then
            return 0
        else
            dialog --backtitle "Configure NTP" --msgbox "Invalid CIDR format. Please try again." 6 40
        fi
    done
}

update_chrony_config() {
    cp /etc/chrony.conf /etc/chrony.conf.bak
    sed -i '/^\(server\|pool\|allow\)[[:space:]]/d' /etc/chrony.conf

    for srv in "${ADDR[@]}"; do
        echo "server ${srv} iburst" >> /etc/chrony.conf
        log_ntp "Added server ${srv} to chrony.conf"
    done

    if [[ -n "$ALLOW_NET" ]]; then
        echo "allow $ALLOW_NET" >> /etc/chrony.conf
        log_ntp "Added allow $ALLOW_NET to chrony.conf"
    fi

    systemctl restart chronyd
    sleep 2
}

validate_time_sync() {
    local attempt=1
    local success=0

    while (( attempt <= 3 )); do
        dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "Validating time sync... Attempt $attempt/3" 4 50
        sleep 5

        TRACKING=$(chronyc tracking 2>&1)
        echo "$TRACKING" >> "$LOG_NTP"

        if echo "$TRACKING" | grep -q "Leap status[[:space:]]*:[[:space:]]*Normal"; then
            success=1
            break
        fi
        ((attempt++))
    done

    if [[ "$success" -eq 1 ]]; then
        dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "Time synchronized successfully:\n\n$TRACKING" 15 100
        sleep 3
    else
        dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --yesno "Time sync failed after 3 attempts.\nDo you want to proceed anyway?" 8 100
        [[ $? -eq 0 ]] || return 1
    fi
    return 0
}

# ========= SYSTEM UPDATE & PACKAGE INSTALL =========
update_and_install_packages() {
  # Simulate progress while enabling EPEL and CRB
  dialog --backtitle "Base Package Update" --title "Repository Setup" --gauge "Enabling EPEL and CRB repositories..." 10 60 0 < <(
    (
      (
        dnf install -y epel-release >/dev/null 2>&1
        dnf config-manager --set-enabled crb >/dev/null 2>&1
      ) &
      PID=$!
      PROGRESS=0
      while kill -0 "$PID" 2>/dev/null; do
        echo "$PROGRESS"
        echo "XXX"
        echo "Enabling EPEL and CRB..."
        echo "XXX"
        ((PROGRESS += 5))
        if [[ $PROGRESS -ge 95 ]]; then
          PROGRESS=5
        fi
        sleep 0.5
      done
      echo "100"
      echo "XXX"
      echo "Repositories enabled."
      echo "XXX"
    )
  )

  dialog --backtitle "Base Package Update" --title "System Update" --infobox "Checking for updates. This may take a few moments..." 5 70
  sleep 2

  dnf check-update -y &>/dev/null

  TEMP_FILE=$(mktemp)
  dnf check-update | awk '{print $1}' | grep -vE '^$|Obsoleting|Last' | awk -F'.' '{print $1}' | sort -u > "$TEMP_FILE"

  PACKAGE_LIST=($(cat "$TEMP_FILE"))
  TOTAL_PACKAGES=${#PACKAGE_LIST[@]}

  if [[ "$TOTAL_PACKAGES" -eq 0 ]]; then
    dialog --backtitle "Base Package Update" --title "System Update" --msgbox "No updates available!" 6 50
    rm -f "$TEMP_FILE"
  else
    PIPE=$(mktemp -u)
    mkfifo "$PIPE"
    dialog --backtitle "Base Package Update" --title "System Update" --gauge "Installing updates..." 10 70 0 < "$PIPE" &
    exec 3>"$PIPE"
    COUNT=0
    for PACKAGE in "${PACKAGE_LIST[@]}"; do
      ((COUNT++))
      PERCENT=$(( (COUNT * 100) / TOTAL_PACKAGES ))
      echo "$PERCENT" > "$PIPE"
      echo "XXX" > "$PIPE"
      echo "Updating: $PACKAGE" > "$PIPE"
      echo "XXX" > "$PIPE"
      dnf -y install "$PACKAGE" >/dev/null 2>&1
    done
    exec 3>&-
    rm -f "$PIPE" "$TEMP_FILE"
  fi

  dialog --backtitle "Required Package Install" --title "Package Installation" --infobox "Installing Required Packages..." 5 50
  sleep 2
  PACKAGE_LIST=("ntsysv" "iptraf" "expect" "nano" "rsync" "sshpass" "openldap-clients" "fail2ban" "tuned" "createrepo" "cockpit" "cockpit-storaged" "mock" "cockpit-files" "net-tools" "dmidecode" "ipcalc" "bind-utils"  "iotop" "zip" "yum-utils" "nano" "curl" "wget" "git" "dnf-automatic" "dnf-plugins-core" "util-linux" "htop" "iptraf-ng" "mc")
  TOTAL_PACKAGES=${#PACKAGE_LIST[@]}

  PIPE=$(mktemp -u)
  mkfifo "$PIPE"
  dialog --backtitle "Required Package Install" --title "Installing Required Packages" --gauge "Preparing to install packages..." 10 70 0 < "$PIPE" &
  exec 3>"$PIPE"
  COUNT=0
  for PACKAGE in "${PACKAGE_LIST[@]}"; do
    ((COUNT++))
    PERCENT=$(( (COUNT * 100) / TOTAL_PACKAGES ))
    echo "$PERCENT" > "$PIPE"
    echo "XXX" > "$PIPE"
    echo "Installing: $PACKAGE" > "$PIPE"
    echo "XXX" > "$PIPE"
    dnf -y install "$PACKAGE" >/dev/null 2>&1
  done
  exec 3>&-
  rm -f "$PIPE"
  dialog --backtitle "Required Package Install" --title "Installation Complete" --infobox "All packages installed successfully!" 6 50
  sleep 3
}
#===========DETECT VIRT and INSTALL GUEST=============
# Function to show a dialog infobox
vm_detection() {
show_info() {
    dialog --backtitle "Guest VM Detection and Installation" --title "$1" --infobox "$2" 5 60
    sleep 2
}

# Function to show a progress bar during installation
show_progress() {
    (
        echo "10"; sleep 1
        echo "40"; sleep 1
        echo "70"; sleep 1
        echo "100"
    ) | dialog --backtitle "Guest VM Detection and Installation" --title "$1" --gauge "$2" 7 60 0
}

# Detect virtualization platform
HWKVM=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep KVM | cut -c16-)
HWVMWARE=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep Manufacturer | grep "VMware, Inc." | cut -c16- | cut -d , -f1)

show_info "Virtualization Check" "Checking for virtualization platform..."

# Install guest agent for KVM
if [ "$HWKVM" = "KVM" ]; then
    show_info "Platform Detected" "KVM platform detected.\nInstalling qemu-guest-agent..."
    show_progress "Installing qemu-guest-agent" "Installing guest tools for KVM..."
    dnf -y install qemu-guest-agent &>/dev/null
fi

# Install guest agent for VMware
if [ "$HWVMWARE" = "VMware" ]; then
    show_info "Platform Detected" "VMware platform detected.\nInstalling open-vm-tools..."
    show_progress "Installing open-vm-tools" "Installing guest tools for VMware..."
    dnf -y install open-vm-tools &>/dev/null
fi
}
#===========OPTIONAL DHCP INSTALL=============
configure_dhcp_server() {
  local DIALOG="${DIALOG_BIN:-dialog}"
  local BACKTITLE="DHCP Server Install"
  local CHOSEN_BACKEND=""

  # ────────────────────────────── UI helpers ──────────────────────────────
  msgbox() { $DIALOG --backtitle "$BACKTITLE" --title "$1" --msgbox "$2" "${3:-8}" "${4:-72}"; }
  infobox(){ $DIALOG --backtitle "$BACKTITLE" --title "$1" --infobox "$2" "${3:-6}" "${4:-60}"; }

  # Require root + Rocky 9+
  require_root(){ [[ $EUID -eq 0 ]] || { echo "Run as root." >&2; return 1; }; }
  require_rocky9plus(){
    . /etc/os-release 2>/dev/null || true
    if [[ "${ID:-}" != "rocky" ]]; then
      msgbox "Unsupported OS" "This installer is limited to Rocky Linux 9+."; return 1
    fi
    local maj="${VERSION_ID%%.*}"
    if [[ -z "$maj" || "$maj" -lt 9 ]]; then
      msgbox "Unsupported Version" "Detected Rocky Linux ${VERSION_ID:-unknown}. This script supports Rocky Linux 9+ only."
      return 1
    fi
    return 0
  }

  # ─────────────────────── detection of installed backends ─────────────────────
  detect_isc_dhcp(){ [[ -f /etc/dhcp/dhcpd.conf ]] || rpm -q dhcp-server >/dev/null 2>&1; }
  detect_kea()     { [[ -f /etc/kea/kea-dhcp4.conf ]] || rpm -q kea >/dev/null 2>&1; }

  # ───────────────────────── repo enable (Rocky 9+) ───────────────────────────
  enable_repos_with_gauge() {
    # Rocky 9+: enable EPEL + CRB, then refresh metadata
    local log="/tmp/repo-setup.$(date +%s).log"
    local status="/tmp/repo-setup-status.$$"
    local msg="/tmp/repo-setup-phase.$$"
    : >"$log"; : >"$msg"
    trap 'rm -f "$status" "$msg"' RETURN

    (
      rc=0
      {
        echo "Installing dnf-plugins-core..." >"$msg"
        dnf -y install dnf-plugins-core >>"$log" 2>&1 || rc=1

        echo "Installing epel-release..." >"$msg"
        dnf -y install epel-release >>"$log" 2>&1 || rc=1

        echo "Enabling CRB repository..." >"$msg"
        dnf config-manager --set-enabled crb >>"$log" 2>&1 || rc=1

        echo "Refreshing repository metadata (makecache --refresh)..." >"$msg"
        dnf -y makecache --refresh >>"$log" 2>&1 || rc=1
      } || rc=1
      echo "$rc" >"$status"
    ) &

    local pid=$!
    (
      local PROGRESS=0
      while kill -0 "$pid" 2>/dev/null; do
        (( PROGRESS < 95 )) && PROGRESS=$(( PROGRESS + 5 ))
        echo "$PROGRESS"
        echo "XXX"
        echo -e "Enabling EPEL and CRB...\n$(cat "$msg" 2>/dev/null || echo "Working...")\n\nLog: $log"
        echo "XXX"
        sleep 0.5
      done
      echo "100"
      echo "XXX"
      echo -e "Repositories enabled and metadata refreshed.\n\nLog: $log"
      echo "XXX"
    ) | $DIALOG --backtitle "$BACKTITLE" --title "Repository Setup" --gauge "Preparing..." 10 70 0

    local rc=1
    [[ -f "$status" ]] && rc="$(cat "$status" 2>/dev/null || echo 1)"
    if [[ "$rc" -ne 0 ]]; then
      msgbox "Repository Setup Failed" "There was a problem enabling repositories.\n\nYou'll see the log next." 9 70
      $DIALOG --backtitle "$BACKTITLE" --title "Repo Setup Log" --textbox "$log" 22 100
      return 1
    fi
    return 0
  }

  # ────────────────────────── generic gauge runner ────────────────────────────
  run_gauge_cmd() {
    local title="$1"; shift
    local log="/tmp/$(basename "$1")-install.$(date +%s).log"
    local status="/tmp/$(basename "$1")-status.$$"
    : > "$log"
    ( "$@" &> "$log"; echo $? > "$status" ) & local pid=$!
    set +e
    (
      local pct=0
      while kill -0 "$pid" 2>/dev/null; do
        echo "$pct"
        echo "XXX"
        echo -e "Installing... Please wait.\nLog: $log"
        echo "XXX"
        sleep 0.3
        pct=$(( (pct + 2) % 97 ))
      done
      echo 100; echo "XXX"; echo "Finishing up..."; echo "XXX"
    ) | $DIALOG --backtitle "$BACKTITLE" --title "$title" --gauge "Preparing..." 10 70 0
    set -e

    local rc=1
    [[ -f "$status" ]] && { rc="$(cat "$status" 2>/dev/null || echo 1)"; rm -f "$status"; }
    if [[ "$rc" -ne 0 ]]; then
      msgbox "Error" "$title failed.\n\nSee the next screen for details.\n\nLog: $log" 10 72
      $DIALOG --backtitle "$BACKTITLE" --title "Install log: $title" --textbox "$log" 22 100
      return "$rc"
    else
      infobox "Success" "$title completed.\n\nLog: $log" 8 70
      sleep 1
    fi
  }

  # ───────────────────────────── dnf installers ────────────────────────────────
  install_isc_dhcp() {
    enable_repos_with_gauge || return 1
    run_gauge_cmd "Installing ISC DHCP (dhcp-server)" dnf -y install dhcp-server
  }
  install_kea() {
    enable_repos_with_gauge || return 1
    run_gauge_cmd "Installing Kea DHCP (kea)" dnf -y install kea
  }

  # ───────────────────── shared IP/CIDR + domain helpers ──────────────────────
  is_valid_ip(){
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS=.; local o; for o in $1; do [[ $o -ge 0 && $o -le 255 ]] || return 1; done
  }
  ip_to_int(){ local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }
  int_to_ip(){ local i=$1; printf "%d.%d.%d.%d" $(( (i>>24)&255 )) $(( (i>>16)&255 )) $(( (i>>8)&255 )) $(( i&255 )); }
  cidr_to_netmask(){ local c=$1; local m=$(( 0xFFFFFFFF << (32-c) & 0xFFFFFFFF )); int_to_ip "$m"; }
  netmask_to_cidr(){
    local ip=$1; is_valid_ip "$ip" || { echo -1; return; }
    local n=$(ip_to_int "$ip") c=0 saw_zero=0
    for ((i=31;i>=0;i--)); do
      if (( (n>>i)&1 )); then (( saw_zero )) && { echo -1; return; }; ((c++))
      else saw_zero=1
      fi
    done
    echo "$c"
  }
  network_from_ip_cidr(){ local ip=$1 c=$2; local m=$(( 0xFFFFFFFF << (32-c) & 0xFFFFFFFF )); int_to_ip $(( $(ip_to_int "$ip") & m )); }
  broadcast_from_ip_cidr(){ local ip=$1 c=$2; local m=$(( 0xFFFFFFFF << (32-c) & 0xFFFFFFFF )); int_to_ip $(( $(ip_to_int "$ip") | (~m & 0xFFFFFFFF) )); }
  ip_in_cidr(){
    local ip=$1 net=$2 c=$3
    local m=$(( 0xFFFFFFFF << (32-c) & 0xFFFFFFFF ))
    (( ( $(ip_to_int "$ip") & m ) == ( $(ip_to_int "$net") & m ) ))
  }
  is_valid_domain(){
    local d="$1"
    [[ -n "$d" ]] || return 1
    [[ "$d" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]
  }

  # ───────────────────────────── dhcpd setup flow ─────────────────────────────
  dhcpd_setup() {
    local iface inet4_line INET4 DHCPCIDR NET_DETECTED NETMASK_DETECTED
    iface=$(nmcli -t -f DEVICE,STATE device status | awk -F: '$2=="connected"{print $1; exit}')
    [[ -z "$iface" ]] && { msgbox "DHCPD Setup" "No active interface found."; return 1; }
    inet4_line=$(nmcli -g IP4.ADDRESS device show "$iface" | head -n 1)
    [[ -z "$inet4_line" ]] && { msgbox "DHCPD Setup" "No IPv4 address found on $iface."; return 1; }

    INET4=${inet4_line%/*}
    DHCPCIDR=${inet4_line#*/}
    NET_DETECTED=$(network_from_ip_cidr "$INET4" "$DHCPCIDR")
    NETMASK_DETECTED=$(cidr_to_netmask "$DHCPCIDR")

    local DHCPBEGIP DHCPENDIP DHCPNETMASK DHCPDEFGW SUBNETDESC DOM_SUFFIX SEARCH_DOMAIN
    local DEF_SUFFIX="$(hostname -d 2>/dev/null || true)"
    local DEF_SEARCH="${DEF_SUFFIX}"

    while true; do
      # Range start
      while true; do
        DHCPBEGIP=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter beginning IP of DHCP lease range (in $NET_DETECTED/$DHCPCIDR):" 8 78)
        [[ -n "$DHCPBEGIP" ]] && is_valid_ip "$DHCPBEGIP" && ip_in_cidr "$DHCPBEGIP" "$NET_DETECTED" "$DHCPCIDR" && break
        msgbox "Invalid Input" "Start IP must be a valid IPv4 within $NET_DETECTED/$DHCPCIDR."
      done
      # Range end
      while true; do
        DHCPENDIP=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter ending IP of DHCP lease range (in $NET_DETECTED/$DHCPCIDR):" 8 78)
        [[ -n "$DHCPENDIP" ]] && is_valid_ip "$DHCPENDIP" && ip_in_cidr "$DHCPENDIP" "$NET_DETECTED" "$DHCPCIDR" && \
          (( $(ip_to_int "$DHCPBEGIP") <= $(ip_to_int "$DHCPENDIP") )) && break
        msgbox "Invalid Input" "End IP must be valid, in $NET_DETECTED/$DHCPCIDR, and ≥ start IP."
      done
      # Netmask (must match detected)
      while true; do
        DHCPNETMASK=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter netmask for clients (must match detected $NETMASK_DETECTED):" 8 78 "$NETMASK_DETECTED")
        local nm_cidr; nm_cidr=$(netmask_to_cidr "$DHCPNETMASK")
        [[ "$nm_cidr" -eq "$DHCPCIDR" ]] && break
        msgbox "Invalid Netmask" "Netmask must be contiguous and equal to $NETMASK_DETECTED."
      done
      # Default gateway
      while true; do
        DHCPDEFGW=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter default gateway for clients (in $NET_DETECTED/$DHCPCIDR):" 8 78)
        [[ -n "$DHCPDEFGW" ]] && is_valid_ip "$DHCPDEFGW" && ip_in_cidr "$DHCPDEFGW" "$NET_DETECTED" "$DHCPCIDR" && break
        msgbox "Invalid Gateway" "Gateway must be a valid IPv4 within $NET_DETECTED/$DHCPCIDR."
      done
      # Domain suffix (option 15)
      while true; do
        DOM_SUFFIX=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter domain suffix (for 'option domain-name'):" 8 78 "${DEF_SUFFIX}")
        is_valid_domain "$DOM_SUFFIX" && break
        msgbox "Invalid Domain" "Please enter a valid domain suffix like 'ad.example.com'."
      done
      # Search domain(s) (option 119)
      while true; do
        SEARCH_DOMAIN=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter search domain(s) for clients (comma-separated if multiple):" 9 78 "${DEF_SEARCH}")
        local ok=1 IFS=, item
        for item in $SEARCH_DOMAIN; do
          item="${item// /}" ; is_valid_domain "$item" || { ok=0; break; }
        done
        [[ $ok -eq 1 ]] && break
        msgbox "Invalid Search Domain" "One or more domains are invalid. Use comma-separated FQDNs."
      done

      SUBNETDESC=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
        "Enter a friendly name/description for this subnet:" 8 78)

      $DIALOG --backtitle "$BACKTITLE" --title "DHCP Configuration Summary" --yesno \
"Interface:     $iface
Interface IP:  $INET4/$DHCPCIDR
Subnet:        $NET_DETECTED
Netmask:       $DHCPNETMASK
Range:         $DHCPBEGIP  →  $DHCPENDIP
Gateway:       $DHCPDEFGW
Domain:        $DOM_SUFFIX
Search:        $SEARCH_DOMAIN
Description:   $SUBNETDESC

Are these settings correct?" 18 72 && break
    done

    infobox "DHCPD Setup" "Creating /etc/dhcp/dhcpd.conf..."
    mkdir -p /etc/dhcp
    mv /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.orig 2>/dev/null || true
    cat <<EOF >/etc/dhcp/dhcpd.conf
authoritative;
allow unknown-clients;
default-lease-time 600;
max-lease-time 7200;

option ntp-servers ${INET4};
option time-servers ${INET4};
option domain-name-servers ${INET4};
option domain-name "${DOM_SUFFIX}";
option domain-search "${SEARCH_DOMAIN}";

# ${SUBNETDESC}
subnet ${NET_DETECTED} netmask ${DHCPNETMASK} {
  range ${DHCPBEGIP} ${DHCPENDIP};
  option subnet-mask ${DHCPNETMASK};
  option routers ${DHCPDEFGW};
}
EOF
  }

  # ───────────────────────────── Kea setup flow ───────────────────────────────
  kea_dhcp_setup() {
    local KEA_CONF="/etc/kea/kea-dhcp4.conf"
    mkdir -p /etc/kea; touch "$KEA_CONF"

    local iface inet4_line INET4 CIDR NETMASK NETWORK BROADCAST
    iface=$(nmcli -t -f DEVICE,STATE device status | awk -F: '$2=="connected"{print $1; exit}')
    [[ -z "$iface" ]] && { msgbox "KEA DHCP Setup" "No active interface found."; return 1; }
    inet4_line=$(nmcli -g IP4.ADDRESS device show "$iface" | head -n 1)
    [[ -z "$inet4_line" ]] && { msgbox "KEA DHCP Setup" "No IPv4 address found on $iface."; return 1; }

    INET4=${inet4_line%/*}
    CIDR=${inet4_line#*/}
    NETWORK=$(network_from_ip_cidr "$INET4" "$CIDR")
    NETMASK=$(cidr_to_netmask "$CIDR")
    BROADCAST=$(broadcast_from_ip_cidr "$INET4" "$CIDR")

    local POOL_START POOL_END ROUTER DOM_SUFFIX SEARCH_DOMAIN DNS_SERVERS SUBNET_DESC
    local DEF_SUFFIX="$(hostname -d 2>/dev/null || true)"
    local DEF_SEARCH="${DEF_SUFFIX}"

    while true; do
      # pool start
      while true; do
        POOL_START=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter beginning IP of DHCP lease range (in $NETWORK/$CIDR):" 8 78)
        [[ -n "$POOL_START" ]] && is_valid_ip "$POOL_START" && ip_in_cidr "$POOL_START" "$NETWORK" "$CIDR" && break
        msgbox "Invalid Input" "Start IP must be a valid IPv4 within $NETWORK/$CIDR."
      done
      # pool end
      while true; do
        POOL_END=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter ending IP of DHCP lease range:" 8 78)
        [[ -n "$POOL_END" ]] && is_valid_ip "$POOL_END" && ip_in_cidr "$POOL_END" "$NETWORK" "$CIDR" && \
          (( $(ip_to_int "$POOL_START") <= $(ip_to_int "$POOL_END") )) && break
        msgbox "Invalid Input" "End IP must be valid, in $NETWORK/$CIDR, and ≥ start IP."
      done
      # gateway
      while true; do
        ROUTER=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter default gateway for clients (in $NETWORK/$CIDR):" 8 78)
        [[ -n "$ROUTER" ]] && is_valid_ip "$ROUTER" && ip_in_cidr "$ROUTER" "$NETWORK" "$CIDR" && break
        msgbox "Invalid Gateway" "Gateway must be a valid IPv4 within $NETWORK/$CIDR."
      done
      # domains
      while true; do
        DOM_SUFFIX=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter domain suffix (for 'domain-name'):" 8 78 "${DEF_SUFFIX}")
        is_valid_domain "$DOM_SUFFIX" && break
        msgbox "Invalid Domain" "Please enter a valid domain suffix like 'ad.example.com'."
      done
      while true; do
        SEARCH_DOMAIN=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter search domain(s) for clients (comma-separated if multiple):" 9 78 "${DEF_SEARCH}")
        local ok=1 IFS=, item
        for item in $SEARCH_DOMAIN; do
          item="${item// /}" ; is_valid_domain "$item" || { ok=0; break; }
        done
        [[ $ok -eq 1 ]] && break
        msgbox "Invalid Search Domain" "One or more domains are invalid. Use comma-separated FQDNs."
      done
      DNS_SERVERS=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
        "Enter DNS servers (comma separated, or leave blank to use $INET4):" 8 78 "$INET4")
      SUBNET_DESC=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
        "Enter a friendly name/description for this subnet:" 8 78)

      $DIALOG --backtitle "$BACKTITLE" --title "KEA DHCP Settings Review" --yesno \
"Interface:     $iface
Interface IP:  $INET4/$CIDR
Subnet:        $NETWORK/$CIDR
Broadcast:     $BROADCAST
Range:         $POOL_START  →  $POOL_END
Gateway:       $ROUTER
DNS:           $DNS_SERVERS
Domain:        $DOM_SUFFIX
Search:        $SEARCH_DOMAIN
Description:   $SUBNET_DESC

Are these settings correct?" 20 72 && break
    done

    infobox "KEA DHCP Setup" "Creating /etc/kea/kea-dhcp4.conf..."
    cat <<EOF > "$KEA_CONF"
{
  "Dhcp4": {
    "interfaces-config": {
      "interfaces": [ "$iface" ]
    },
    "lease-database": {
      "type": "memfile",
      "persist": true,
      "name": "/var/lib/kea/kea-leases4.csv"
    },
    "subnet4": [
      {
        "id": 1,
        "subnet": "$NETWORK/$CIDR",
        "interface": "$iface",
        "comment": "$SUBNET_DESC",
        "pools": [ { "pool": "$POOL_START - $POOL_END" } ],
        "option-data": [
          { "name": "routers",               "data": "$ROUTER" },
          { "name": "domain-name-servers",   "data": "$DNS_SERVERS" },
          { "name": "ntp-servers",           "data": "$DNS_SERVERS" },
          { "name": "domain-name",           "data": "$DOM_SUFFIX" },
          { "name": "domain-search",         "data": "$SEARCH_DOMAIN" }
        ]
      }
    ],
    "authoritative": true
  }
}
EOF
    chown root:kea "$KEA_CONF"
    chmod 640 "$KEA_CONF"
    restorecon "$KEA_CONF" 2>/dev/null || true
  }

  # ────────────────────────────── preflight checks ─────────────────────────────
  require_root || return 1
  require_rocky9plus || return 1
  command -v "$DIALOG" >/dev/null 2>&1 || { echo "dialog not found. dnf -y install dialog" >&2; return 1; }
  command -v nmcli   >/dev/null 2>&1 || { echo "nmcli not found. dnf -y install NetworkManager" >&2; return 1; }

  # ────────────────────────────── user selection ───────────────────────────────
  $DIALOG --backtitle "$BACKTITLE" --title "DHCP Installation" --yesno \
"Would you like to install a DHCP service on this system?

You will be able to choose between ISC DHCP or Kea DHCP in the next step." 9 80 || { clear; return 0; }

  local isc_installed="not installed" kea_installed="not installed"
  detect_isc_dhcp && isc_installed="installed"
  detect_kea && kea_installed="installed"

  local default="kea"
  detect_kea && default="kea"
  { detect_isc_dhcp && ! detect_kea; } && default="isc"

  local kea_desc="Install/upgrade Kea DHCP (recommended)"
  [[ $kea_installed == "installed" ]] && kea_desc+=" [installed]"
  local isc_desc="Install/upgrade ISC DHCP (dhcp-server)"
  [[ $isc_installed == "installed" ]] && isc_desc+=" [installed]"

  local KEA_ON="OFF" ISC_ON="OFF"
  [[ $default == "kea" ]] && KEA_ON="ON" || ISC_ON="ON"

  local choice
  choice=$($DIALOG --backtitle "$BACKTITLE" --stdout --title "DHCP Installer" --radiolist \
"Select which DHCP server to install or upgrade.

Detected:
- ISC DHCP: $isc_installed
- Kea DHCP: $kea_installed" \
    14 76 2 \
    kea "$kea_desc" $KEA_ON \
    isc "$isc_desc" $ISC_ON)

  case "${choice:-}" in
    kea) install_kea && CHOSEN_BACKEND="kea" ;;
    isc) install_isc_dhcp && CHOSEN_BACKEND="isc" ;;
    *)   clear; return 0 ;;
  esac

  # ────────────────── run setup, enable service, open firewall ────────────────
  local CONF SVC
  if [[ "$CHOSEN_BACKEND" == "kea" ]]; then
    kea_dhcp_setup
    systemctl enable --now kea-dhcp4 >/dev/null 2>&1 || true
    CONF="/etc/kea/kea-dhcp4.conf"; SVC="kea-dhcp4"
  else
    dhcpd_setup
    systemctl enable --now dhcpd >/dev/null 2>&1 || true
    CONF="/etc/dhcp/dhcpd.conf"; SVC="dhcpd"
  fi

  firewall-cmd --zone=public --add-service=dhcp --permanent >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true

  # ────────────────────────────── final validation ─────────────────────────────
  local ok_conf=0 ok_svc=0
  [[ -s "$CONF" ]] && ok_conf=1
  if systemctl is-active --quiet "$SVC"; then ok_svc=1; fi

  if [[ $ok_conf -eq 1 && $ok_svc -eq 1 ]]; then
    msgbox "Success" "$SVC is running and $CONF configured successfully."
    clear; return 0
  fi

  # Syntax hint on failure
  local syntax=""
  if [[ "$SVC" == "kea-dhcp4" && -f "$CONF" ]]; then
    syntax="$(kea-dhcp4 -t "$CONF" 2>&1 || true)"
  elif [[ "$SVC" == "dhcpd" && -f "$CONF" ]]; then
    syntax="$(dhcpd -t -cf "$CONF" 2>&1 || true)"
  fi

  local err="Validation failed:
- Config file present: $( [[ $ok_conf -eq 1 ]] && echo YES || echo NO )
- Service active:      $( [[ $ok_svc -eq 1 ]] && echo YES || echo NO )

$( [[ -n "$syntax" ]] && echo -e "Syntax check output:\n\n$syntax" || echo "No syntax details available.")"

  msgbox "DHCP Validation" "$err" 18 90
  clear
  return 1
}
#===========SET SELINUX=============
configure_selinux() {
  dialog --backtitle "SELinux setsbool Configuration" --title "SELinux Configuration" --infobox "Applying SELinux settings for Samba..." 5 50
  sleep 2
  setsebool -P samba_create_home_dirs=on \
             samba_domain_controller=on \
             samba_enable_home_dirs=on \
             samba_portmapper=on \
             use_samba_home_dirs=on
sleep2
}
#===========CONFGIURE FIREWALL=============
configure_firewall() {
  dialog --backtitle "Firewall Services Configuration" --title "Firewall Configuration" --infobox "Applying firewall rules for AD services..." 5 60
  firewall-cmd --permanent --add-service=samba-dc >/dev/null
  firewall-cmd --permanent --add-service=ldaps >/dev/null
  firewall-cmd --permanent --add-service=ntp >/dev/null

  firewall-cmd --reload >/dev/null
  systemctl restart firewalld
  sleep 2
  # Extract enabled services
  FIREWALL_SERVICES=$(firewall-cmd --list-services 2>/dev/null)

  dialog --backtitle "Firewall Services Configuration" --title "Firewall Status" --infobox "These services are now open on the server:\n\n$FIREWALL_SERVICES\n\n" 12 60
  sleep 4
}
#===========PROVISION SAMBA WITH MOCK=============
configure_samba_provisioning() {
  OSVER=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release)
  MAJOROS=$(cut -d. -f1 <<< "$OSVER")
  MINOROS=$(cut -d. -f2 <<< "$OSVER")

  DOMAIN=$(hostname | sed 's/^[^.:]*[.:]//' | sed -e 's/\(.*\)/\U\1/')
  ADDOMAIN=$(hostname | sed 's/^[^.:]*[.:]//' | cut -d. -f1 | sed -e 's/\(.*\)/\U\1/')

  dialog --backtitle "Samba Build --dc with Mock" --title "Samba Source Build" --infobox \
  "Downloading and compiling Samba from source using 'mock'\n\nThis may take up to 30 minutes\n\nThe Installer will Continue Shortly " 10 80
  sleep 4

  dnf download samba --source
  if ! ls /root/samba-*.rpm 1>/dev/null 2>&1; then
    dialog --backtitle "Samba Build --dc with Mock" --msgbox "Samba source RPM failed to download. Check your network." 8 50
    return 1
  fi

  MOCKSMBVER=$(dnf provides samba | grep samba | sed '2,4d' | cut -d: -f1 | cut -dx -f1)
  MOCKCMD="mock -r rocky-${MAJOROS}-x86_64 --enablerepo=devel --define 'dist .el${MAJOROS}_${MINOROS}.dc' --with dc ${MOCKSMBVER}src.rpm"

  TMPLOG=$(mktemp)
  PIPE=$(mktemp -u)
  mkfifo "$PIPE"

  # Launch mock inside a pseudo-terminal using `script`
  script -q -c "$MOCKCMD" /dev/null > "$PIPE" 2>&1 &
  MOCKPID=$!

  dialog --backtitle "Samba Build --dc with Mock" --title "Building Samba with Mock (Live)" --programbox 25 150 < "$PIPE"

  wait $MOCKPID
  rm -f "$PIPE"

  if ! ls /var/lib/mock/rocky-${MAJOROS}-x86_64/result/*.rpm &>/dev/null; then
    dialog --backtitle "Samba Build --dc with Mock" --title "Mock Build Failed" --msgbox "Build failed. Check logs manually." 8 60
    return 1
  fi

  mkdir -p /root/.samba
  cp /var/lib/mock/rocky-${MAJOROS}-x86_64/result/*.rpm /root/.samba
  createrepo /root/.samba
  dnf config-manager --add-repo /root/.samba
  dnf -y install --nogpgcheck samba-dc samba-client krb5-workstation samba \
    --repofrompath=samba,/root/.samba \
    --enablerepo=samba >/dev/null

  mv -f /etc/samba/smb.conf /etc/samba/smb.bak.orig

  output=$(samba-tool domain provision \
    --realm="$DOMAIN" \
    --domain="$ADDOMAIN" \
    --adminpass="$ADMINPASS" 2>&1)

  echo "$output"

  if echo "$output" | grep -q "ERROR"; then
    dialog --backtitle "Samba Build --dc with Mock" --msgbox "Provisioning failed. Check output." 8 60
    return 1
  fi

  dialog --backtitle "Samba Build --dc with Mock" --msgbox "Samba AD Domain provisioned successfully." 7 50
  return 0
}

#===========CREATE KDC=============
create_kdc_conf() {
  KRB5_SRC="/var/lib/samba/private/krb5.conf"
  KRB5_DEST="/etc/krb5.conf"

  if [[ ! -f "$KRB5_SRC" ]]; then
    dialog --backtitle "Configure Kerberos (KDC)" --title "KDC Error" --msgbox "Kerberos configuration file not found at $KRB5_SRC.\nProvisioning may have failed. Exiting..." 8 60
    exit 1
  fi

  dialog --backtitle "Configure Kerberos (KDC)" --title "Creating KDC" --infobox "Copying Kerberos configuration to $KRB5_DEST..." 5 60
  sleep 2
  \cp -rf "$KRB5_SRC" "$KRB5_DEST"

  if [[ $? -eq 0 ]]; then
    dialog --backtitle "Configure Kerberos (KDC)" --infobox "Kerberos configuration successfully copied." 6 50
    sleep 2
  else
    dialog --backtitle "Configure Kerberos (KDC)" --msgbox "Failed to copy Kerberos configuration. Please check permissions." 6 60
    sleep 2
  fi
}

#===========SET DNS to ITSELF=============
set_local_dns_resolver() {
  IP=$(hostname -I | awk '{print $1}')  # Get first IP address
  INTERFACE=$(nmcli -t -f DEVICE,STATE dev | awk -F: '$2=="connected" {print $1}' | head -n1)

  if [[ -z "$IP" || -z "$INTERFACE" ]]; then
    dialog --backtitle "Configure Local Resolver" --msgbox "Failed to detect IP or active interface. Cannot set DNS." 8 50
    return 1
  fi

  dialog --backtitle "Configure Local Resolver" --title "Setting DNS Resolver" --infobox \
  "Configuring ${INTERFACE} to use ${IP} as its primary DNS resolver..." 5 80
  sleep 2

  nmcli con mod "$INTERFACE" ipv4.dns "$IP"
  systemctl restart NetworkManager

  if [[ $? -eq 0 ]]; then
    dialog --backtitle "Configure Local Resolver" --infobox "DNS resolver successfully set to ${IP} on ${INTERFACE}." 6 80
    sleep 2
  else
    dialog --backtitle "Configure Local Resolver" --msgbox "Failed to apply DNS resolver configuration." 6 50
    return 1
  fi
}

#===========ADD FREERADIUS SUPPORT=============
add_freeradius_support() {
  SMB_CONF="/etc/samba/smb.conf"

  if [[ ! -f "$SMB_CONF" ]]; then
    dialog --title "FreeRADIUS Error" --msgbox "$SMB_CONF not found. Please verify Samba is installed." 7 60
    exit 1
  fi

  dialog --backtitle "Configuring smb.conf" --title "FreeRADIUS Integration" --infobox "Adding default FreeRADIUS support to smb.conf..." 5 60
  sleep 2

  sed -i '8i \       \ #Added for FreeRADIUS Support' "$SMB_CONF"
  sed -i '9i \       \ ntlm auth = mschapv2-and-ntlmv2-only' "$SMB_CONF"
  sed -i '10i \       \\#ldap server require strong auth = no #UNCOMMENT THIS IF YOU NEED PLAIN LDAP BIND (non-TLS)' "$SMB_CONF"

  dialog --backtitle "Configuring smb.conf" --infobox "FreeRADIUS options successfully added to smb.conf." 6 60
  sleep 2
}
#===========ADD DNF-SMB-MON CRON JOB=============
add_dnf_smb_mon_cron() {
  MONITOR_SCRIPT="/root/ADDCInstaller/dnf-smb-mon"
  DEST_BIN="/usr/bin/dnf-smb-mon"

  if [[ ! -f "$MONITOR_SCRIPT" ]]; then
    dialog --backtitle "Configuring Repository Monitoring" --title "Cron Job Error" --msgbox "$MONITOR_SCRIPT not found. Cannot configure cron job." 7 80
    exit 1
  fi

  dialog --backtitle "Configuring Repository Monitoring" --title "Configuring Repo Monitor" --infobox "Installing dnf-smb-mon and setting up cron job..." 5 80
  sleep 2

  touch /var/log/dnf-smb-mon.log
  chmod 700 "$MONITOR_SCRIPT"
  \cp "$MONITOR_SCRIPT" "$DEST_BIN"

  (
    crontab -l 2>/dev/null
    echo "0 */6 * * * $DEST_BIN"
  ) | sort -u | crontab -

  systemctl restart crond
  dialog --backtitle "Configuring Repository Monitoring" --infobox "dnf-smb-mon installed and cron job scheduled every 6 hours." 6 70
  sleep 2
}
#===========COPY SAMBA-DNF-PKG-UPDATE=============
copy_samba_dnf_pkg_update() {
  UPDATE_SCRIPT="/root/ADDCInstaller/samba-dnf-pkg-update"
  DEST_BIN="/usr/bin/samba-dnf-pkg-update"

  if [[ ! -f "$UPDATE_SCRIPT" ]]; then
    dialog --backtitle "Configuring Samba DNF Package Updater" --title "Copy Error" --msgbox "$UPDATE_SCRIPT not found. Cannot continue." 7 60
    exit 1
  fi

  dialog --backtitle "Configuring Samba DNF Package Updater" --title "Samba DNF Update" --infobox "Installing samba-dnf-pkg-update script..." 5 60
  sleep 2

  chmod 700 "$UPDATE_SCRIPT"
  \cp "$UPDATE_SCRIPT" "$DEST_BIN"

  dialog --backtitle "Configuring Samba DNF Package Updater" --infobox "samba-dnf-pkg-update successfully installed to /usr/bin." 6 60
  sleep 2
}
#===========ENABLE AND CHECK SAMBA DC SERVICE=============
enable_and_check_samba_service() {
  SERVICE_NAME="samba"

  # Check if the service exists
  if ! systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
    dialog --title "Service Error" --msgbox "The service '${SERVICE_NAME}' was not found on this system.\nPlease ensure Samba is installed." 8 60
    exit 1
  fi

  # Enable and start the service
  dialog --backtitle "Validating Samba Service" --title "Samba Service" --infobox "Enabling and starting the Samba service..." 5 60
  sleep 2
  systemctl enable "$SERVICE_NAME" --now

  # Check service status
  samba_status=$(systemctl is-active "$SERVICE_NAME")
  if [[ "$samba_status" = "active" ]]; then
    dialog --backtitle "Validating Samba Service" --title "Samba Service" --infobox "Samba service is running." 5 40
  else
    dialog --backtitle "Validating Samba Service" --title "Samba Error" --msgbox "Samba service is NOT running.\nStatus: $samba_status" 7 50
    exit 1
  fi
  sleep 2
}
#===========UPDATE ISSUE FILE============
update_issue_file() {
  rm -rf /etc/issue
  touch /etc/issue
  cat <<EOF >/etc/issue
\S
Kernel \r on an \m
Hostname: \n
IP Address: \4
EOF
}
#===========SAMBA LDAPS CERT SETUP=============
setup_samba_ldaps_cert() {
  TLS_DIR="/var/lib/samba/private/tls"
  CERT="$TLS_DIR/samba.crt"
  KEY="$TLS_DIR/samba.key"
  CA="$TLS_DIR/ca.crt"
  SMB_CONF="/etc/samba/smb.conf"
  LOG="/var/log/samba-ldap-cert-setup.log"

  FQDN=$(hostname -f)
  IPADDR=$(hostname -I | awk '{print $1}')

  mkdir -p "$TLS_DIR"

  dialog --backtitle "Configuring TLS" --title "Samba TLS Setup" --infobox "Generating Samba LDAPS certificate for $FQDN with IP $IPADDR..." 6 80
  sleep 2

  SAN_CONF=$(mktemp)
  cat > "$SAN_CONF" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $FQDN

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $FQDN
IP.1 = $IPADDR
EOF

  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$KEY" \
    -out "$CERT" \
    -config "$SAN_CONF" \
    -extensions v3_req >> "$LOG" 2>&1
  rm -f "$SAN_CONF"

  if [[ -f "$CERT" && -f "$KEY" ]]; then
    cp "$CERT" "$CA"
    chmod 600 "$CERT" "$CA" "$KEY"
    dialog --backtitle "Configuring TLS" --infobox "Certificate and key successfully created at $TLS_DIR" 6 60
    sleep 2
  else
    dialog --backtitle "Configuring TLS" --title "Certificate Error" --msgbox "Certificate or key was not created. Check $LOG for errors." 7 60
    return 1
  fi

  if ! grep -q "tls keyfile" "$SMB_CONF"; then
    dialog --backtitle "Configuring TLS" --title "Updating smb.conf" --infobox "Inserting TLS configuration into smb.conf..." 6 60
    sleep 2

    awk -v keyfile="$KEY" -v certfile="$CERT" -v cafile="$CA" '
    BEGIN { inserted=0 }
    /^\[global\]/ { print; in_global=1; next }
    in_global && /^\[/ {
      if (!inserted) {
        print "    # TLS configuration for LDAPS/StartTLS"
        print "    tls enabled = yes"
        print "    tls keyfile = " keyfile
        print "    tls certfile = " certfile
        print "    tls cafile = " cafile
        print "    ldap server require strong auth = yes"
        inserted = 1
      }
      in_global=0
    }
    { print }
    END {
      if (!inserted) {
        print "[global]"
        print "    tls enabled = yes"
        print "    tls keyfile = " keyfile
        print "    tls certfile = " certfile
        print "    tls cafile = " cafile
        print "    ldap server require strong auth = yes"
      }
    }
    ' "$SMB_CONF" > "$SMB_CONF.new" && mv "$SMB_CONF.new" "$SMB_CONF"
  fi

  dialog --backtitle "Configuring TLS" --title "Restarting Samba" --infobox "Restarting Samba to apply certificate configuration..." 6 60
  sleep 2
  systemctl restart samba

  # Validate that samba restarted successfully
  if systemctl is-active --quiet samba; then
    dialog --backtitle "Configuring TLS" --infobox "Samba restarted and is running." 6 50
    sleep 2
  else
    dialog --backtitle "Configuring TLS" --title "Samba Error" --msgbox "Samba failed to restart. Please check the service status manually." 7 60
    return 1
  fi
}
#===========LDAP BIND AND TEST=============
test_ldap_secure_connection() {
  LOG="/var/log/samba-ldap-cert-setup.log"
  IPADDR=$(hostname -I | awk '{print $1}')

  LDAP_ADMIN_DN=$(samba-tool user show Administrator | awk -F': ' '/^dn: / {print $2}')
  if [[ -z "$LDAP_ADMIN_DN" ]]; then
    dialog --backtitle "Samba Validation" --title "LDAP Test Error" --msgbox "Failed to retrieve Administrator DN from samba-tool output." 7 60
    return 1
  fi

  LDAP_BASEDN=$(echo "$LDAP_ADMIN_DN" | grep -oE 'DC=[^,]+(,DC=[^,]+)*')

  dialog --backtitle "Samba Validation" --infobox "Testing StartTLS on port 389..." 5 50
  sleep 2
  LDAPTLS_REQCERT=never \
  ldapsearch -x -H ldap://$IPADDR -ZZ \
    -D "$LDAP_ADMIN_DN" \
    -w "$ADMINPASS" \
    -b "$LDAP_BASEDN" dn >> "$LOG" 2>&1

  if grep -q "^dn: " "$LOG"; then
    dialog --backtitle "Samba Validation" --infobox "StartTLS (389) test passed." 5 50
    sleep 2
  else
    dialog --backtitle "Samba Validation" --msgbox "StartTLS (389) test failed — see $LOG for details." 7 60
  fi

  dialog --backtitle "Samba Validation" --infobox "Testing LDAPS on port 636..." 5 50
  sleep 2
  LDAPTLS_REQCERT=never \
  ldapsearch -x -H ldaps://$IPADDR \
    -D "$LDAP_ADMIN_DN" \
    -w "$ADMINPASS" \
    -b "$LDAP_BASEDN" dn >> "$LOG" 2>&1

  if grep -q "^dn: " "$LOG"; then
    dialog --backtitle "Samba Validation" --infobox "LDAPS (636) test passed." 5 50
    sleep 2
  else
    dialog --backtitle "Samba Validation" --msgbox "LDAPS test failed — see $LOG for details." 7 60
  fi

  dialog --backtitle "Samba Validation" --title "LDAP Secure Setup Complete" --infobox "StartTLS and LDAPS tested." 7 60
  sleep 3
  return 0
}
#===========KERBEROS LOGIN AND TICKET CHECK=============
check_kerberos_ticket() {
  dialog --backtitle "Samba Validation" --title "Kerberos Login" --infobox "Attempting Kerberos login using Administrator credentials..." 5 80
  sleep 2

  # Attempt kinit with password from variable
  echo "$ADMINPASS" | kinit Administrator 2>/tmp/kinit_error.log

  if [[ $? -ne 0 ]]; then
    ERROR_MSG=$(< /tmp/kinit_error.log)
    dialog --backtitle "Samba Validation" --title "Kerberos Login Failed" --msgbox "Kerberos login failed:\n$ERROR_MSG" 10 80
    return 1
  fi

  # Run klist and capture output
  klist_output=$(klist 2>&1)

  if echo "$klist_output" | grep -q "Valid starting.*Service principal"; then
    dialog --backtitle "Samba Validation" --title "Kerberos Login Success" --infobox "Kerberos ticket successfully acquired for Administrator.\n\nTicket Details:\n\n$klist_output" 20 80
    sleep 3
  else
    dialog --backtitle "Samba Validation" --title "Kerberos Ticket Check Failed" --msgbox "Kerberos login succeeded, but no valid ticket found.\n\n$klist_output" 10 80
    return 1
  fi

  return 0
}
#===========AUTHENTICATED SAMBA LOGIN CHECK=============
check_smbclient_login() {
  dialog --backtitle "Samba Validation" --title "SMB Login Test" --infobox "Attempting SMB connection to //localhost/netlogon as Administrator..." 5 80
  sleep 2

  smb_output=$(echo "$ADMINPASS" | smbclient //localhost/netlogon -UAdministrator -c 'ls' 2>&1)

  if echo "$smb_output" | grep -qE '^\s*\.\s+D\s+[0-9]+' && echo "$smb_output" | grep -qE '^\s*\.\.\s+D\s+[0-9]+'; then
    dialog --backtitle "Samba Validation" --title "SMB Login Success" --infobox "Successfully authenticated and listed netlogon share." 5 60
    sleep 2
  else
    dialog --backtitle "Samba Validation" --title "SMB Login Failed" --msgbox "SMB login failed or unexpected output.\n\n$smb_output" 15 70
    return 1
  fi

  return 0
}
#===========DNS SRV RECORD CHECK=============
check_dns_srv_records() {
  FQDN=$(hostname -f)
  DOMAIN=$(echo "$FQDN" | cut -d'.' -f2-)
  HOSTNAME_PART=$(echo "$FQDN" | cut -d'.' -f1)
  TIMEOUT=5

  dialog --backtitle "Samba Validation" --backtitle "SRV Records Check" --title "DNS SRV Record Check" --infobox "Querying SRV records for domain $DOMAIN..." 5 60
  sleep 1

  # Perform SRV lookups with timeout
  ldap_srv=$(timeout $TIMEOUT host -t SRV _ldap._tcp."$DOMAIN" 2>/dev/null)
  kerberos_srv=$(timeout $TIMEOUT host -t SRV _kerberos._udp."$DOMAIN" 2>/dev/null)
  fqdn_check=$(timeout $TIMEOUT host -t A "$FQDN" 2>/dev/null)

  # Handle timeout or failure
  if [[ -z "$ldap_srv" || -z "$kerberos_srv" || -z "$fqdn_check" ]]; then
    dialog --backtitle "Samba Validation" --title "DNS Query Timeout" --msgbox "Error: One or more DNS queries timed out after ${TIMEOUT}s.\n\nLDAP SRV:\n$ldap_srv\n
\nKerberos SRV:\n$kerberos_srv\n\nFQDN A record:\n$fqdn_check" 20 75
    return 1
  fi

  # Extract and normalize target FQDNs from SRV responses
  get_srv_hostnames() {
    local srv_records="$1"
    echo "$srv_records" | awk '/SRV record/ {print tolower($NF)}' | sed 's/\.$//'
  }

  ldap_targets=$(get_srv_hostnames "$ldap_srv")
  kerberos_targets=$(get_srv_hostnames "$kerberos_srv")

  # Combine and check if any match our full FQDN
  all_targets="$ldap_targets $kerberos_targets"
  match_found=0
  for t in $all_targets; do
    if [[ "$t" == "$FQDN" ]]; then
      match_found=1
      break
    fi
  done

  if [[ $match_found -eq 1 ]]; then
    dialog --backtitle "Samba Validation" --backtitle "SRV Records Check" --title "DNS SRV Check Passed" --infobox "Success: SRV record matches found for $FQDN\n\nLDAP SRV:\n$ldap_srv\n\nKerberos SRV:\n$kerberos_srv\n\nA Record:\n$fqdn_check" 20 75
    sleep 3
    return 0
  else
    # Check Samba service status
    samba_status=$(systemctl is-active samba)
    dns_entry=$(nmcli dev show | grep 'IP4.DNS')

    dialog  --backtitle "Samba Validation" --title "DNS SRV Record Check Failed" --msgbox "Error: No matching SRV hostnames.\n\nSamba
 status: $samba_status\n\nDNS entries:\n$dns_entry" 20 75
    return 1
  fi
}

#===========ANONYMOUS LOGIN TEST=============
test_anonymous_login() {
  dialog --backtitle "Samba Validation" --title "Anonymous SMB Login Test" --infobox "Testing anonymous login to the Samba server..." 5 60
  sleep 2

  output=$(smbclient -L localhost -N 2>&1)

  if echo "$output" | grep -q "Anonymous login successful"; then
    dialog --backtitle "Samba Validation" --title "Anonymous Login Success" --infobox "Success: Anonymous login successful." 6 60
    sleep 2
  else
    dialog --backtitle "Samba Validation" --title "Anonymous Login Failed" --msgbox "Error: Anonymous logins are not available.\n\n$output" 15 70
    return 1
  fi

  return 0
}
#===========CLEANUP STRONG AUTH LINE IN smb.conf=============
cleanup_strong_auth_line() {
  CONF_FILE="/etc/samba/smb.conf"

  if grep -q '^[[:space:]]*\\#ldap server require strong auth = no' "$CONF_FILE"; then
    dialog --backtitle "Samba Validation" --title "Cleaning Samba Config" --infobox "Fixing strong auth line in smb.conf..." 5 60
    sleep 2

    # Remove leading backslash before #ldap line
    sed -i 's/^[[:space:]]*\\#ldap server require strong auth = no/#ldap server require strong auth = no/' "$CONF_FILE"

    dialog --backtitle "Samba Validation" --title "Fix Applied" --infobox "smb.conf corrected" 5 60
    sleep 2
  else
    dialog --backtitle "Samba Validation" --title "No Change Needed" --infobox "No Errors in smb.conf." 5 60
    sleep 2
  fi
}
#===========REVERSE DNS ZONE CREATION=============
create_reverse_dns_zone() {
  LOG_FILE="/var/log/samba-reverse-zone.log"
  FQDN=$(hostname -f)
  IP=$(hostname -I | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; exit }}')

  echo "[INFO] Detected FQDN: $FQDN" >> "$LOG_FILE"
  echo "[INFO] Detected IP: $IP" >> "$LOG_FILE"

  if [[ -z "$IP" ]]; then
    dialog --backtitle "Create Reverse Zone" --title "IP Detection Failed" --msgbox "Could not detect a valid IPv4 address from hostname -I." 6 60
    echo "[ERROR] No valid IPv4 address found." >> "$LOG_FILE"
    return 1
  fi

  REVERSE=$(echo "$IP" | awk -F. '{print $(NF-1)"."$(NF-2)"."$(NF-3)}')
  DEFAULT_ZONE="$REVERSE.in-addr.arpa"

  TMP_ZONE_FILE=$(mktemp)
  dialog --backtitle "Create Reverse Zone" --title "Reverse DNS Zone Suggestion" --inputbox \
    "A reverse DNS zone should be added to your Samba DNS.\n\nBased on your IP $IP, the recommended reverse zone is:\n\n  $DEFAULT_ZONE\n\nYou may press OK to accept this default or modify it." \
    12 70 "$DEFAULT_ZONE" 2> "$TMP_ZONE_FILE"
  RESPONSE=$?

  ZONE=$(<"$TMP_ZONE_FILE")
  rm -f "$TMP_ZONE_FILE"

  if [[ $RESPONSE -ne 0 || -z "$ZONE" ]]; then
    dialog --backtitle "Create Reverse Zone" --title "Operation Cancelled" --msgbox "No reverse zone was specified. Operation cancelled." 6 60
    echo "[WARN] Operation cancelled. No zone specified." >> "$LOG_FILE"
    return 1
  fi

  dialog --backtitle "Create Reverse Zone" --title "Creating Reverse DNS Zone" --infobox "Adding reverse DNS zone $ZONE to domain $FQDN..." 6 80
  echo "[INFO] Creating reverse zone: $ZONE on $FQDN" >> "$LOG_FILE"
  sleep 2

  samba-tool dns zonecreate "$FQDN" "$ZONE" -U "Administrator%$ADMINPASS" >> "$LOG_FILE" 2>&1
  if [[ $? -eq 0 ]]; then
    dialog --backtitle "Create Reverse Zone" --title "Reverse Zone Added" --infobox "Reverse DNS zone $ZONE successfully added to $FQDN." 7 80
    echo "[SUCCESS] Reverse zone $ZONE added to $FQDN" >> "$LOG_FILE"
    sleep 3
  else
    dialog --backtitle "Create Reverse Zone" --title "Zone Creation Failed" --msgbox "Failed to add reverse DNS zone.\n\nCheck $LOG_FILE for details." 10 70
    echo "[ERROR] Failed to create reverse zone $ZONE" >> "$LOG_FILE"
  fi
}
#===========RELAX PASSWORD SETTINGS FOR LAB=============
relax_lab_password_policy() {
  TMP_SELECTION=$(mktemp)
  TMP_LOG="/var/log/samba-password-policy.log"

  dialog --backtitle "Password Policy" --title "Relax Password Settings (Lab Use)" --checklist "\
Select which password policy changes you want to apply:\n\n\
Use SPACE to select/deselect options. Press ENTER to confirm, or Cancel to skip" 15 90 6 \
    1 "Disable complexity requirements" off \
    2 "Set history-length to 0" off \
    3 "Set min password age to 0" off \
    4 "Set max password age to 0" off 2> "$TMP_SELECTION"

  RESPONSE=$?
  CHOICES=$(<"$TMP_SELECTION")
  rm -f "$TMP_SELECTION"

  if [[ $RESPONSE -ne 0 || -z "$CHOICES" ]]; then
    dialog --backtitle "Password Policy" --title "Cancelled" --infobox "No changes were made to password policy." 5 50
    sleep 2
    return 1
  fi

  dialog --backtitle "Password Policy" --title "Applying Settings" --infobox "Applying selected password policy settings..." 5 50
  sleep 2

  for choice in $CHOICES; do
    case $choice in
      1)
        samba-tool domain passwordsettings set --complexity=off >> "$TMP_LOG" 2>&1
        ;;
      2)
        samba-tool domain passwordsettings set --history-length=0 >> "$TMP_LOG" 2>&1
        ;;
      3)
        samba-tool domain passwordsettings set --min-pwd-age=0 >> "$TMP_LOG" 2>&1
        ;;
      4)
        samba-tool domain passwordsettings set --max-pwd-age=0 >> "$TMP_LOG" 2>&1
        ;;
    esac
  done

  dialog --backtitle "Password Policy" --title "Password Policy Updated" --infobox "Selected settings have been applied.\nLog saved to $TMP_LOG." 6 60
  sleep 2
}
#===========CONFIGURE FAIL2BAN=============
configure_fail2ban() {
  LOG_FILE="/var/log/fail2ban-setup.log"
  ORIGINAL_FILE="/etc/fail2ban/jail.conf"
  JAIL_LOCAL_FILE="/etc/fail2ban/jail.local"
  SSHD_LOCAL_FILE="/etc/fail2ban/jail.d/sshd.local"

  {
    echo "10"
    echo "# Copying jail.conf to jail.local..."
    if cp -v "$ORIGINAL_FILE" "$JAIL_LOCAL_FILE" >> "$LOG_FILE" 2>&1; then
      echo "Copied jail.conf to jail.local" >> "$LOG_FILE"
    else
      dialog --backtitle "Configure Fail2ban for SSH" --title "Error" --msgbox "Failed to copy $ORIGINAL_FILE to $JAIL_LOCAL_FILE" 6 60
      echo "Failed to copy jail.conf" >> "$LOG_FILE"
      return 1
    fi

    echo "30"
    echo "# Enabling SSHD in jail.local..."
    if sed -i '/^\[sshd\]/,/^$/ s/#mode.*normal/&\nenabled = true/' "$JAIL_LOCAL_FILE" >> "$LOG_FILE" 2>&1; then
      echo "Modified jail.local to enable SSHD" >> "$LOG_FILE"
    else
      dialog --backtitle "Configure Fail2ban for SSH" --title "Error" --msgbox "Failed to enable SSHD in jail.local" 6 60
      return 1
    fi

    echo "50"
    echo "# Writing SSHD jail configuration..."
    cat <<EOL > "$SSHD_LOCAL_FILE"
[sshd]
enabled = true
maxretry = 5
findtime = 300
bantime = 3600
bantime.increment = true
bantime.factor = 2
EOL
    echo "Created sshd.local config" >> "$LOG_FILE"

    echo "60"
    echo "# Enabling and starting Fail2Ban..."
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl start fail2ban >> "$LOG_FILE" 2>&1
    sleep 2

    echo "75"
    echo "# Checking Fail2Ban status..."
    if systemctl is-active --quiet fail2ban; then
      echo "Fail2Ban is running." >> "$LOG_FILE"
    else
      echo "Fail2Ban failed to start. Attempting SELinux recovery..." >> "$LOG_FILE"

      selinux_status=$(sestatus | grep "SELinux status" | awk '{print $3}')
      if [[ "$selinux_status" == "enabled" ]]; then
        restorecon -v /etc/fail2ban/jail.local >> "$LOG_FILE" 2>&1
        denials=$(ausearch -m avc -ts recent | grep "fail2ban-server" | wc -l)
        if (( denials > 0 )); then
          ausearch -c 'fail2ban-server' --raw | audit2allow -M my-fail2banserver >> "$LOG_FILE" 2>&1
          semodule -X 300 -i my-fail2banserver.pp >> "$LOG_FILE" 2>&1
          echo "Custom SELinux policy applied." >> "$LOG_FILE"
        fi
      fi

      systemctl restart fail2ban >> "$LOG_FILE" 2>&1
      if systemctl is-active --quiet fail2ban; then
        echo "Fail2Ban restarted successfully after SELinux fix." >> "$LOG_FILE"
      else
        dialog --title "Fail2Ban Error" --msgbox "Fail2Ban failed to start even after SELinux policy fix. Please investigate manually." 8 70
        echo "Fail2Ban still failed after SELinux fix." >> "$LOG_FILE"
        return 1
      fi
    fi

    echo "90"
    echo "# Verifying SSHD jail status..."
    sshd_status=$(fail2ban-client status sshd 2>&1)
    if echo "$sshd_status" | grep -q "ERROR   NOK: ('sshd',)"; then
      dialog --backtitle "Configure Fail2ban for SSH" --title "SSHD Jail Error" --msgbox "SSHD jail failed to start. Check configuration:\n\n$sshd_status" 10 70
      echo "SSHD jail failed to start." >> "$LOG_FILE"
    elif echo "$sshd_status" | grep -q "Banned IP list:"; then
      echo "SSHD jail is active and functional." >> "$LOG_FILE"
    else
      dialog --backtitle "Configure Fail2ban for SSH" --title "SSHD Jail Warning" --msgbox "SSHD jail may not be functional. Check manually:\n\n$sshd_status" 10 70
      echo "SSHD jail might be non-functional." >> "$LOG_FILE"
    fi

    echo "100"
  } | dialog --backtitle "Configure Fail2ban for SSH" --title "Fail2Ban Setup" --gauge "Installing and configuring Fail2Ban..." 10 60 0

  dialog --backtitle "Configure Fail2ban for SSH" --title "Success" --infobox "Fail2Ban has been configured and started successfully." 6 60
  sleep 3
}
#===========SERVICE CHECK & ENABLE PROGRESS=============
check_and_enable_services() {
  TMP_LOG=$(mktemp)
  TMP_BAR=$(mktemp)

  # List the services you want to manage
  SERVICES=("fail2ban" "samba" "cockpit.socket")  # <-- add or remove services as needed

  total=${#SERVICES[@]}
  count=0

  {
    for service in "${SERVICES[@]}"; do
      echo "Checking $service..." >> "$TMP_LOG"

      systemctl is-enabled --quiet "$service"
      if [[ $? -ne 0 ]]; then
        echo "$service is not enabled. Enabling..." >> "$TMP_LOG"
        systemctl enable "$service" >> "$TMP_LOG" 2>&1
      fi

      systemctl is-active --quiet "$service"
      if [[ $? -ne 0 ]]; then
        echo "$service is not running. Starting..." >> "$TMP_LOG"
        systemctl start "$service" >> "$TMP_LOG" 2>&1
      fi

      systemctl is-active --quiet "$service"
      if [[ $? -eq 0 ]]; then
        echo "$service is active." >> "$TMP_LOG"
      else
        echo "$service failed to start." >> "$TMP_LOG"
      fi

      # Progress bar update
      count=$((count + 1))
      percent=$(( (count * 100) / total ))
      echo $percent
      sleep 1
    done
  } | dialog --backtitle "Enabling and Starting Services" --title "Service Check & Startup" --gauge "Checking services and starting them if needed..." 10 70 0

  # Final report
  if grep -q "failed to start" "$TMP_LOG"; then
    dialog --backtitle "Enabling and Starting Services" --title "Service Status" --textbox "$TMP_LOG" 20 70
  else
    dialog --backtitle "Enabling and Starting Services" --title "All Services Running" --infobox "All services have been enabled and are running." 7 60
   sleep 3
  fi

  rm -f "$TMP_LOG" "$TMP_BAR"
}
#===========INSTALL SERVER MANAGEMENT SCRIPTS=============
install_server_management() {
  LOG_FILE="/var/log/server-management-install.log"
  INSTALL_DIR="/root/RADS-SMInstaller"
  GIT_REPO="https://github.com/fumatchu/RADS-SM.git"

  dialog --backtitle "Installing Server Manager" --title "Installing Server Management" --infobox \
    "This installer will set up Server Management tools for AD, DHCP, and services.\n\nYou can launch it anytime by typing: server-manager" 8 90
  echo "[INFO] Starting Server Management installation..." >> "$LOG_FILE"
  sleep 5

  mkdir -p "$INSTALL_DIR"
  git clone "$GIT_REPO" "$INSTALL_DIR" >> "$LOG_FILE" 2>&1
  if [[ $? -ne 0 ]]; then
    dialog --backtitle "Installing Server Manager" --title "Clone Failed" --msgbox "Failed to clone repository from $GIT_REPO\nCheck $LOG_FILE for details." 8 60
    echo "[ERROR] Git clone failed." >> "$LOG_FILE"
    return 1
  fi

  rm -rf /root/.servman /usr/bin/server-manager
  sed -i '/\/usr\/bin\/server-manager/d' /root/.bash_profile
  cd "$INSTALL_DIR" || return 1

  mv -v ./.servman /root >> "$LOG_FILE" 2>&1
  chmod 700 "$INSTALL_DIR/server-manager"
  mv -v "$INSTALL_DIR/server-manager" /usr/bin/ >> "$LOG_FILE" 2>&1
  chmod -R 700 /root/.servman/
  echo "/usr/bin/server-manager" >> /root/.bash_profile

  rm -rf "$INSTALL_DIR" /root/RADS-*

  dialog --backtitle "Installing Server Manager" --title "Installation Complete" --msgbox \
    "Server Management tools have been successfully installed!\n\nType 'server-manager' at any time to launch the interface." 10 80
  echo "[SUCCESS] Server Manager installed." >> "$LOG_FILE"
}
#===========CLEANUP INSTALLATION FILES=============
cleanup_installer_files() {
  LOG_FILE="/var/log/rads-cleanup.log"
  TMP_PROGRESS=$(mktemp)

  {
    echo "10"; sleep 0.5
    echo "# Starting cleanup..." >> "$TMP_PROGRESS"

    # Remove DCInstall.sh launch block
    sed -i '/## Run RADS installer on every interactive login ##/,/fi/d' /root/.bash_profile
    echo "[INFO] Removed RADS installer launch block" >> "$LOG_FILE"
    echo "30"; sleep 0.5

    # Also remove any straggling DCInstall.sh lines
    sed -i '/DCInstall.sh/d' /root/.bash_profile
    echo "[INFO] Removed any additional DCInstall.sh entries" >> "$LOG_FILE"
    echo "50"; sleep 0.5

    # Delete installer-related files
    rm -rf /root/DC-Installer.sh /root/ADDCInstaller /root/FR-Installer /root/FR-Installer.sh >> "$LOG_FILE" 2>&1
    rm -f /root/samba*.src.rpm >> "$LOG_FILE" 2>&1
    echo "[INFO] Removed installer files" >> "$LOG_FILE"
    echo "90"; sleep 0.5

    echo "100"
  } | dialog --backtitle "Installer Cleanup" --title "Cleanup Progress" --gauge "Cleaning up installer files..." 10 60 0

  rm -f "$TMP_PROGRESS"

  dialog --backtitle "Installer Cleanup" --title "Cleanup Complete" --infobox "Installer files have been successfully removed from the system." 6 80
  sleep 3
}
configure_dnf_automatic() {
    local CONFIG="/etc/dnf/automatic.conf"
    local BACKUP="/etc/dnf/automatic.conf.bak"
    local LOG="/tmp/dnf_automatic_setup.log"
    : > "$LOG"

    # 1. Inform the user
    dialog --backtitle "DNF Automatic Setup" --title "Configure Security Updates" \
        --infobox "This will enable SECURITY-ONLY updates.\n\nIt will also disable major OS upgrades.\n\nUpdate time will be left to system default" 10 60
        sleep 4

    # 2. Backup current config
    sudo cp -f "$CONFIG" "$BACKUP"
    echo "[INFO] Backed up $CONFIG to $BACKUP" >> "$LOG"

    # 3. Apply dnf-automatic settings
    sudo sed -i 's/^upgrade_type.*/upgrade_type = security/' "$CONFIG"
    sudo sed -i 's/^apply_updates.*/apply_updates = yes/' "$CONFIG"

    # 4. Remove any [timer] section from the config (let systemd handle it)
    sudo sed -i '/^\[timer\]/,/^$/d' "$CONFIG"

    # 5. Remove any old systemd override (Cockpit workaround)
    sudo rm -f /etc/systemd/system/dnf-automatic.timer.d/override.conf

    # 6. Reload systemd and restart timer
    sudo systemctl daemon-reexec
    sudo systemctl daemon-reload
    sudo systemctl enable --now dnf-automatic.timer

    # 7. Validate setup
    local STATUS_MSG=""
    local VALIDATE_OUTPUT
    VALIDATE_OUTPUT=$(grep -E 'upgrade_type|apply_updates' "$CONFIG")
    echo "$VALIDATE_OUTPUT" >> "$LOG"

    if echo "$VALIDATE_OUTPUT" | grep -q "apply_updates = yes"; then
        STATUS_MSG=" Security updates enabled.\n"
    else
        dialog --title "Error" --msgbox "Configuration failed.\nCheck $CONFIG or $LOG." 7 50
        return 1
    fi

    if systemctl is-active --quiet dnf-automatic.timer; then
        STATUS_MSG+="Timer is active.\n"
    else
        STATUS_MSG+="⚠Timer is not running!\nCheck: journalctl -u dnf-automatic.timer\n"
    fi

    NEXT_RUN=$(systemctl list-timers --all | grep dnf-automatic.timer | awk '{print $1, $2}')
    STATUS_MSG+="\nNext scheduled run: $NEXT_RUN"

    dialog --backtitle "DNF Automatic Setup" --title "Setup Complete" --infobox "$STATUS_MSG" 12 60
    sleep 3
}
#===========FINAL INSTALLATION COMPLETE PROMPT=============
prompt_reboot_now() {
  dialog --backtitle "Installation Complete" --title "Installation Complete" \
    --yesno "Server Installation Complete!\n\nWould you like to reboot the system now?" 8 50

  if [[ $? -eq 0 ]]; then
    reboot
  fi
}

# ========= MAIN =========
check_samba_running
show_welcome_screen
detect_active_interface
prompt_static_ip_if_dhcp
check_root_and_os
check_and_enable_selinux
check_internet_connectivity
validate_and_set_hostname
show_ad_server_checklist
prompt_admin_password
configure_dhcp_server
# === Set Time ===
if ! prompt_ntp_servers; then
    dialog --title "Chrony NTP Configuration" --msgbox "NTP configuration was cancelled." 6 40
    exit 1
fi

if ! prompt_allow_networks; then
    dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --msgbox "No network was allowed. Configuration cancelled." 6 50
    exit 1
fi

update_chrony_config

if ! validate_time_sync; then
    dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --msgbox "Chrony configuration aborted." 6 40
    exit 1
fi

dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "NTP configuration completed successfully." 4 60
sleep 3
#=== End Set time ===
update_and_install_packages
vm_detection
configure_selinux
configure_firewall
configure_samba_provisioning
create_kdc_conf
set_local_dns_resolver
add_freeradius_support
add_dnf_smb_mon_cron
copy_samba_dnf_pkg_update
enable_and_check_samba_service
update_issue_file
setup_samba_ldaps_cert
cleanup_strong_auth_line
test_ldap_secure_connection
check_kerberos_ticket
check_dns_srv_records
check_smbclient_login
test_anonymous_login
create_reverse_dns_zone
relax_lab_password_policy
configure_fail2ban
configure_dnf_automatic
install_server_management
check_and_enable_services
cleanup_installer_files
prompt_reboot_now
