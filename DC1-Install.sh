#!/bin/bash
#DC1-install.sh
#This script installs ANY ADDITIONAL INSTANCE of Samba AD (Secondary/Tertiary Server) with DC support using mock from Upstream Rocky REPO via src.rpm
TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
clear
#Check for Network Connectivity
echo "Checking for Internet Connectivity"
echo " "
sleep 3
# Function to check DNS resolution
check_dns_resolution() {
    local domain=$1
    ping -c 1 $domain &> /dev/null
    return $?
}

# Function to ping an address
ping_address() {
    local address=$1
    ping -c 1 $address &> /dev/null
    return $?
}

# Flag to track if any test fails
test_failed=false

# Check DNS resolution for google.com
echo "Checking DNS resolution for google.com via ping..."
if check_dns_resolution "google.com"; then
    echo "DNS resolution for google.com is successful."
else
    echo "DNS resolution for google.com failed."
    test_failed=true
fi

# Ping 8.8.8.8
echo "Trying to ping 8.8.8.8..."
if ping_address "8.8.8.8"; then
    echo "Successfully reached 8.8.8.8."
else
    echo "Cannot reach 8.8.8.8."
    test_failed=true
fi

# Provide final results summary
echo
echo "===== TEST RESULTS ====="
echo "DNS Resolution for google.com: $(if check_dns_resolution "google.com"; then echo "${GREEN}Passed"${TEXTRESET}; else echo "${RED}Failed"${TEXTRESET}; fi)"
echo "Ping to 8.8.8.8: $(if ping_address "8.8.8.8"; then echo "${GREEN}Passed"${TEXTRESET}; else echo "${RED}Failed"${TEXTRESET}; fi)"
echo "========================"
echo

# Prompt the user only if any test fails
if $test_failed; then
    read -p "One or more tests failed. Do you want to continue the script? (y/n): " user_input
    if [[ $user_input == "y" || $user_input == "Y" ]]; then
        echo "Continuing the script with failures"
        sleep 1
        # Place additional script logic here
    else
        echo "Please make sure that you have full Connectivty to the Internet Before Proceeding."
        exit 1
    fi
else
    echo "All tests passed successfully."
    sleep 3
    # Continue with the script or exit as needed
fi
clear
dnf -y install net-tools dmidecode ipcalc bind-utils

INTERFACE=$(nmcli | grep "connected to" | cut -d " " -f4)
DETECTIP=$(nmcli -f ipv4.method con show $INTERFACE)
FQDN=$(hostname)
IP=$(hostname -I)
DOMAIN=$(hostname | sed 's/^[^.:]*[.:]//' | sed -e 's/\(.*\)/\U\1/')
ADDOMAIN=$(hostname | sed 's/^[^.:]*[.:]//' | cut -d. -f1 | sed -e 's/\(.*\)/\U\1/')
REVERSE=$(echo "$IP" | {
  IFS=. read q1 q2 q3 q4
  echo "$q3.$q2.$q1"
})
MOCKSMBVER=$(dnf provides samba | grep samba | sed '2,4d' | cut -d: -f1 | cut -dx -f1)
MAJOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')
MINOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '1d')
USER=$(whoami)
DHCPNSNAME=$(hostname | sed 's/^[^.:]*[.:]//')
SUBNETNETWORK=$(echo "$IP" | {
  IFS=. read q1 q2 q3 q4
  echo "$q1.$q2.$q3.0"
})
NMCLIIP=$(nmcli | grep inet4 | sed '$d'| cut -c7- |cut -d / -f1)
HWKVM=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep KVM | cut -c16-)
HWVMWARE=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep Manufacturer | grep "VMware, Inc." | cut -c16- | cut -d , -f1)
n='([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
m='([0-9]|[12][0-9]|3[012])'
#Bracketed pasting...yuck!
sed -i '8i set enable-bracketed-paste off' /etc/inputrc
#Checking for user permissions
if [ "$USER" = "root" ]; then
  echo " "
else
  echo ${RED}"This program must be run as root ${TEXTRESET}"
  echo "Exiting"
fi
#Checking for version Information
if [ "$MAJOROS" = "9" ]; then
  echo " "
else
  echo ${RED}"Sorry, but this installer only works on Rocky 9.X ${TEXTRESET}"
  echo "Please upgrade to ${GREEN}Rocky 9.x${TEXTRESET}"
  echo "Exiting the installer..."
  exit
fi
clear
#Detect Static or DHCP (IF not Static, change it)
cat <<EOF
Checking for static IP Address
EOF
sleep 1s

if [ -z "$INTERFACE" ]; then
  "Usage: $0 <interface>"
  exit 1
fi
# Function to validate IP address in CIDR notation
validate_cidr() {
  local cidr=$1
  local n="(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
  local m="(3[0-2]|[1-2]?[0-9])"
  [[ $cidr =~ ^$n(\.$n){3}/$m$ ]]
}

# Function to validate an IP address in dotted notation
validate_ip() {
  local ip=$1
  local n="(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
  [[ $ip =~ ^$n(\.$n){3}$ ]]
}

# Function to validate FQDN
validate_fqdn() {
  local fqdn=$1
  [[ $fqdn =~ ^([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]
}

if [ "$DETECTIP" = "ipv4.method:                            auto" ]; then
  while true; do
    echo -e "${RED}Interface $INTERFACE is using DHCP${TEXTRESET}"

    # Validate IPADDR
    read -p "Please provide a static IP address in CIDR format (i.e 192.168.24.2/24): " IPADDR
    while ! validate_cidr "$IPADDR"; do
      echo -e "${RED}The entry is not in valid CIDR notation. Please Try again${TEXTRESET}"
      read -p "Please provide a static IP address in CIDR format (i.e 192.168.24.2/24): " IPADDR
    done

    # Validate GW
    read -p "Please provide a Default Gateway Address: " GW
    while ! validate_ip "$GW"; do
      echo -e "${RED}The entry is not a valid IP address. Please Try again${TEXTRESET}"
      read -p "Please provide a Default Gateway Address: " GW
    done

    # Validate HOSTNAME
    validate_fqdn() {
  local fqdn="$1"

  # Check if the FQDN is valid using a regular expression
  if [[ "$fqdn" =~ ^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$ ]]; then
    return 0
  else
    return 1
  fi
}

check_hostname_in_domain() {
  local fqdn="$1"
  local hostname="${fqdn%%.*}"
  local domain="${fqdn#*.}"

  # Check if the hostname is not the same as any part of the domain
  if [[ "$domain" =~ (^|\.)"$hostname"(\.|$) ]]; then
    return 1
  else
    return 0
  fi
}

read -p "Please provide the FQDN for this machine: " HOSTNAME

while ! validate_fqdn "$HOSTNAME" || ! check_hostname_in_domain "$HOSTNAME"; do
  echo -e "${RED}The entry is not a valid FQDN, or the hostname is repeated in the domain name (This is not Supported). Please Try again${TEXTRESET}"
  read -p "Please provide the FQDN for this machine: " HOSTNAME
done


    # Validate DNSSERVER
    read -p "Please provide the IP Address of your Pre-existing Domain Controller for name resolution: " DNSSERVER
    while ! validate_ip "$DNSSERVER"; do
      echo -e "${RED}The entry is not a valid IP address. Please Try again${TEXTRESET}"
      read -p "Please provide an upstream DNS IP for resolution: " DNSSERVER
    done

    # Validate DNSSEARCH
    read -p "Please provide the domain search name of your Active Directory: " DNSSEARCH
    while [ -z "$DNSSEARCH" ]; do
      echo -e "${RED}The response cannot be blank. Please Try again${TEXTRESET}"
      read -p "Please provide the domain search name: " DNSSEARCH
    done

    clear
    cat <<EOF
The following changes to the system will be configured:
IP address: ${GREEN}$IPADDR${TEXTRESET}
Gateway: ${GREEN}$GW${TEXTRESET}
DNS Search: ${GREEN}$DNSSEARCH${TEXTRESET}
DNS Server: ${GREEN}$DNSSERVER${TEXTRESET}
HOSTNAME: ${GREEN}$HOSTNAME${TEXTRESET}

EOF

    # Ask the user to confirm the changes
    read -p "Are these settings correct? (y/n): " CONFIRM
    if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
      nmcli con mod $INTERFACE ipv4.address $IPADDR
      nmcli con mod $INTERFACE ipv4.gateway $GW
      nmcli con mod $INTERFACE ipv4.method manual
      nmcli con mod $INTERFACE ipv4.dns-search $DNSSEARCH
      nmcli con mod $INTERFACE ipv4.dns $DNSSERVER
      hostnamectl set-hostname $HOSTNAME
      echo "/root/ADDCInstaller/DC1-Install.sh" >>/root/.bash_profile
      echo "The System must reboot for the changes to take effect."
      echo "${RED}Please log back in as root.${TEXTRESET}"
      echo "The installer will continue when you log back in."
      echo "If using SSH, please use the IP Address: $IPADDR"
      echo "${RED}Rebooting${TEXTRESET}"
      sleep 2
      reboot
      break
    else
      echo -e "${RED}Reconfiguring Interface${TEXTRESET}"
      sleep 2
      clear
    fi
  done
else
  echo -e "${GREEN}Interface $INTERFACE is using a static IP address${TEXTRESET}"
  sleep 2
fi
clear
if [ "$FQDN" = "localhost.localdomain" ]; then
  cat <<EOF
${RED}This system is still using the default hostname (localhost.localdomain)${TEXTRESET}

EOF
  # Validate HOSTNAME
    validate_fqdn() {
  local fqdn="$1"

  # Check if the FQDN is valid using a regular expression
  if [[ "$fqdn" =~ ^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$ ]]; then
    return 0
  else
    return 1
  fi
}

check_hostname_in_domain() {
  local fqdn="$1"
  local hostname="${fqdn%%.*}"
  local domain="${fqdn#*.}"

  # Check if the hostname is not the same as any part of the domain
  if [[ "$domain" =~ (^|\.)"$hostname"(\.|$) ]]; then
    return 1
  else
    return 0
  fi
}

read -p "Please provide the FQDN for this machine: " HOSTNAME

while ! validate_fqdn "$HOSTNAME" || ! check_hostname_in_domain "$HOSTNAME"; do
  echo -e "${RED}The entry is not a valid FQDN, or the hostname is repeated in the domain name (This is not Supported). Please Try again${TEXTRESET}"
  read -p "Please provide the FQDN for this machine: " HOSTNAME
done

  hostnamectl set-hostname $HOSTNAME
  cat <<EOF
The System must reboot for the changes to take effect.
${RED}Please log back in as root.${TEXTRESET}
The installer will continue when you log back in.
If using SSH, please use the IP Address: ${NMCLIIP}

EOF
  read -p "Press Enter to Continue"
  clear
  echo "/root/ADDCInstaller/DC1-Install.sh" >>/root/.bash_profile
  reboot
  exit

fi
clear
cat <<EOF
*********************************************
${GREEN}This will Install another AD Server to a pre-existing Forest/Domain${TEXTRESET}

Checklist:
Before the Installer starts, please make sure you have the following information

    1. ${YELLOW}THE FQDN of the Pre-existing DC ${TEXTRESET}
    2. ${YELLOW}An Administrator password${TEXTRESET} that you will use to join the domain
    3. ${YELLOW}An NTP Subnet${TEXTRESET} for your clients. This server will provide syncronized time
    4. The ${YELLOW}beginning and ending lease range${TEXTRESET} for DHCP (optional)
    5. The ${YELLOW}client default gateway IP Address${TEXTRESET} for the DHCP Scope (optional)
    6. A ${YELLOW}Friendly name${TEXTRESET} as a description to the DHCP scope created (optional



*********************************************
EOF
read -p "Press Any Key to Continue or Ctrl-C to exit the Installer"
clear

cat <<EOF
${GREEN}Samba AD/DC Setup${TEXTRESET}
EOF

while true; do
  read -p "Please provide the (pre-existing) AD Server FQDN that we will use to join the (pre-existing) domain: " ADDC

  while [ -z "$ADDC" ]; do
    echo -e "${RED}The response cannot be blank. Please try again${TEXTRESET}"
    read -p "Please provide the (pre-existing) AD Server FQDN that we will use to join the (pre-existing) domain: " ADDC
  done

  # Resolve the FQDN to an IP address
  IP_ADDRESS=$(dig +short "$ADDC" | head -n 1)

  # Check if we got an IP address
  if [ -z "$IP_ADDRESS" ]; then
    echo -e "${RED}Failed to resolve the FQDN to an IP address. Please check the server name and try again.${TEXTRESET}"
    read -p "Would you like to try again? (y/n): " TRY_AGAIN
    if [[ "$TRY_AGAIN" != "y" ]]; then
      exit 1
    else
      continue
    fi
  else
    echo -e "${GREEN}Name lookup successful. FQDN '$ADDC' resolved to IP address: $IP_ADDRESS${TEXTRESET}"
  fi

  # Ping the resolved IP address
  ping -c 1 "$IP_ADDRESS" &> /dev/null

  if [ $? -ne 0 ]; then
    echo -e "${RED}Ping test failed. Please check that the server is online and operational.${TEXTRESET}"
    read -p "Would you like to try again? (y/n): " TRY_AGAIN
    if [[ "$TRY_AGAIN" != "y" ]]; then
      exit 1
    else
      continue
    fi
  else
    echo -e "${GREEN}Ping successful.${TEXTRESET}"
  fi

  # Extract the domain from the FQDN
  DOMAIN="${ADDC#*.}"

  # Check SRV records for LDAP
  LDAP_SRV=$(host -t SRV _ldap._tcp."${DOMAIN}")
  if echo "$LDAP_SRV" | grep -q "$ADDC"; then
    echo -e "${GREEN}The server '$ADDC' is listed in the LDAP SRV records.${TEXTRESET}"
  else
    echo -e "${GREEN}The server '$ADDC' is NOT listed in the LDAP SRV records.${TEXTRESET}"
    read -p "Would you like to try again? (y/n): " TRY_AGAIN
    if [[ "$TRY_AGAIN" != "y" ]]; then
      exit 1
    else
      continue
    fi
  fi

  # Check SRV records for Kerberos
  KRB_SRV=$(host -t SRV _kerberos._udp."${DOMAIN}")
  if echo "$KRB_SRV" | grep -q "$ADDC"; then
    echo -e "${GREEN}The server '$ADDC' is listed in the Kerberos SRV records.${TEXTRESET}"
  else
    echo -e "${RED}The server '$ADDC' is NOT listed in the Kerberos SRV records.${TEXTRESET}"
    read -p "Would you like to try again? (y/n): " TRY_AGAIN
    if [[ "$TRY_AGAIN" != "y" ]]; then
      exit 1
    else
      continue
    fi
  fi

#  clear
  break
done
sleep 2
clear
# Function to validate CIDR format
validate_cidr() {
    local cidr="$1"
    # Check if the input matches the CIDR format
    if [[ $cidr =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
        # Extract the IP part and the prefix length
        local ip="${cidr%/*}"
        local prefix="${cidr#*/}"
        # Check if the IP is a valid network address (last octet should be 0 for /24, /16, etc.)
        local oIFS="$IFS"
        IFS='.' read -r -a octets <<< "$ip"
        IFS="$oIFS"
        # Calculate the subnet mask
        local mask=$((0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF))
        # Calculate the network address
        local network=$(((octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]))
        if (( (network & mask) == network )); then
            return 0
        fi
    fi
    return 1
}
cat <<EOF
${GREEN}NTP Setup${TEXTRESET}

EOF
read -p "Please provide the appropriate network scope in CIDR format (i.e 192.168.0.0/16) to allow NTP for clients: " NTPCIDR

# Validate the input
while ! validate_cidr "$NTPCIDR"; do
    echo -e "${RED}Invalid input. Please enter a valid network address in CIDR format.${TEXTRESET}"
    read -p "Please provide the appropriate network scope in CIDR format (i.e 192.168.0.0/16) to allow NTP for clients: " NTPCIDR
done
echo "Valid network scope provided: $NTPCIDR"
echo ${GREEN}Saving and Restarting Service${TEXTRESET}
sed -i "/#allow /c\allow $NTPCIDR" /etc/chrony.conf
systemctl restart chronyd
sleep 2
clear
#OPTIONAL DHCP Installation
cat <<EOF
${GREEN}DHCP Server Setup${TEXTRESET}

This server can be a DHCP server to service clients.
The installer will prompt you to create a default declaration for its interface
If you want to add additional scopes, use Server Management after installation

EOF

read -r -p "Would you like to install/enable DHCP and create a default scope? [y/N]" -n 1
echo # (optional) move to a new line
if [[ "$REPLY" =~ ^[Yy]$ ]]; then
  echo ${GREEN}"Installing DHCP Server${TEXTRESET}"
  sleep 1
  dnf -y install dhcp-server
  firewall-cmd --zone=public --add-service dhcp --permanent
  clear

# Get the first active network interface
active_interface=$(nmcli -t -f DEVICE,STATE device status | grep ':connected' | cut -d: -f1 | head -n 1)
if [ -z "$active_interface" ]; then
  echo "No active network interface found."
  echo "Exiting"
  exit 1
fi

# Extract the inet4 address for the active interface
inet4_line=$(nmcli -g IP4.ADDRESS device show "$active_interface" | head -n 1)
if [ -n "$inet4_line" ]; then
  # Extract the IP and CIDR
  INET4=$(echo "$inet4_line" | cut -d'/' -f1)
  DHCPCIDR=$(echo "$inet4_line" | cut -d'/' -f2)
else
  echo "No inet4 address found for interface $active_interface."
  echo "Exiting"
  exit
fi

# Function to calculate the network address
calculateNetworkAddress() {
  local ip=$1
  local cidr=$2
  local mask=$(( 0xFFFFFFFF << (32 - cidr) ))
  local ipnum=$(ipToNumber "$ip")
  local netnum=$(( ipnum & mask ))
  echo "$(( (netnum >> 24) & 0xFF )).$(( (netnum >> 16) & 0xFF )).$(( (netnum >> 8) & 0xFF )).$(( netnum & 0xFF ))"
}

# Function to calculate the broadcast address
calculateBroadcastAddress() {
  local ip=$1
  local cidr=$2
  local mask=$(( 0xFFFFFFFF << (32 - cidr) ))
  local ipnum=$(ipToNumber "$ip")
  local broadcastnum=$(( ipnum | ~mask ))
  echo "$(( (broadcastnum >> 24) & 0xFF )).$(( (broadcastnum >> 16) & 0xFF )).$(( (broadcastnum >> 8) & 0xFF )).$(( broadcastnum & 0xFF ))"
}
# Function to convert IP address to a number
ipToNumber() {
  local ip=$1
  IFS=. read -r o1 o2 o3 o4 <<< "$ip"
  echo $(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))
}
# Calculate network and broadcast addresses
NETWORK=$(calculateNetworkAddress "$INET4" "$DHCPCIDR")
BROADCAST=$(calculateBroadcastAddress "$INET4" "$DHCPCIDR")

# Function to check if an IP is within a network range
isIPInRange() {
  local ip=$1
  local networknum=$(ipToNumber "$NETWORK")
  local broadcastnum=$(ipToNumber "$BROADCAST")
  local ipnum=$(ipToNumber "$ip")
  [[ $ipnum -ge $networknum && $ipnum -le $broadcastnum ]]
}
  # Function to validate IP address format
isValidIP() {
    local ip=$1
    # Regular expression to match valid IPv4 address
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    # Check if each octet is less than or equal to 255
    IFS=. read -r o1 o2 o3 o4 <<< "$ip"
    (( o1 <= 255 && o2 <= 255 && o3 <= 255 && o4 <= 255 )) || return 1

    return 0
}
# Function to validate netmask format
isValidNetmask() {
    local netmask=$1
    # List of valid netmask values
    local valid_netmasks=(
        "255.255.255.255" "255.255.255.254" "255.255.255.252" "255.255.255.248"
        "255.255.255.240" "255.255.255.224" "255.255.255.192" "255.255.255.128"
        "255.255.255.0"   "255.255.254.0"   "255.255.252.0"   "255.255.248.0"
        "255.255.240.0"   "255.255.224.0"   "255.255.192.0"   "255.255.128.0"
        "255.255.0.0"     "255.254.0.0"     "255.252.0.0"     "255.248.0.0"
        "255.240.0.0"     "255.224.0.0"     "255.192.0.0"     "255.128.0.0"
        "255.0.0.0"       "254.0.0.0"       "252.0.0.0"       "248.0.0.0"
        "240.0.0.0"       "224.0.0.0"       "192.0.0.0"       "128.0.0.0"
        "0.0.0.0"
    )
    
    for valid in "${valid_netmasks[@]}"; do
        if [[ "$netmask" == "$valid" ]]; then
            return 0
        fi
    done

    return 1
}

# Function to validate the user inputs
validate_input() {
  # Prompt user for beginning IP address and validate
  while true; do
     echo ${GREEN}Configure DHCP Scope${TEXTRESET}
     read -p "Please provide the beginning IP address in the lease range (based on the network $NETWORK): " DHCPBEGIP
    if [ -z "$DHCPBEGIP" ]; then
      echo -e "${RED}The response cannot be blank. Please try again.${TEXTRESET}"
    elif ! isValidIP "$DHCPBEGIP"; then
      echo -e "${RED}Invalid IP format. Please provide a valid IP address.${TEXTRESET}"
    elif ! isIPInRange "$DHCPBEGIP"; then
      echo -e "${RED}IP is not within the network range $NETWORK/$DHCPCIDR. Please provide a valid IP address.${TEXTRESET}"
    else
      break
    fi
  done

  # Prompt user for ending IP address and validate
  while true; do
    read -p "Please provide the ending IP address in the lease range (based on the network $NETWORK): " DHCPENDIP
    if [ -z "$DHCPENDIP" ]; then
      echo -e "${RED}The response cannot be blank. Please try again.${TEXTRESET}"
    elif ! isValidIP "$DHCPENDIP"; then
      echo -e "${RED}Invalid IP format. Please provide a valid IP address.${TEXTRESET}"
    elif ! isIPInRange "$DHCPENDIP"; then
      echo -e "${RED}IP is not within the network range $NETWORK/$DHCPCIDR. Please provide a valid IP address.${TEXTRESET}"
    else
      break
    fi
  done

  # Prompt user for netmask and validate
  while true; do
    read -p "Please provide the netmask for clients: " DHCPNETMASK
    if [ -z "$DHCPNETMASK" ]; then
      echo -e "${RED}The response cannot be blank. Please try again.${TEXTRESET}"
    elif ! isValidNetmask "$DHCPNETMASK"; then
      echo -e "${RED}Invalid netmask format. Please provide a valid netmask (e.g., 255.255.255.0).${TEXTRESET}"
    else
      break
    fi
  done

  # Prompt user for default gateway and validate
  while true; do
    read -p "Please provide the default gateway for clients: " DHCPDEFGW
    if [ -z "$DHCPDEFGW" ]; then
      echo -e "${RED}The response cannot be blank. Please try again.${TEXTRESET}"
    elif ! isValidIP "$DHCPDEFGW"; then
      echo -e "${RED}Invalid IP format. Please provide a valid IP address.${TEXTRESET}"
    else
      break
    fi
  done

  # Prompt user for subnet description and ensure it's not blank
  while true; do
    read -p "Please provide a description for this subnet: " SUBNETDESC
    if [ -z "$SUBNETDESC" ]; then
      echo -e "${RED}The response cannot be blank. Please try again.${TEXTRESET}"
    else
      break
    fi
  done
}

# Main loop to ask for settings and confirmation
while true; do
  # Gather user input
  validate_input

  # Display the configuration
clear
  cat <<EOF
The script will configure DHCP with these settings:

SUBNET: ${GREEN}$NETWORK${TEXTRESET}
BEGINNING IP RANGE: ${GREEN}$DHCPBEGIP${TEXTRESET}
ENDING IP RANGE: ${GREEN}$DHCPENDIP${TEXTRESET}
NETMASK: ${GREEN}$DHCPNETMASK${TEXTRESET}
DEFAULT GW: ${GREEN}$DHCPDEFGW${TEXTRESET}
SCOPE FRIENDLY NAME: ${GREEN}$SUBNETDESC${TEXTRESET}
NTP: ${GREEN}${IP}${TEXTRESET}
DOMAIN NAME: ${GREEN}${DHCPNSNAME}${TEXTRESET}
DOMAIN SEARCH: ${GREEN}${DHCPNSNAME}${TEXTRESET}

EOF

  # Ask the user if the settings are okay
  read -p "Are these settings correct? (yes/no): " CONFIRM
  if [[ "$CONFIRM" =~ ^[Yy][Ee][Ss]$ || "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo " "
    echo ${GREEN}"Deploying DHCP Server"${TEXTRESET}
    sleep 1
    break
  else
    echo " "
    echo ${GREEN}"Re-Running DHCP Scope Creation"${TEXTRESET}
    sleep 1
    clear 
  fi
done

  #Configure DHCP
  mv /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.orig

  cat <<EOF >/etc/dhcp/dhcpd.conf

authoritative;
allow unknown-clients;
option ntp-servers ${IP};
option time-servers ${IP};
option domain-name-servers ${IP};
option domain-name "${DHCPNSNAME}";
option domain-search "${DHCPNSNAME}";


#$SUBNETDESC
subnet ${SUBNETNETWORK} netmask ${DHCPNETMASK} {
        range ${DHCPBEGIP} ${DHCPENDIP};
        option subnet-mask ${DHCPNETMASK};
        option routers ${DHCPDEFGW};
}
EOF
echo ${GREEN}"Starting DHCP Services"${TEXTRESET}
  systemctl enable dhcpd
  systemctl start dhcpd

fi
# Define the service name
SERVICE_NAME="dhcpd"

# Function to check the status of the DHCP service
check_dhcp_service() {
  # Check if the service is active
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo ${GREEN}"The DHCP service ($SERVICE_NAME) is running."${TEXTRESET}
    return 0
  else
    echo ${RED}"The DHCP service ($SERVICE_NAME) is NOT running."${TEXTRESET}
    echo "Please validate your configuration before expecting DHCP to Service clients"
    read -p "Press Enter"
    return 1
  fi
}

# Execute the function
check_dhcp_service

sleep 2

clear
#Add option for cockpit install
cat <<EOF
${GREEN}Install Cockpit${TEXTRESET}
Cockpit is a server administration tool, focused on providing a modern-looking 
and user-friendly interface to manage and administer servers.
EOF

read -r -p "Would you like to install Cockpit for web based administration? [y/N]" -n 1
echo # (optional) move to a new line
if [[ "$REPLY" =~ ^[Yy]$ ]]; then

    echo ${YELLOW}"Your cockpit instance can be accessed at ${FQDN}:9090"${TEXTRESET}
    sleep 5
    dnf -y install cockpit cockpit-storaged
    systemctl enable cockpit.socket
    systemctl start cockpit.socket
fi
clear
cat <<EOF
${GREEN}Deploying the server with these settings${TEXTRESET}

The installer will deploy Samba AD with the following information:

DOMAIN to Join: ${GREEN}$DOMAIN${TEXTRESET}
NTP Client Scope: ${GREEN}$NTPCIDR${TEXTRESET}



EOF
read -p "Press any Key to continue or Ctrl-C to Exit"
clear

#Checking for VM platform-Install client
echo ${GREEN}"Installing VMGuest${TEXTRESET}"
if [ "$HWKVM" = "KVM" ]; then
  echo ${GREEN}"KVM Platform detected ${TEXTRESET}"
  echo "Installing qemu-guest-agent"
  sleep 1
  dnf -y install qemu-guest-agent
else
  echo "Not KVM Platform"
fi

#Checking for VM platform-Install client
if [ "$HWVMWARE" = "VMware" ]; then
  echo ${GREEN}"VMWARE Platform detected ${TEXTRESET}"
  echo "Installing open-vm-tools"
  sleep 1
  dnf -y install open-vm-tools
else
  echo "Not VMware Platform"
fi
clear
#If this server got DHCP, and there is an NTP server option, we must change it to a pool
sed -i "/pool /c\server ${ADDC} iburst" /etc/chrony.conf
sed -i "/server /c\server ${ADDC} iburst" /etc/chrony.conf
sed -i "/#allow /c\allow ${NTPCIDR}" /etc/chrony.conf
systemctl restart chronyd
clear
echo ${YELLOW}"Syncronizing time, Please wait${TEXTRESET}"
sleep 10s
clear
chronyc tracking

# Function to check if the system time is synchronized
check_time_sync() {
  # Run the chronyc tracking command and capture the output
  output=$(chronyc tracking)

  # Check if the output indicates the time is synchronized
  if echo "$output" | grep -q "Leap status     : Normal"; then
    echo ${GREEN}"The system time is synchronized."${TEXTRESET}
    return 0
  else
    echo ${RED}"The system time is NOT synchronized"${TEXTRESET}
    return 1
  fi
}

# Execute the function
check_time_sync

# Check the result and prompt the user if not synchronized
if [ $? -ne 0 ]; then
  echo ""
  while true; do
    read -p "Do you want to continue with the installation? (yes/no): " user_response
    case $user_response in
      [Yy][Ee][Ss]|[Yy])
        echo ${GREEN}"Continuing with the installation..."${TEXTRESET}
        break
        ;;
      [Nn][Oo]|[Nn])
        echo ${RED}"Installation aborted due to unsynchronized time."${TEXTRESET}
        exit 1
        ;;
      *)
        echo "Please enter yes or no."
        ;;
    esac
  done
fi
sleep 2


clear
#Set selinux contexts
setsebool -P samba_create_home_dirs=on \
  samba_domain_controller=on \
  samba_enable_home_dirs=on \
  samba_portmapper=on \
  use_samba_home_dirs=on
#Apply Firewall Rules
cat <<EOF
Updating Firewall Rules
EOF
firewall-cmd --permanent --add-service samba-dc
firewall-cmd --permanent --add-service ntp
firewall-cmd --complete-reload
systemctl restart firewalld
clear
echo ${GREEN}"These are the services/ports now open on the server${TEXTRESET}"
firewall-cmd --list-all
echo "The Installer will continue in a moment or Press Ctrl-C to Exit"
sleep 8s
clear
cat <<EOF
${GREEN}Downloading and compiling the Samba source from Rocky --with dc${TEXTRESET}
${YELLOW}This may take approximately 20-30 minutes${TEXTRESET}
EOF
sleep 4s
dnf -y install ntsysv nano bind-utils
dnf -y update
# Initial build
dnf install epel-release createrepo -y
crb enable
dnf install mock -y

dnf download samba --source
# Validate the downloaded RPM file
if ls /root/samba-*.rpm 1> /dev/null 2>&1; then
    echo "${GREEN}Samba RPM file found. Continuing with the script...${TEXTRESET}"
else
    echo "${RED}The Samba source rpm file did not download correctly. Please check your network settings.${TEXTRESET}"
    echo "Exiting..."
    exit 1
fi

mock -r rocky-"$MAJOROS"-x86_64 --enablerepo=devel --define 'dist .el'"$MAJOROS"'_'"$MINOROS"'.dc' --with dc "$MOCKSMBVER"src.rpm
mkdir /root/.samba
cp /var/lib/mock/rocky-"$MAJOROS"-x86_64/result/*.rpm /root/.samba
createrepo /root/.samba
dnf config-manager --add-repo /root/.samba
dnf -y install --nogpgcheck samba-dc samba-client krb5-workstation samba \
  --repofrompath=samba,/root/.samba \
  --enablerepo=samba
#Move smb.conf file
mv -f /etc/samba/smb.conf /etc/samba/smb.bak.orig

#Create KDC:
#sed -i '12i \       \ dns_lookup_kdc = true' /etc/krb5.conf
#sed -i "s/#    default_realm = EXAMPLE.COM/default_realm = ${DOMAIN}/" /etc/krb5.conf

#Provision Domain
cat <<EOF
Joining the Domain

EOF
read -p "Press Any Key when Ready"
samba-tool domain join ${DOMAIN} DC -U "${ADDOMAIN}\administrator"
read -p "Press Any Key"

#Set DNS resolver
nmcli con mod $INTERFACE ipv4.dns $IP
systemctl restart NetworkManager

#Copy KDC:
\cp -rf /var/lib/samba/private/krb5.conf /etc/krb5.conf

#Add support for FreeRADIUS
sed -i '7i \       \ #Added for FreeRADIUS Support' /etc/samba/smb.conf
sed -i '8i \       \ ntlm auth = mschapv2-and-ntlmv2-only' /etc/samba/smb.conf

#Allow plain LDAP binds
sed -i '9i \       \#ldap server require strong auth = no #UNCOMMENT THIS IF YOU NEED PLAIN LDAP BIND (non-TLS)' /etc/samba/smb.conf
sed -i '10i \       \dns forwarder = 208.67.222.222' /etc/samba/smb.conf

#ADD cron for monitoring of REPOS
touch /var/log/dnf-smb-mon.log
chmod 700 /root/ADDCInstaller/dnf-smb-mon
\cp /root/ADDCInstaller/dnf-smb-mon /usr/bin
(
  crontab -l
  echo "0 */6 * * * /usr/bin/dnf-smb-mon"
) | sort -u | crontab -
systemctl restart crond

#ADD samba-dnf-package update
chmod 700 /root/ADDCInstaller/samba-dnf-pkg-update
\cp /root/ADDCInstaller/samba-dnf-pkg-update /usr/bin
systemctl enable samba --now
clear

#Update /etc/issue so we can see the hostname and IP address Before logging in
rm -r -f /etc/issue
touch /etc/issue
cat <<EOF >/etc/issue
\S
Kernel \r on an \m
Hostname: \n
IP Address: \4
EOF

#Run tests to validate Samba Install
cat <<EOF
${GREEN}Validation${TEXTRESET}

The server will now test 
  -Kerberos (Ticket)
  -Authenticated Logins
  -DNS SRV Records 
  -Anonymous Logins
  



EOF
read -p "Press any key to continue"
clear

cat <<EOF
${GREEN}Kerberos${TEXTRESET}
Login with the Administrator password you created earlier for the domain
EOF
kinit Administrator
echo ${GREEN}
klist
echo ${TEXTRESET}
echo "The Installer will continue in a moment or Press Ctrl-C to Exit"
sleep 5s
clear

cat <<EOF
${GREEN}Verifying Authentication Login:${TEXTRESET}
EOF
# Function to check the status of the Samba service
check_samba_service() {
  echo "Checking Samba service status..."
  samba_status=$(systemctl is-active samba)
  if [ "$samba_status" = "active" ]; then
    echo "Samba service is running."
    return 0
  else
    echo "${RED}Error:${TEXTRESET} Samba service is not running. Status: $samba_status"
    return 1
  fi
}

# Function to attempt connection using smbclient
attempt_connection() {
  echo "Attempting to connect to //localhost/netlogon with user Administrator..."
  smbclient //localhost/netlogon -UAdministrator -c 'ls'
  sleep 4
}

# Main script execution
if check_samba_service; then
  # If the service is running, prompt the user to attempt the connection
  attempt_connection
else
  echo "${RED}Error:${TEXTRESET} Authenticated logins are not available because the Samba service is not running."
  exit 1
fi
clear


cat <<EOF
${GREEN}Checking DNS SRV Records${TEXTRESET}

EOF

# Validate that the server can resolve SRV records
echo "${GREEN}Setting up Query for SRV records${TEXTRESET}"
sleep 1
host -t SRV _ldap._tcp."${DOMAIN}"
host -t SRV _kerberos._udp."${DOMAIN}"
host -t A "${FQDN}"

# Extract hostname from FQDN
hostname_part=$(echo "$FQDN" | cut -d '.' -f 1)

# Function to extract the target hostnames from SRV records
get_srv_hostnames() {
  local srv_records=$1
  echo "$srv_records" | awk '{print $NF}' | cut -d '.' -f 1 # Get the last field and extract the hostname part
}

# Get SRV records for LDAP and Kerberos
ldap_srv=$(host -t SRV _ldap._tcp."$DOMAIN")
kerberos_srv=$(host -t SRV _kerberos._udp."$DOMAIN")

# Extract target hostnames from SRV records
ldap_hostnames=$(get_srv_hostnames "$ldap_srv")
kerberos_hostnames=$(get_srv_hostnames "$kerberos_srv")

# Function to check if at least one hostname matches
check_any_hostnames_match() {
  local hostnames=$1
  local hostname=$2
  for hn in $hostnames; do
    if [ "$hn" == "$hostname" ]; then
      echo "At least one hostname matches: ${GREEN}$hn${TEXTRESET}"
      return 0
    fi
  done
  return 1
}

# Check if any LDAP or Kerberos hostnames match the hostname part of FQDN
if check_any_hostnames_match "$ldap_hostnames" "$hostname_part" || check_any_hostnames_match "$kerberos_hostnames" "$hostname_part"; then
  echo "${GREEN}Success:${TEXTRESET} Hostname from SRV record matches.."
  echo ${YELLOW}"AD is resolvable"${TEXTRESET}
  echo "Proceeding..."
  sleep 5
  exit_status=0
else
  echo "${RED}Error:${TEXTRESET} No hostnames from SRV records match the hostname part of FQDN. The Samba service has failed to start or DNS is not configured correctly."
  echo "AD Failed to resolve. Make sure the Samba service is running and that the DNS entry on this server is pointed to the local interface (Not loopback)."
  
  # Check the status of the Samba service
  echo "Checking Samba service status..."
  samba_status=$(systemctl is-active samba)
  if [ "$samba_status" = "active" ]; then
    echo ${GREEN}"Samba service is running."${TEXTRESET}
  else
    echo ${RED}"Samba service is not running. Status: $samba_status"${TEXTRESET}
  fi

  # Check DNS server entry
  echo "Checking DNS server entry using nmcli..."
  dns_entry=$(nmcli dev show | grep DNS)
  echo "DNS server entries:"
  echo ${YELLOW}"$dns_entry"${TEXTRESET}

  exit 1
fi

clear

cat <<EOF
${GREEN}Testing anonymous Logins to the server${TEXTRESET}

EOF
# Run the smbclient command
output=$(smbclient -L localhost -N 2>&1)

# Check for success or specific failure
if echo "$output" | grep -q "Anonymous login successful"; then
  echo "${GREEN}Success:${TEXTRESET} Anonymous login successful."
  sleep 5
  # Continue with further operations if needed
  # Add further operations or commands here
else
  echo "${RED}Error:${TEXTRESET} Anonymous logins are not available."
  echo "Error details: $output"

  # Check the status of the Samba service
  echo "Checking Samba service status..."
  samba_status=$(systemctl is-active samba)
  if [ "$samba_status" = "active" ]; then
    echo ${GREEN}"Samba service is running."${TEXTRESET}
  else
    echo ${YELLOW}"Samba service is not running.${TEXTRESET} Status: ${RED}$samba_status"${TEXTRESET}
  fi

  exit 1
fi
clear


echo ${GREEN}"Installation is successful"${TEXTRESET}
sleep 4
clear

cat <<EOF
${GREEN}Providing replication Status${TEXTRESET}
EOF
sleep 2
samba-tool drs showrepl | more
sleep 1s
clear

echo "If all tests returned valid, installation is successful"
sleep 4
clear

cat <<EOF
${GREEN}********************************
  Server Installation Complete
********************************${TEXTRESET}

The Installer will continue in a moment

${YELLOW}Getting Ready to install Server Management${TEXTRESET}

EOF

sleep 5

#Cleanup RADS Install Files
sed -i '/DC1-Install.sh/d' /root/.bash_profile
rm -r -f /root/DC-Installer.sh
rm -r -f /root/ADDCInstaller
rm -f /root/samba*.src.rpm
rm -r -f /root/FR-Installer
rm -r -f /root/FR-Installer.sh

cat <<EOF
${GREEN}******************************
Installing Server Management
******************************${TEXTRESET}

EOF

cd /root/
dnf -y install wget
wget https://raw.githubusercontent.com/fumatchu/RADS-SM/main/RADS-FirstInstaller.sh
chmod 700 ./RADS-FirstInstaller.sh
/root/RADS-FirstInstaller.sh
