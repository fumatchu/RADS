#!/bin/bash
#DC-install.sh
#This script installs the FIRST Samba AD with DC support using mock from Upstream Rocky REPO via src.rpm
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
dnf -y install net-tools dmidecode ipcalc
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
    read -p "Please provide the FQDN for this machine: " HOSTNAME
    while ! validate_fqdn "$HOSTNAME"; do
      echo -e "${RED}The entry is not a valid FQDN. Please Try again${TEXTRESET}"
      read -p "Please provide the FQDN for this machine: " HOSTNAME
    done

    # Validate DNSSERVER
    read -p "Please provide an upstream DNS IP for resolution: " DNSSERVER
    while ! validate_ip "$DNSSERVER"; do
      echo -e "${RED}The entry is not a valid IP address. Please Try again${TEXTRESET}"
      read -p "Please provide an upstream DNS IP for resolution: " DNSSERVER
    done

    # Validate DNSSEARCH
    read -p "Please provide the domain search name: " DNSSEARCH
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
      echo "/root/ADDCInstaller/DCInstall.sh" >>/root/.bash_profile
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
  read -p "Please provide a valid FQDN for this machine: " HOSTNAME
  while [ -z "$HOSTNAME" ]; do
    echo ${RED}"The response cannot be blank. Please Try again${TEXTRESET}"
    read -p "Please provide a valid FQDN for this machine: " HOSTNAME
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
  echo "/root/ADDCInstaller/DCInstall.sh" >>/root/.bash_profile
  reboot
  exit

fi
clear
cat  <<EOF
*********************************************
${GREEN}This will Install the FIRST AD Server and build a new Forest/Domain${TEXTRESET}

Checklist:
Before the Installer starts, please make sure you have the following information

    1. ${YELLOW}An Administrator password${TEXTRESET} that you want to use for the new DOMAIN
    2. ${YELLOW}An NTP Subnet${TEXTRESET} for your clients. This server will provide syncronized time
    3. The ${YELLOW}beginning and ending lease range${TEXTRESET} for DHCP (optional)
    4. The ${YELLOW}client default gateway IP Address${TEXTRESET} for the DHCP Scope (optional)
    5. A ${YELLOW}Friendly name${TEXTRESET} as a description to the DHCP scope created (optional)
    
     

*********************************************
EOF
read -p "Press Any Key to Continue or Ctrl-C to exit the Installer"
clear

cat <<EOF
${GREEN}Samba AD/DC Password Setup${TEXTRESET}

The Administrator Domain Password should meet the following requirements:
-At least 8 characters
-(1) Special Character
-(1) Upper-Case Letter
-(1) Lower-Case Letter
-(1) Number

EOF
while :
do
read -p "Please provide the Administrator Password to use for AD/DC Provisioning: " ADMINPASS
while [ -z "$ADMINPASS" ]; do
    echo ${RED}"The response cannot be blank. Please Try again${TEXTRESET}"
     read -p "Please provide the Administrator Password to use for AD/DC Provisioning: " ADMINPASS
  done
# Check password length
  if [ ${#ADMINPASS} -lt 8 ]; then
    echo "${RED}Weak:${TEXTRESET} Password is too short (less than 8 characters)"
   read -p "Please provide the Administrator Password to use for AD/DC Provisioning: " ADMINPASS
  fi
  # Check for the presence of numbers
  if ! [[ "$ADMINPASS" =~ [0-9] ]]; then
    echo "${RED}Weak:${TEXTRESET} Password must contain at least one number"
   read -p "Please provide the Administrator Password to use for AD/DC Provisioning: " ADMINPASS
  fi
  # Check for the presence of special characters
  if ! [[ "$ADMINPASS" =~ [!@#\$%^*] ]]; then
    echo "${RED}Weak:${TEXTRESET} Password must contain at least one special character (!@#\$%^&*)"
  read -p "Please provide the Administrator Password to use for AD/DC Provisioning: " ADMINPASS
  fi
  # Check for uppercase and lowercase letters
  if ! [[ "$ADMINPASS" =~ [a-z] && "$ADMINPASS" =~ [A-Z] ]]; then
    echo "${RED}Weak:${TEXTRESET} Password must contain both uppercase and lowercase letters"
    read -p "Please provide the Administrator Password to use for AD/DC Provisioning: " ADMINPASS
  fi
  read -p "Please provide the password again for AD/DC Provisioning: " VERIFYPASS
 while [ -z "$VERIFYPASS" ]; do
     echo ${RED}"The response cannot be blank. Please Try again${TEXTRESET}"
      read -p "Please provide the password again for AD/DC Provisioning: " VERIFYPASS
   done

if [ "${ADMINPASS}" = "${VERIFYPASS}" ]
then
 echo "${GREEN}Saving Password${TEXTRESET}"
 sleep 1
 break;
fi 
echo "${RED}Password does not match.${TEXTRESET} Please try again."
sleep 1
done

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
  # Output the results
  echo "INET4 Address: $INET4"
  echo "DHCPCIDR: $DHCPCIDR"
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

# Prompt user for beginning IP address and validate
while true; do
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

cat <<EOF
The Install will configure DHCP with these settings:
SUBNET:${GREEN}$NETWORK${TEXTRESET}
BEGINNING IP RANGE:${GREEN}$DHCPBEGIP${TEXTRESET}
ENDING IP RANGE: ${GREEN}$DHCPENDIP${TEXTRESET}
NETMASK: ${GREEN}$DHCPNETMASK${TEXTRESET}
DEFAULT GW: ${GREEN}$DHCPDEFGW${TEXTRESET}
SCOPE FRIENDLY NAME: ${GREEN}$SUBNETDESC${TEXTRESET}
NTP: ${GREEN}${IP}${TEXTRESET}
DOMAIN NAME: ${GREEN}${DHCPNSNAME}${TEXTRESET}
DOMAIN SEARCH: ${GREEN}${DHCPNSNAME}${TEXTRESET}
EOF
read -p "Press Enter"

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

  systemctl enable dhcpd
  systemctl start dhcpd

fi

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
Hostname:${GREEN}$HOSTNAME${TEXTRESET}
REALM: ${GREEN}$DOMAIN${TEXTRESET}
DOMAIN: ${GREEN}$ADDOMAIN${TEXTRESET}
Administrator Password: ${GREEN}$ADMINPASS${TEXTRESET}
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
#Set hostname
hostnamectl set-hostname $HOSTNAME
#If this server got DHCP, and there is an NTP server option, we must change it to a pool
sed -i '/server /c\pool 2.rocky.pool.ntp.org iburst' /etc/chrony.conf
sed -i "/#allow /c\allow $NTPCIDR" /etc/chrony.conf
systemctl restart chronyd
clear
echo ${RED}"Syncronizing time, Please wait${TEXTRESET}"
sleep 10s
clear
chronyc tracking
cat <<EOF
${GREEN}We should be syncing time${TEXTRESET}

The Installer will continue in a moment or Press Ctrl-C to Exit
EOF
sleep 5s
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
mock -r rocky-"$MAJOROS"-x86_64 --enablerepo=devel --define 'dist .el'"$MAJOROS"'_'"$MINOROS"'.dc' --with dc "$MOCKSMBVER"src.rpm
mkdir /root/.samba
cp /var/lib/mock/rocky-"$MAJOROS"-x86_64/result/*.rpm /root/.samba
createrepo /root/.samba
#dnf config-manager --add-repo /root/.samba
dnf -y install --nogpgcheck samba-dc samba-client krb5-workstation samba \
  --repofrompath=samba,/root/.samba \
  --enablerepo=samba
#Move smb.conf file
mv -f /etc/samba/smb.conf /etc/samba/smb.bak.orig
#Provision Domain
samba-tool domain provision \
  --realm="$DOMAIN" \
  --domain="$ADDOMAIN" \
  --adminpass="$ADMINPASS"

#Copy KDC:
\cp -rf /var/lib/samba/private/krb5.conf /etc/krb5.conf

#Set DNS resolver
nmcli con mod $INTERFACE ipv4.dns $IP
systemctl restart NetworkManager

#Add support for FreeRADIUS
sed -i '8i \       \ #Added for FreeRADIUS Support' /etc/samba/smb.conf
sed -i '9i \       \ ntlm auth = mschapv2-and-ntlmv2-only' /etc/samba/smb.conf

#Allow plain LDAP binds
sed -i '10i \       \#ldap server require strong auth = no #UNCOMMENT THIS IF YOU NEED PLAIN LDAP BIND (non-TLS)' /etc/samba/smb.conf

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
  -DNS SRV Records 
  -Anonymous Logins
  -Authenticated Logins



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
sleep 10s
clear

cat <<EOF
${GREEN}Checking DNS SRV Records${TEXTRESET}

Testing _ldap._tcp
Example Result:
${YELLOW}_ldap._tcp.samdom.example.com has SRV record 0 100 389 dc1.samdom.example.com.${TEXTRESET}

The actual result is:
EOF
echo ${GREEN}
host -t SRV _ldap._tcp.${DOMAIN}.
echo ${TEXTRESET}

cat <<EOF
Testing _udp kerberos
Example Result:
${YELLOW}_kerberos._udp.samdom.example.com has SRV record 0 100 88 dc1.samdom.example.com.${TEXTRESET}

The actual result is:
EOF
echo ${GREEN}
host -t SRV _kerberos._udp.${DOMAIN}.
echo ${TEXTRESET}

cat <<EOF

Testing A Record of Domain Controller
Example Result:
${YELLOW}dc1.samdom.example.com has address 10.99.0.1${TEXTRESET}

The actual result is:
EOF
echo ${GREEN}
host -t A $FQDN.
echo ${TEXTRESET}
cat <<EOF

The Installer will continue in a moment or Press Ctrl-C to Exit
EOF
sleep 20s
clear

cat <<EOF
${GREEN}Testing anonymous Logins to the server${TEXTRESET}
EOF
smbclient -L localhost -N
sleep 8s
clear

cat <<EOF
${GREEN}Verifying Authentication Login:${TEXTRESET}
EOF
smbclient //localhost/netlogon -UAdministrator -c 'ls'
sleep 8
clear
echo "If all tests returned valid, installation is successful"
sleep 4
clear

cat <<EOF
${GREEN} Add a reverse zone for the first subnet${TEXTRESET}

A reverse zone should be added to DNS.
Based on your configuration, and assuming a Class C subnet, your command should be:

${GREEN}samba-tool dns zonecreate $FQDN $REVERSE.in-addr.arpa -U Administrator ${TEXTRESET}

EOF

#Add reverse zone to AD for bound IP Range
read -r -p "Would you like to add this reverse zone now? [y/N]" -n 1
echo # (optional) move to a new line
if [[ "$REPLY" =~ ^[Yy]$ ]]; then
  echo "Adding Entry, Please provde the Domain Administrator password"
  samba-tool dns zonecreate $FQDN $REVERSE.in-addr.arpa -U Administrator
fi

clear

#If this is a Lab, reduce password complexity
cat <<EOF
${GREEN}Relax Passwords if in Lab Setting${TEXTRESET}

You may want to reduce the password requirements 
for this system if you are using it in a lab. 
A sane set of options are:

samba-tool domain passwordsettings set --complexity=off
samba-tool domain passwordsettings set --history-length=0
samba-tool domain passwordsettings set --min-pwd-age=0
samba-tool domain passwordsettings set --max-pwd-age=0

EOF

read -r -p "Would you like to change these password settings? [y/N]" -n 1
echo # (optional) move to a new line
if [[ "$REPLY" =~ ^[Yy]$ ]]; then
  echo "Modifying Password Settings"
  samba-tool domain passwordsettings set --complexity=off
  samba-tool domain passwordsettings set --history-length=0
  samba-tool domain passwordsettings set --min-pwd-age=0
  samba-tool domain passwordsettings set --max-pwd-age=0
fi

clear
cat <<EOF
${GREEN}Setting up Your First User ${TEXTRESET}
To setup your first user, use the Active Directory Management Module in Server Management
This will be installed in the next step
EOF
sleep 3
cat <<EOF

${GREEN}********************************
    Server Installation Complete
********************************${TEXTRESET}

The Installer will continue in a moment

${YELLOW}Getting Ready to install Server Management${TEXTRESET}

EOF

sleep 5

#Cleanup RADS Install Files
sed -i '/DCInstall.sh/d' /root/.bash_profile
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
