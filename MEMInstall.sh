#!/bin/bash
#MEMinstall.sh
#This installer will install a member server to a pre-existing domain
clear
dnf -y install net-tools dmidecode
TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
INTERFACE=$(nmcli | grep "connected to" | cut -c22-)
FQDN=$(hostname)
IP=$(hostname -I)
FQDN=$(hostname)
DOMAIN=$(hostname | sed 's/^[^.:]*[.:]//' | sed -e 's/\(.*\)/\U\1/')
ADDOMAIN=$(hostname | sed 's/^[^.:]*[.:]//' | cut -d. -f1 | sed -e 's/\(.*\)/\U\1/')
USER=$(whoami)
MAJOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')
DETECTIP=$(nmcli -f ipv4.method con show $INTERFACE)
NMCLIIP=$(nmcli | grep inet4 | sed '$d' | cut -c7- | cut -d / -f1)
HWKVM=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep KVM | cut -c16-)
HWVMWARE=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep Manufacturer | grep "VMware, Inc." | cut -c16- | cut -d , -f1)
n='([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
m='([0-9]|[12][0-9]|3[012])'

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
cat <<EOF
Checking for static IP Address
EOF
sleep 1s

#Detect Static or DHCP (IF not Static, change it)
if [ -z "$INTERFACE" ]; then
  "Usage: $0 <interface>"
  exit 1
fi

if [ "$DETECTIP" = "ipv4.method:                            auto" ]; then
  echo ${RED}"Interface $INTERFACE is using DHCP${TEXTRESET}"
  read -p "Please provide a static IP address in CIDR format (i.e 192.168.24.2/24): " IPADDR
  while [ -z "$IPADDR" ]; do
    echo ${RED}"The response cannot be blank. Please Try again${TEXTRESET}"
    read -p "Please provide a static IP address in CIDR format (i.e 192.168.24.2/24): " IPADDR
  done
  while [[ ! $IPADDR =~ ^$n(\.$n){3}/$m$ ]]; do
    read -p ${RED}"The entry is not in valid CIDR notation. Please Try again:${TEXTRESET} " IPADDR
  done
  read -p "Please Provide a Default Gateway Address: " GW
  while [ -z "$GW" ]; do
    echo ${RED}"The response cannot be blank. Please Try again${TEXTRESET}"
    read -p "Please Provide a Default Gateway Address: " GW
  done
  read -p "Please provide the FQDN of this machine: " HOSTNAME
  while [ -z "$HOSTNAME" ]; do
    echo ${RED}"The response cannot be blank. Please Try again${TEXTRESET}"
    read -p "Please provide the FQDN of this machine: " HOSTNAME
  done
  read -p "Please provide the IP address of the Active Directory server: " DNSSERVER
  while [ -z "$DNSSERVER" ]; do
    echo ${RED}"The response cannot be blank. Please Try again${TEXTRESET}"
    read -p "Please provide the IP address of the Active Directory server: " DNSSERVER
  done
  read -p "Please provide the domain search name: " DNSSEARCH
  while [ -z "$DNSSEARCH" ]; do
    echo ${RED}"The response cannot be blank. Please Try again${TEXTRESET}"
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

  read -p "Press any Key to Continue"
  nmcli con mod $INTERFACE ipv4.address $IPADDR
  nmcli con mod $INTERFACE ipv4.gateway $GW
  nmcli con mod $INTERFACE ipv4.method manual
  nmcli con mod $INTERFACE ipv4.dns-search $DNSSEARCH
  nmcli con mod $INTERFACE ipv4.dns $DNSSERVER
  hostnamectl set-hostname $HOSTNAME

  cat <<EOF
The System must reboot for the changes to take effect. ${RED}Please log back in as root.${TEXTRESET}
The installer will continue when you log back in.
If using SSH, please use the IP Address: $IPADDR
EOF
  read -p "Press Any Key to Continue"
  clear
  echo "/root/ADDCInstaller/MEMInstall.sh" >>/root/.bash_profile
  reboot
  exit
else
  echo ${GREEN}"Interface $INTERFACE is using a static IP address ${TEXTRESET}"
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
  read -p "Press Any Key to Continue"
  clear
  echo "/root/ADDCInstaller/MEMInstall.sh" >>/root/.bash_profile
  reboot
  exit
fi

clear

cat <<EOF

*********************************************

This script was created for ${GREEN}Rocky 9.x${TEXTRESET}
This script will quickly configure a Samba File/Print Server

 What this script does:
    1. Update and install all dependencies the Base OS.
    2. Add samba allowances to the Firewall
    3. Sets the SELinux to Passive mode (you should change this after install)
    4. Joins this server to the domain
    5. Creates an example share for AD integration

*********************************************

This will take around 10-15 minutes depending on your Internet connection
and processor speed/memory

EOF
read -p "Press any Key to continue or Ctrl-C to Exit"
clear

cat <<EOF

*********************************************
Checklist:
Before the Installer starts, please make sure you have the following information

    1. ${YELLOW}An Active Admin account${TEXTRESET} that you can use to join this server to the Windows domain
    2. ${YELLOW}An Active User account${TEXTRESET} that you can use to test login to the Windows domain
    2. Verify that this server is ${YELLOW}configured to use the DNS services of AD.${TEXTRESET}
    3. Verify that the FQDN contains the ${YELLOW}REALM of the AD environment${TEXTRESET} you wish to join


*********************************************


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
#SELinux Change
#We need to set SELinux to permissive if this is a file server.
#It must be declared what directories to use. RW
sed -i "s/SELINUX=enforcing/SELINUX=permissive/" /etc/selinux/config

#Allow SAMBA Ports on firewall-cmd
echo "Updating Firewall Rules"
echo "${GREEN} "
firewall-cmd --add-service=samba --permanent
firewall-cmd --add-service=samba-client --permanent
firewall-cmd --reload
clear
echo ${GREEN}"These are the services/ports now open on the server${TEXTRESET}"
echo
firewall-cmd --list-services --zone=public
echo "${TEXTRESET}"
echo "The Installer will continue in a moment or Press Ctrl-C to Exit"
sleep 8s
clear
cat <<EOF
${GREEN}Downloading and installing updates${TEXTRESET}
EOF
sleep 3s
dnf -y install epel-release
dnf -y install dnf-plugins-core
dnf config-manager --set-enabled crb
dnf -y update
dnf -y install ntsysv wget oddjob oddjob-mkhomedir samba-winbind samba-winbind-clients samba-common-tools realmd bind-utils samba
systemctl enable winbind
systemctl start winbind

clear

cat <<EOF
The Installer will now ask some questions from the checklist provided earlier.
Please make sure you have this information

EOF
read -p "Press any Key to continue or Ctrl-C to Exit"
clear
read -p "Please provide a valid AD username for testing: " ADUSER
while [ -z "$ADUSER" ]; do
  echo ${RED}"The response cannot be blank. Please Try again${TEXTRESET}"
  read -p "Please provide a valid AD username for testing: " ADUSER
done

read -p "Please provides this user's password: " ADPASS
while [ -z "$ADPASS" ]; do
  echo ${RED}"The response cannot be blank. Please Try again${TEXTRESET}"
  read -p "Please provides this user's password: " ADPASS
done

read -p "Please provide the IP/FQDN Address of your NTP/AD Server: " NTP
while [ -z "$NTP" ]; do
  echo ${RED}"The response cannot be blank. Please Try again${TEXTRESET}"
  read -p "Please provide the IP/FQDN Address of your NTP/AD Server: " NTP
done

read -p "Please provide the Administrator Account to join this system to AD (Just username, not UPN): " DOMAINADMIN
while [ -z "$DOMAINADMIN" ]; do
  echo ${RED}"The response cannot be blank. Please Try again${TEXTRESET}"
  read -p "Please provide the Administrator Account to join this system to AD (Just username, not UPN): " DOMAINADMIN
done

clear
cat <<EOF
Validating your Entries:
AD Testing Username: ${GREEN}$ADUSER${TEXTRESET}
AD Testing Password: ${GREEN}$ADPASS${TEXTRESET}
Domain: ${GREEN}$ADDOMAIN${TEXTRESET}
NTP Server: ${GREEN}$NTP${TEXTRESET}
AD Administrator Account: ${GREEN}$DOMAINADMIN${TEXTRESET}
EOF

read -p "Press any Key to continue or Ctrl-C to Exit"
clear

cat <<EOF
Joining server to Domain $ADDOMAIN
${RED}The screen may look frozen for up to a minute after the password is entered... Please wait${TEXTRESET}
EOF

realm join -U $DOMAINADMIN --client-software=winbind $DOMAIN

clear

sed -i "/pool /c\server $NTP iburst" /etc/chrony.conf
sed -i "/server /c\server $NTP iburst" /etc/chrony.conf
sed -e '2d' /etc/chrony.conf
systemctl restart chronyd
clear
echo ${RED}"Syncronizing time, Please wait${TEXTRESET}"
sleep 10s
clear
chronyc tracking
cat <<EOF
${GREEN}We should be syncing time${TEXTRESET}

The Installer will continue in a moment, otherwise Ctrl-C to stop processing
EOF
sleep 8
clear

#Validate winbind is working
cat <<EOF
${GREEN}Testing RPC to Active Directory${TEXTRESET}
EOF
echo ${GREEN}
wbinfo -t
echo ${TEXTRESET}
echo " "
echo "The Installer will continue in a moment, otherwise Ctrl-C to stop processing"
sleep 8
clear

#Validate winbind sees users
cat <<EOF
${GREEN}AD Users${TEXTRESET}
Please make sure you see your AD users.
If you do not, then please resolve this issue first before proceeding.
EOF
echo ${GREEN}
wbinfo -u
echo ${TEXTRESET}
echo " "
echo "The Installer will continue in a moment, otherwise Ctrl-C to stop processing"
sleep 8
clear

#Validate winbind groups are seen
cat <<EOF
${GREEN}AD Groups${TEXTRESET}
Please make sure you see your AD groups.
If you do not, then please resolve this issue first before proceeding.
EOF
echo ${GREEN}
wbinfo -g
echo ${TEXTRESET}
echo " "
echo "The Installer will continue in a moment, otherwise Ctrl-C to stop processing"
sleep 10
clear

#Basic test against AD
cat <<EOF
${GREEN}Test a winbind login${TEXTRESET}
We are going to login with the test account ${GREEN}($ADUSER)${TEXTRESET}. Please make sure you see a valid response of:

${GREEN}challenge/response password authentication succeeded${TEXTRESET}
If you do not, then please resolve this issue first before proceeding.

EOF
echo ${GREEN}
wbinfo -a $ADUSER%$ADPASS
echo ${TEXTRESET}
echo " "
echo "The Installer will continue in a moment, otherwise Ctrl-C to stop processing"
sleep 10
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
    dnf -y install cockpit-navigator cockpit cockpit-storaged
    systemctl enable cockpit.socket
    systemctl start cockpit.socket
fi

#Add Example file share for Samba

cat <<EOF >/etc/samba/smb.tmp

#Create a writable share to be used by an AD group
#Make sure that before you enable the share, you chown, recursively
#(i.e.) chown -R root."${ADDOMAIN}\domain users" /path/to/share 
#Also change your permissions for the files/directories. Default is RWX(770) for Users and Groups
# chmod -R 770 /path/to/share
#SELinux also comes into play:
#chcon -t samba_share_t /path/to/top directory/ -R
#Remember to uncomment all the lines below 
#[SHARE_NAME]
#writeable = yes
#write list = @"${ADDOMAIN}\domain users"
#path = /path/to/share
#force group = "${ADDOMAIN}\domain users"
#force create mode = 2770
#comment = Data Share
#valid users = @"${ADDOMAIN}\domain users"
#create mode = 2770
#directory mode = 2770
#directory mask = 2770
EOF

cat /etc/samba/smb.tmp >> /etc/samba/smb.conf

#Enable and start samba services 
systemctl enable smb
systemctl start smb

#Clean up Install files
sed -i '/MEMInstall.sh/d' /root/.bash_profile
rm -r -f /root/FR-Installer
rm -r -f /root/DC-Installer.sh
rm -r -f /root/ADDCInstaller
rm -r -f /root/FR-Installer.sh

clear
cat <<EOF
${GREEN}********************************
   Server Installation Complete
********************************${TEXTRESET}

${YELLOW}An example share has been included in the smb.conf file${TEXTRESET}

${RED}SELinux has been set to PERMISSIVE MODE.${TEXTRESET}
Please make sure that you apply the correct 
Please adjust, and set SELinux to enabled
Something as easy as:
${YELLOW} chcon -t samba_share_t /path/to/top directory/ -R${TEXTRESET}
Should be good
(Cockpit can help you do this if you are unfamiliar) 

The Server will reboot now

EOF

read -p "Press Any Key to reboot"
echo ${RED}"Rebooting${TEXTRESET}"
sleep 1
reboot
