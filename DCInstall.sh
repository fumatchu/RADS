#!/bin/sh
#DC-install.sh
#This script installs the FIRST Samba AD with DC support using mock from Upstream Rocky REPO via src.rpm
dnf -y install net-tools
TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
INTERFACE=$(nmcli | grep "connected to" | cut -c22-)
DETECTIP=$(nmcli -f ipv4.method con show $INTERFACE)
FQDN=$(hostname)
IP=$(hostname -I)
DOMAIN=$(hostname | sed 's/^[^.:]*[.:]//' |sed -e 's/\(.*\)/\U\1/')
ADDOMAIN=$(hostname | sed 's/^[^.:]*[.:]//' |cut -d. -f1 | sed -e 's/\(.*\)/\U\1/')
FQDN=$(hostname)
REVERSE=$(echo "$IP" | {
  IFS=. read q1 q2 q3 q4
  echo "$q3.$q2.$q1"
})
MOCKSMBVER=$(dnf provides samba | grep samba | sed '2,4d' | cut -d: -f1 | cut -dx -f1)
MAJOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')
MINOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '1d')
USER=$(whoami)
DHCPNSNAME=$(hostname | sed 's/^[^.:]*[.:]//')
DHCPNETMASK=$(ifconfig | grep 255 | sed '$d' | cut -c36- | cut -d b -f1)
SUBNETNETWORK=$(echo "$IP" | {
  IFS=. read q1 q2 q3 q4
  echo "$q1.$q2.$q3.0"
})

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

if [ "$DETECTIP" = "ipv4.method:                            auto" ]; then
  echo ${RED}"Interface $INTERFACE is using DHCP${TEXTRESET}"
  read -p "Please provide a static IP address in CIDR format (i.e 192.168.24.2/24): " IPADDR
  read -p "Please provide a Default Gateway Address: " GW
  read -p "Please provide the FQDN of this machine (i.e. machine.domain.com) " HOSTNAME
  read -p "Please provide the domain search name (i.e. domain.com): " DNSSEARCH
  read -p "Please provide an upstream DNS IP for resolution (OPENDNS is reliable-try-208.67.222.222): " DNSSERVER
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
  echo "/root/ADDCInstaller/DCInstall.sh" >>/root/.bash_profile
  reboot
  exit
else
  echo ${GREEN}"Interface $INTERFACE is using a static IP address ${TEXTRESET}"
fi
clear

cat <<EOF
*********************************************
${GREEN}This will Install the FIRST AD Server and build a new Forest/Domain${TEXTRESET}

Checklist:
Before the Installer starts, please make sure you have the following information

    1. ${YELLOW}An FQDN${TEXTRESET} that you want to use for this AD server.
    2. ${YELLOW}A REALM (i.e CONTOSO.COM) ${TEXTRESET} that will become the AD Kerberos Advertisement
    3. ${YELLOW}A DOMAIN Name (Shortened REALM- i.e. CONTOSO)${TEXTRESET} that you want to use for the DOMAIN name.
    4. ${YELLOW}An Administrator password${TEXTRESET} that you want to use for the DOMAIN
    5. ${YELLOW}An NTP Subnet${TEXTRESET} that you will be allowing for your clients. This server will provide syncronized time
    6. The ${YELLOW}beginning and ending lease range${TEXTRESET} for DHCP
    7. The ${YELLOW}client default gateway IP Address${TEXTRESET} for the DHCP Scope
    8. A ${YELLOW}Friendly name${TEXTRESET} as a description to the DHCP scope created
    
     

*********************************************
EOF
read -p "Press Any Key to Continue or Ctrl-C to exit the Installer"
clear

cat <<EOF
${GREEN}Samba AD/DC Setup${TEXTRESET}
EOF
read -p "Please provide the FQDN of this host to use (i.e. format-hostname.domain.com): " HOSTNAME
read -p "Please provide the Samba REALM you would like to use (in ${YELLOW}CAPS${TEXTRESET} i.e. $DOMAIN):  " REALM
read -p "Please provide the Samba DOMAIN name you would like to use (in ${YELLOW}CAPS${TEXTRESET} i.e. $ADDOMAIN): " DOMAIN
read -p "Please provide the Administrator Password to use for AD/DC Provisioning: " ADMINPASS
read -p "Please provide the appropriate network scope in CIDR format (i.e 192.168.0.0/16) to allow NTP for clients: " NTPCIDR
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

read -p "Please provide the beginning IP address in the lease range (based on the network $SUBNETNETWORK): " DHCPBEGIP
read -p "Please provdie the ending IP address in the lease range (based on the network $SUBNETNETWORK): " DHCPENDIP
read -p "Please provide the default gateway for clients: " DHCPDEFGW
read -p "Please provide a description for this subnet: " SUBNETDESC

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
cat <<EOF
${GREEN}Deploying the server with these settings${TEXTRESET}

The installer will deploy Samba AD with the following information:
Hostname:${GREEN}$HOSTNAME${TEXTRESET}
REALM: ${GREEN}$REALM${TEXTRESET}
DOMAIN: ${GREEN}$DOMAIN${TEXTRESET}
Administrator Password: ${GREEN}$ADMINPASS${TEXTRESET}
NTP Client Scope: ${GREEN}$NTPCIDR${TEXTRESET}



EOF
read -p "Press any Key to continue or Ctrl-C to Exit"
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
dnf -y install ntsysv open-vm-tools net-tools nano
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
#dnf config-manager --add-repo /root/samba
dnf -y install --nogpgcheck samba-dc samba-client krb5-workstation samba \
  --repofrompath=samba,/root/.samba \
  --enablerepo=samba
#Move smb.conf file
mv -f /etc/samba/smb.conf /etc/samba/smb.bak.orig
#Provision Domain
samba-tool domain provision \
 --realm="$REALM" \
 --domain="$DOMAIN" \
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


The Installer will continue in a moment or Press Ctrl-C to Exit
EOF
sleep 15s
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
host -t SRV _ldap._tcp.$REALM.
echo ${TEXTRESET}

cat <<EOF
Testing _udp kerberos
Example Result:
${YELLOW}_kerberos._udp.samdom.example.com has SRV record 0 100 88 dc1.samdom.example.com.${TEXTRESET}

The actual result is:
EOF
echo ${GREEN}
host -t SRV _kerberos._udp.$REALM.
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
${GREEN} Relax Passwords if in Lab Setting ${TEXTRESET}

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
${GREEN} Setting up Your First User ${TEXTRESET}
To setup your first user, use the Active Directory Management Module in Server Management
This will be installed in the next step
EOF

cat <<EOF

${GREEN}********************************
    Server Installation Complete
********************************${TEXTRESET}

The Installer will continue in a moment

${YELLOW}Getting Ready to install Server Management${TEXTRESET}

EOF

sleep 3

#Cleanup RADS Install Files
sed -i '/DCInstall.sh/d' /root/.bash_profile
rm -r -f /root/DC-Installer.sh
rm -r -f /root/ADDCInstaller
rm -f /root/samba*.src.rpm

cat <<EOF
${GREEN}******************************
Installing Server Management
******************************${TEXTRESET}

EOF

cd /root/
dnf -y install wget
wget https://raw.githubusercontent.com/fumatchu/RADS-SM/main/RADS-SMInstaller.sh
chmod 700 ./RADS-SMInstaller.sh
/root/RADS-SMInstaller.sh
