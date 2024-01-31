#!/bin/sh
#DC-install.sh
#This script installs AD with DC support using mock from Upstream REPO 
textreset=$(tput sgr0) # reset the foreground colour
red=$(tput setaf 1)
yellow=$(tput setaf 3)
green=$(tput setaf 2)
interface=$(nmcli | grep "connected to" | cut -c22-)
FQDN=$(hostname)
IP=$(hostname -I)
ADREALM=$(hostname | sed 's/...//'|sed -e 's/\(.*\)/\U\1/')
ADDOMAIN=$(hostname | sed 's/...//' | cut -d. -f1| sed -e 's/\(.*\)/\U\1/')
FQDN=$(hostname)
REVERSE=$(echo "$IP" | { IFS=. read q1 q2 q3 q4; echo "$q3.$q2.$q1"; })
mocksmbver=$(dnf provides samba | grep samba |sed '2,4d'| cut -d: -f1| cut -dx -f1)
majoros=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')
minoros=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '1d')
cat <<stop
Checking for static IP Address
stop
sleep 1s

#Detect Static or DHCP (IF not Static, change it)
if [ -z "$interface" ]; then
   "Usage: $0 <interface>"
  exit 1
fi

method=$(nmcli -f ipv4.method con show $interface)

if [ "$method" = "ipv4.method:                            auto" ]; then
  echo ${red}"Interface $interface is using DHCP${textreset}"
  echo "This server should be using a Static IP"
  echo "Please Provide a Static IP address in CIDR format"
  echo "(i.e 192.168.24.2/24)"
  read IPADDR
  echo " "
  echo "Please Provide a Default Gateway Address"
  read GW
  echo " "
  echo "Please provide the domain search name"
  echo "(i.e test.int)"
  read DNSSEARCH
  echo " "
  echo "Please provide an upstream DNS IP for resolution"
  read DNSSERVER
  echo " "
cat <<EOF
Please provide the FQDN of this host to use
(i.e. hostname.domain.int)
EOF
read HOSTNAME 
clear
  echo "The following changes to the system will be configured:"
  echo "IP address: $IPADDR"
  echo "Gateway: $GW"
  echo "DNS Search: $DNSSEARCH"
  echo "DNS Server: $DNSSERVER"
  echo "HOSTNAME: $HOSTNAME"
  read -p "Press any Key to Continue"
  nmcli con mod $interface ipv4.address $IPADDR
  nmcli con mod $interface ipv4.gateway $GW
  nmcli con mod $interface ipv4.method manual
  nmcli con mod $interface ipv4.dns-search $DNSSEARCH
  nmcli con mod $interface ipv4.dns $DNSSERVER
  hostnamectl set-hostname $HOSTNAME
  echo " "
  echo "The System must reboot for the changes to take effect. Please log back in as root."
  echo "The installer will continue when you log back in."
  echo "If using SSH, please use the IP Address: $IPADDR"
  read -p "Press Any Key to Continue"
  clear
  echo "/root/ADDCInstaller/DCInstall.sh" >> /root/.bash_profile
  reboot 
  clear 
  clear
  clear
else
echo   ${green}"Interface $interface is using a static IP address ${textreset}"
fi


clear
cat <<EOF

 *********************************************

 This script was created for ${green}Rocky 9.x${textreset}
 This will install a Samba AD/DC Server.

 What this script does:
 1. Apply appropriate SELinux context and Firewall rules
 2. Install the REPO(s) needed and dependencies needed
 3. Compile Samba RPMS
 4. Configure the DC
 5. Test for kerberos ticket and DNS
 6. Once that is complete we will restart the server

 *********************************************"
 This will take around 20-25 minutes depending on your Internet connection
 and processor speed/memory
 ${red} NOTE: This installer must run as the root account${textreset}
EOF

read -p "Press Any Key to Continue or Ctrl-C to exit the Installer"
clear
cat <<EOF
Please provide the FQDN of this host to use
(i.e. hostname.domain.int)
EOF
read HOSTNAME
#Set hostname 
hostnamectl set-hostname $HOSTNAME
clear
cat <<EOF
Please provide the Samba REALM you would like to use:
(CAPS Preferred)
EOF
echo "(i.e $ADREALM)"

read REALM
clear
cat <<EOF
Please provide the Samba DOMAIN name you would like to use:
(CAPS Preferred)
EOF
echo "(i.e. $ADDOMAIN)"

read DOMAIN
clear
cat <<EOF
Please provide the Administrator Password to use for AD/DC Provisioning:
EOF

read ADMINPASS
clear
cat <<EOF
We are going to provide NTP to our clients on the network
Please provide the appropriate network scope in CIDR format
(i.e 192.168.0.0/16)
Please provide the network scope to service clients
EOF
read NTPCIDR
clear
echo "The installer will deploy Samba with the following information:"
echo "Hostname:$HOSTNAME"
echo "NTP Client Scope: $NTPCIDR"
echo "REALM: $REALM"
echo "DOMAIN: $DOMAIN"
echo "Administrator Password: $ADMINPASS"

read -p "Press any Key"
#Set hostname 
hostnamectl set-hostname $HOSTNAME
#If this server got DHCP, and there is an NTP server option, we must change it to a pool
sed -i '/server /c\pool 2.rocky.pool.ntp.org iburst' /etc/chrony.conf
sed -i "/#allow /c\allow $NTPCIDR" /etc/chrony.conf
systemctl restart chronyd
clear
echo ${red}"Syncronizing time, Please wait${textreset}"
sleep 10s
clear
chronyc tracking
echo " " 
echo " " 
echo ${green}"We should be syncing time${textreset}"
echo "The Installer will continue in a moment or Press Ctrl-C to Exit"
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
firewall-cmd --zone=public --add-port=53/tcp --add-port=53/udp --permanent
firewall-cmd --zone=public --add-port=88/tcp --add-port=88/udp --permanent
firewall-cmd --zone=public --add-port=135/tcp --permanent
firewall-cmd --zone=public --add-port=389/tcp --add-port=389/udp --permanent
firewall-cmd --zone=public --add-port=445/tcp --permanent
firewall-cmd --zone=public --add-port=464/tcp --add-port=464/udp --permanent
firewall-cmd --zone=public --add-port=636/tcp --permanent
firewall-cmd --zone=public --add-port=3268/tcp --permanent
firewall-cmd --zone=public --add-port=3269/tcp --permanent
firewall-cmd --zone=public --add-port=50000-51000/tcp --permanent
firewall-cmd --zone=public --add-port=49152-65535/tcp --permanent
firewall-cmd --complete-reload
systemctl restart firewalld
clear
echo ${green}"These are the services/ports now open on the server${textreset}"
firewall-cmd --list-all
echo "The Installer will continue in a moment or Press Ctrl-C to Exit"
sleep 8s
clear
cat <<EOF
${green}Downloading and compiling the Samba source from Rocky --with dc${textreset}
EOF
sleep 3s
dnf -y update 
# Initial build
 dnf install epel-release createrepo -y
 crb enable
 dnf install mock -y
 dnf download samba --source
 mock -r rocky-"$majoros"-x86_64 --enablerepo=devel --define 'dist .el'"$majoros"'_'"$minoros"'.dc' --with dc "$mocksmbver"src.rpm
 mkdir /root/samba
 cp /var/lib/mock/rocky-"$majoros"-x86_64/result/*.rpm /root/samba
 createrepo /root/samba
 #dnf config-manager --add-repo /root/samba
 dnf -y install --nogpgcheck samba-dc samba-client krb5-workstation samba \
  --repofrompath=samba,/root/samba \
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
nmcli con mod ens192 ipv4.dns $IP
systemctl restart NetworkManager
#Add support for FreeRADIUS
sed -i '8i \       \ #ntlm auth = mschapv2-and-ntlmv2-only #Added for FreeRADIUS Support'  /etc/samba/smb.conf
#Allow plain LDAP binds
sed -i '9i \       \#ldap server require strong auth = no #UNCOMMENT THIS IF YOU NEED PLAIN LDAP BIND (non-TLS)' /etc/samba/smb.conf
systemctl enable samba --now
clear
cat  <<EOF
Now we are going to do some testing
These tests came from:

${red}https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller#Troubleshooting${textreset}

If you would like, please following along from that link
EOF
echo "The Installer will continue in a moment or Press Ctrl-C to Exit" 
sleep 10s
clear
cat <<EOF
First, We will check Kerberos and get a ticket
Login with the Administrator password you created earlier for the domain
EOF
kinit Administrator
echo ${green}
klist
echo ${textreset}
echo "The Installer will continue in a moment or Press Ctrl-C to Exit"
sleep 8s
clear
cat <<EOF
We should check DNS for correct resolution
Testing _ldap._tcp
Example Result:
${yellow}_ldap._tcp.samdom.example.com has SRV record 0 100 389 dc1.samdom.example.com.${textreset}

The actual result is:
EOF
echo ${green}
host -t SRV _ldap._tcp.$REALM.
echo ${textreset}

cat <<EOF
Testing _udp kerberos
Example Result:
${yellow}_kerberos._udp.samdom.example.com has SRV record 0 100 88 dc1.samdom.example.com.${textreset}

The actual result is:
EOF
echo ${green}
host -t SRV _kerberos._udp.$REALM.
echo ${textreset}
cat <<EOF

Testing A Record of Domain Controller
Example Result:
${yellow}"dc1.samdom.example.com has address 10.99.0.1${textreset}

The actual result is:
EOF
echo ${green}
host -t A $FQDN.
echo ${textreset}
sleep 8s
clear
cat <<EOF
Testing anonymous Logins to the server
EOF
smbclient -L localhost -N
sleep 8s
clear
cat <<EOF
Verifying Authentication Login:
EOF
smbclient //localhost/netlogon -UAdministrator -c 'ls'
read -p "Press Any Key to Continue"
clear
echo "If all tests returned valid, installation is successful"
read -p "Press Any Key to Continue"
clear

cat <<EOF
The last thing that should be done is add a reverse zone in DNS.
Based on your configuration, and assuming a Class C subnet, your command should be:
EOF
echo " "
echo ${green}""samba-tool dns zonecreate $FQDN $REVERSE.in-addr.arpa -U Administrator ${textreset}""
echo " "
cat <<EOF
Please add this as approriate and apply it to the system
You may want to reduce the complexity and history, length, etc. of the passwords

Type the command:
${green}samba-tool domain passwordsettings set --help${textreset}

For a total list of options, or use PSO's

If this is a testing envrionment, you can always use these options (copy/paste)

samba-tool domain passwordsettings set --complexity=off
samba-tool domain passwordsettings set --history-length=0
samba-tool domain passwordsettings set --min-pwd-age=0
samba-tool domain passwordsettings set --max-pwd-age=0
After that is complete, please reboot the system

EOF

sed -i '/DCInstall.sh/d' /root/.bash_profile


while true; do

read -p "Do you want to reboot now? (y/n) " yn

case $yn in 
   [yY] ) reboot;
      break;;
   [nN] ) echo exiting...;
      exit;;
   * ) echo invalid response;;
esac

done
exit1
