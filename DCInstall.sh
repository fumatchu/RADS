#!/bin/sh
#DC-install.sh
#This script installs Samba AD with DC support using mock from Upstream Rocky REPO via src.rpm
textreset=$(tput sgr0)
red=$(tput setaf 1)
yellow=$(tput setaf 3)
green=$(tput setaf 2)
interface=$(nmcli | grep "connected to" | cut -c22-)
FQDN=$(hostname)
IP=$(hostname -I)
ADREALM=$(hostname | sed 's/...//'|sed -e 's/\(.*\)/\U\1/')
ADDOMAIN=$(hostname | sed 's/...//' | cut -d. -f1| sed -e 's/\(.*\)/\U\1/')
FQDN=$(hostname)
DHCPNTPSERVER=$(hostname -I)
DHCPDOMAINNAME=$(hostname | sed 's/...//')
REVERSE=$(echo "$IP" | { IFS=. read q1 q2 q3 q4; echo "$q3.$q2.$q1"; })
mocksmbver=$(dnf provides samba | grep samba |sed '2,4d'| cut -d: -f1| cut -dx -f1)
majoros=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')
minoros=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '1d')
user=$(whoami)

#Checking for user permissions
if [ "$user" != "root" ]; then
echo ${red}"This program must be run as root ${textreset}"
echo "Exiting"
exit
else
echo "Running Program"
fi
#Checking for version Information
if [ "$majoros" != "9" ]; then
echo ${red}"Sorry, but this installer only works on Rocky 9.X ${textreset}"
echo "Please upgrade to ${green}Rocky 9.x${textreset}"
echo "Exiting the installer..."
exit 
else
echo ${green}"Version information matches..Continuing${textreset}"
fi
#Detect Static or DHCP (IF not Static, change it)
cat <<EOF
Checking for static IP Address
EOF
sleep 1s

if [ -z "$interface" ]; then
   "Usage: $0 <interface>"
  exit 1
fi
method=$(nmcli -f ipv4.method con show $interface)
if [ "$method" = "ipv4.method:                            auto" ]; then
echo  ${red}"Interface $interface is using DHCP${textreset}"
read -p "Please provide a static IP address in CIDR format (i.e 192.168.24.2/24): " IPADDR
read -p "Please provide a Default Gateway Address: " GW
read -p "Please provide the FQDN of this machine (i.e. machine.domain.com) " HOSTNAME
read -p "Please provide the domain search name (i.e. domain.com): " DNSSEARCH
read -p "Please provide an upstream DNS IP for resolution (OPENDNS is reliable-try-208.67.222.222): " DNSSERVER
  
clear
cat <<EOF
The following changes to the system will be configured:
IP address: ${green}$IPADDR${textreset}
Gateway: ${green}$GW${textreset}
DNS Search: ${green}$DNSSEARCH${textreset}
DNS Server: ${green}$DNSSERVER${textreset}
HOSTNAME: ${green}$HOSTNAME${textreset}
EOF
  read -p "Press any Key to Continue"
  nmcli con mod $interface ipv4.address $IPADDR
  nmcli con mod $interface ipv4.gateway $GW
  nmcli con mod $interface ipv4.method manual
  nmcli con mod $interface ipv4.dns-search $DNSSEARCH
  nmcli con mod $interface ipv4.dns $DNSSERVER
  hostnamectl set-hostname $HOSTNAME
cat <<EOF
The System must reboot for the changes to take effect. ${red}Please log back in as root.${textreset}
The installer will continue when you log back in.
If using SSH, please use the IP Address: $IPADDR
EOF
  read -p "Press Any Key to Continue"
  clear
  echo "/root/ADDCInstaller/DCInstall.sh" >> /root/.bash_profile
  reboot 
  exit
else
echo   ${green}"Interface $interface is using a static IP address ${textreset}"
fi
clear
cat <<EOF

 *********************************************

 This script was created for ${green}Rocky 9.x${textreset}
 This will install a Samba AD/DC Server and provision it.

 What this script does:
 1. Apply appropriate SELinux context and Firewall rules
 2. Install the REPO(s) needed and dependencies needed
 3. Compile Samba RPMS
 4. Configure the DC
 5. Test for kerberos ticket and DNS
 6. Once that is complete we will restart the server

 *********************************************"
 This will take 20-25 minutes depending on your Internet connection
 and processor speed/memory
 ${red} NOTE: This installer must run as the root account${textreset}
EOF
read -p "Press Any Key to Continue or Ctrl-C to exit the Installer"
clear
cat <<EOF
*********************************************
Checklist:
Before the Installer starts, please make sure you have the following information

    1. ${yellow}An FQDN${textreset} that you want to use for this AD server.
    2. ${yellow}A REALM (i.e CONTOSO.COM) ${textreset} that will become the AD Kerberos Advertisement
    3. ${yellow}A DOMAIN Name (Shortened REALM- i.e. CONTOSO)${textreset} that you want to use for the DOMAIN name.
    4. ${yellow}An Administrator password${textreset} that you want to use for the DOMAIN
    5. ${yellow}An NTP Subnet${textreset} that you will be allowing for your clients. This server will provide syncronized time
     

*********************************************
EOF
read -p "Press Any Key to Continue or Ctrl-C to exit the Installer"
clear


read -p "Please provide the FQDN of this host to use (i.e. hostname.contoso.com): " HOSTNAME
read -p "Please provide the Samba REALM you would like to use (i.e. $ADREALM)  " REALM
read -p "Please provide the Samba DOMAIN name you would like to use (CAPS PREFERRED i.e. $ADDOMAIN): " DOMAIN
read -p "Please provide the Administrator Password to use for AD/DC Provisioning: " ADMINPASS
read -p "Please provide the appropriate network scope in CIDR format (i.e 192.168.0.0/16) to allow NTP for clients: " NTPCIDR
clear
cat <<EOF
The installer will deploy Samba AD with the following information:
Hostname:${green}$HOSTNAME${textreset}
REALM: ${green}$REALM${textreset}
DOMAIN: ${green}$DOMAIN${textreset}
Administrator Password: ${green}$ADMINPASS${textreset}
NTP Client Scope: ${green}$NTPCIDR${textreset}
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
firewall-cmd --zone=public --add-port=123/udp --permanent
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
${yellow}This may take approximately 20-30 minutes${textreset}
EOF
sleep 4s
dnf -y install ntsysv open-vm-tools cockpit cockpit-storaged dhcp-server net-tools
dnf -y update 
# Initial build
 dnf install epel-release createrepo -y
 crb enable
 dnf install mock -y
 dnf download samba --source
 mock -r rocky-"$majoros"-x86_64 --enablerepo=devel --define 'dist .el'"$majoros"'_'"$minoros"'.dc' --with dc "$mocksmbver"src.rpm
 mkdir /root/.samba
 cp /var/lib/mock/rocky-"$majoros"-x86_64/result/*.rpm /root/.samba
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
nmcli con mod ens192 ipv4.dns $IP
systemctl restart NetworkManager
#Add support for FreeRADIUS
sed -i '8i \       \ #Added for FreeRADIUS Support' /etc/samba/smb.conf
sed -i '9i \       \ ntlm auth = mschapv2-and-ntlmv2-only'   /etc/samba/smb.conf
#Allow plain LDAP binds
sed -i '10i \       \#ldap server require strong auth = no #UNCOMMENT THIS IF YOU NEED PLAIN LDAP BIND (non-TLS)' /etc/samba/smb.conf
#ADD cron for monitoring of REPOS
touch /var/log/dnf-smb-mon.log
chmod 700 /root/ADDCInstaller/dnf-smb-mon
\cp /root/ADDCInstaller/dnf-smb-mon /usr/bin
(crontab -l; echo "0 */6 * * * /usr/bin/dnf-smb-mon") | sort -u | crontab -
systemctl restart crond
#ADD samba-dnf-package update
chmod 700 /root/ADDCInstaller/samba-dnf-pkg-update
\cp /root/ADDCInstaller/samba-dnf-pkg-update /usr/bin
systemctl enable samba --now
clear
cat  <<EOF
Now we are going to do some testing
These tests came from:

${red}https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller#Troubleshooting${textreset}

If you would like, please following along from that link
EOF
echo "The Installer will continue in a moment or Press Ctrl-C to Exit" 
sleep 15s
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
sleep 10s
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
echo "The Installer will continue in a moment or Press Ctrl-C to Exit"
sleep 10s
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
sleep 5
clear

cat <<EOF
 A reverse zone should be added to DNS.
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

To setup your first user:
samba-tool user add <username> [<password>]

After that is complete, please reboot the system

EOF
#Cleanup
sed -i '/DCInstall.sh/d' /root/.bash_profile
rm -r -f /root/DC-Installer.sh
rm -r -f /root/ADDCInstaller
rm -f /root/samba*.src.rpm




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
exit
