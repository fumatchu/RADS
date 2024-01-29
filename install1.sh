#!/bin/sh
#Install1
textreset=$(tput sgr0) # reset the foreground colour
red=$(tput setaf 1)
yellow=$(tput setaf 3)
green=$(tput setaf 2)
clear
echo "*********************************************"
echo " "
echo "This script was created for ${green}Rocky 9.x${textreset}"
echo "This will install a Samba AD/DC Server. There will be some manual"
echo "intervention needed later in the install for final configuration,"
echo "in Phase two, after the initial server reboot"
echo " "
echo "What the First Phase of this script does:"
echo "1. Apply approrpriate SELinux context and Friewall rules"
echo "2. Disable un-needed Services"
echo "2. Install the REPO(s) needed and dependencies needed"
echo "3. Once that is complete we will restart the server"
echo ${red}"4. After the Server restarts, PLEASE LOG BACK IN as root to continue${textreset}"
echo " "
echo "*********************************************"
echo " "
echo "This will take around 10-15 minutes depending on your Internet connection"
echo "and processor speed/memory"
echo " "
echo ${red}"PLEASE NOTE: When you setup your server via the Rocky installer,"
echo "You should have specified the static IP and FQDN to be used as your AD instance."
echo "It is assumed this is the correct information and will utilize it for the install moving forward."
echo "If this information is not correct, i.e. ip address, hostname, domain name, use${textreset} ${yellow}nmtui${textreset} ${red}to modify it,"
echo "and start the installer again by typing:"
echo "/root/DC-Installer.sh${textreset}"
read -p "Press Enter to continue or CtrL-C to terminate the installer"


setsebool -P samba_create_home_dirs=on \
  samba_domain_controller=on \
  samba_enable_home_dirs=on \
  samba_portmapper=on \
  use_samba_home_dirs=on

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
systemctl restart firewalld



dnf -y install epel-release
dnf -y install dnf-plugins-core
dnf config-manager --set-enabled crb
dnf -y update

dnf -y install cockpit cockpit-storaged ntsysv wget open-vm-tools

systemctl enable cockpit.socket

dnf -y install docbook-style-xsl gcc gdb gnutls-devel gpgme-devel jansson-devel keyutils-libs-devel krb5-workstation libacl-devel libaio-devel libarchive-devel libattr-devel libblkid-devel libtasn1 libtasn1-tools libxml2-devel libxslt lmdb-devel openldap-devel pam-devel perl perl-ExtUtils-MakeMaker perl-Parse-Yapp popt-devel python3-cryptography python3-dns python3-gpg python3-devel readline-devel rpcgen systemd-devel tar zlib-devel flex bison dbus-devel python3-markdown bind-utils

export PERL_MM_USE_DEFAULT=1
cpan JSON
echo "export PATH=/usr/local/samba/bin/:/usr/local/samba/sbin/:$PATH" >> /root/.bash_profile

echo "/root/ADDCInstaller/install2.sh" >> /root/.bash_profile

systemctl disable iscsi
systemctl disable iscsi-onboot
clear
echo " "
echo "************************************************ "
echo "The Server is ready to reboot"
echo ${red}"Please make sure you are logging back in as root"
echo "for the second part of the install${textreset}"
echo "************************************************ "
echo " "
read -p "Press Any key when you're ready"
reboot
