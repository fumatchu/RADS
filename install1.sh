#!/bin/sh
#Install1
echo " "
echo " "
echo "*********************************************"
echo " "
echo "This script was created for Rocky 9.x"
echo "This will install a Samba AD/DC Server. There will be some manual"
echo "intervention needed later in the install for final configuration."
echo " "
echo "What this script does:"
echo "1. Disable Firewall Services and SELINUX"
echo "2. Disable un-needed Services"
echo "2. Install the REPO(s) needed and dependencies needed"
echo "3. Once that is complete we will restart the server"
echo "4. After the Server restarts, PLEASE LOG BACK IN as root to continue"
echo " "
echo "*********************************************"
echo " "
echo "This will take around 10-15 minutes depending on your Internet connection"
echo "and processor speed/memory"
echo " "
read -p "Press Enter when you're ready"



sed -i 's/^SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config
systemctl disable firewalld



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
echo "Please make sure you are logging back in as root"
echo "for the second part of the install"
echo "************************************************ "
echo " "
read -p "Press Any key when you're ready"
reboot
