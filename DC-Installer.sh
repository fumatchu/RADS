#!/bin/sh
#DC-Installer.sh #Bootstrap to GIT REPO
TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
USER=$(whoami)
MAJOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')

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

cat <<EOF
${GREEN}**************************
Please wait while we gather some files
**************************${TEXTRESET}


${YELLOW}Installing wget and git${TEXTRESET}
EOF
sleep 1

dnf -y install wget git

cat <<EOF
${YELLOW}*****************************
Retrieving Files from GitHub
*****************************${TEXTRESET}
EOF

sleep 1

mkdir /root/ADDCInstaller

git clone https://github.com/fumatchu/RADS.git /root/ADDCInstaller

chmod 700 /root/ADDCInstaller/DC*
clear

clear
cat <<EOF
 *********************************************

 This script was created for ${GREEN}Rocky 9.x${TEXTRESET}
 This will install a primary Samba AD/DC Server OR additional AD server and provision it.

 What this script does:
 1. Apply appropriate SELinux context and Firewall rules
 2. Install the REPO(s) needed and dependencies needed
 3. Compile Samba RPMS
 4. Configure the DC
 5. Test for kerberos ticket and DNS
 6. Install Server Management Tools

 *********************************************"
 This will take 20-25 minutes depending on your Internet connection
 and processor speed/memory

EOF

while true; do
    read -p "Is this the First AD Server you are installing? " yn
    case $yn in
        [Yy]* ) /root/ADDCInstaller/DCInstall.sh; break;;
        [Nn]* ) /root/ADDCInstaller/DC1-Install.sh;;
        * ) echo "Please answer yes or no.";;
    esac
done
