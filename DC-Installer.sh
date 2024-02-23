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
**************************
Please wait while we gather some files
**************************


Installing wget and git
EOF
sleep 1

dnf -y install wget git

cat <<EOF
*****************************
Retrieving Files from GitHub
*****************************
EOF

sleep 1

mkdir /root/ADDCInstaller

git clone https://github.com/fumatchu/RADS.git /root/ADDCInstaller

chmod 700 /root/ADDCInstaller/DC*
clear

/root/ADDCInstaller/DCInstall.sh
