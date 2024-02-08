#!/bin/sh
#DC-Installer.sh #Bootstrap to GIT REPO
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
