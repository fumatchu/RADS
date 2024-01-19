#!/bin/sh
#install.sh
echo "**************************"
echo "Please wait while we gather some files"
echo "**************************"

echo " "
echo "Installing wget and git"
echo " "

dnf -y install wget git 

echo " "
echo "Retreiving Files from github"

mkdir /root/ADDCInstaller

git clone https://github.com/fumatchu/DaD.git /root/ADDCInstaller

chmod 700 /root/ADDCInstaller/i*

/root/ADDCInstaller/install1.sh