#!/bin/bash
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

dnf -y install wget git dialog

cat <<EOF
${YELLOW}*****************************
Retrieving Files from GitHub
*****************************${TEXTRESET}
EOF

sleep 1

mkdir -p /root/RADSPatch

git clone https://github.com/fumatchu/RADS.git /root/RADSPatch

#Check that Pacakges are up to date on the server.
# Run dnf check-update and capture the output, ignoring the metadata expiration line
UPDATE_OUTPUT=$(dnf check-update | grep -v '^Last metadata expiration check:')

# Check if there are any lines in the output indicating available updates
if echo "$UPDATE_OUTPUT" | grep -q '^[[:alnum:]]'; then
  echo ${RED}"There are new packages available for update."${TEXTRESET}
  echo "Updating Server"
  sleep 5
  dnf -y update
  echo ${GREEN}"Restarting NetworkManager"${TEXTRESET}
  systemctl restart NetworkManager
  sleep 5
  echo "The OS update is complete, but the patch has ${RED}NOT been installed"${TEXTRESET}
  echo " "
  echo "Make sure your server can resolve via external DNS first. It should not be pointed to your AD DNS."
  echo "This can be accomplished using nmtui, editing the dns server, then running systemctl restart NetworkManager"
  echo "After that is complete, restart the patch process with this link here:"
  echo "dnf -y install wget && cd /root &&  bash <(wget -qO- https://raw.githubusercontent.com/fumatchu/RADS/main/patch.sh)"
  read -p "Press Enter"
  exit
else
  echo ${GREEN}"No new packages available."${TEXTRESET}
  echo "Proceeding..."
  sleep 2
fi

items=(1 "Patch samba-dnf-pkg-update"
2 "Exit Patch Management"
)

while choice=$(dialog --title "$TITLE" \
  --backtitle "Patch Update" \
  --menu "Please select the install type" 15 65 3 "${items[@]}" \
  2>&1 >/dev/tty); do
  case $choice in
 1) clear && cd /root && chmod 700 /root/RADSPatch/patches/samba-dnf-update-patch.sh && /root/RADSPatch/patches/samba-dnf-update-patch.sh;;
 2) exit ;;
 
  esac
done
clear # clear after user pressed Cancel
