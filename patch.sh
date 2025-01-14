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

clear 
cat << EOF
${GREEN}Patch update${TEXTRESET}
This patch will do the following:
Correct an issue when upgrading from 9.X to the latest version for the Samba src. rpm
Correct an issue with mis-reporting samba sync between upstream repository and local install 
Updated server-manager to check the sync logs before bringing up the main menu in dialog.

${GREEN}The Patch has the following process:${TEXTRESET}
Check in with dnf first. If there are updates, download them and install them ${GREEN}(a reboot is not necessary)${TEXTRESET} 
If there are no updates, the installer will continue to patch the system. 
It will replace samaba-dnf-pkg-update, dnf-smb-mon, and server-manager 
${YELLOW}YOU MUST MAKE SURE YOU HAVE INTERNET CONNECTIVITY${TEXTRESET}
(Assuming you are reading this, you have changed your dns entry on this server to something other than the Samba local).
If for some odd reason you still have internet connectivity you should do the following:
Make sure you have set your ${YELLOW}DNS entry on this server to something else (8.8.8.8, 208.67.222.222)${TEXTRESET}
You can do this with ${YELLOW}nmtui${TEXTRESET}
Run the command ${YELLOW}systemctl restart NetworkManager${TEXTRESET}
Run ${YELLOW}nmcli${TEXTRESET} to validate that the DNS entry is updated to the ${YELLOW}external DNS.${TEXTRESET}
After the patches are applied, the patch itself will ask you if you want to update samba using mock (in most cases, you will want to do this- This upgrades Samba to latest version)
The patch will then compile samba to the latest version and validate the install.
It will also change the External DNS entry back to the appropriate IP on your system. 
After that, yes, you should ${RED}reboot${TEXTRESET}

EOF

# Prompt the user
read -p "Do you want to proceed with patching? (y/n): " choice

# Convert input to lowercase
choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')

# Check the user's choice
if [[ "$choice" == "y" || "$choice" == "yes" ]]; then
    echo "Continuing with the script..."
    # Add your script logic here
    echo ${GREEN}"Proceeding..."${TEXTRESET}
else
    echo ${RED}"Exiting the script."${TEXTRESET}
    exit 0
fi
#Check that Pacakges are up to date on the server.
# Run dnf check-update and capture the output, ignoring the metadata expiration line
UPDATE_OUTPUT=$(dnf check-update | grep -v '^Last metadata expiration check:')

# Check if there are any lines in the output indicating available updates
if echo "$UPDATE_OUTPUT" | grep -q '^[[:alnum:]]'; then
  echo ${YELLOW}"There are new packages available for update."${TEXTRESET}
  echo "Updating Server"
  sleep 5
  dnf -y update
  echo ${GREEN}"Restarting NetworkManager"${TEXTRESET}
  systemctl restart NetworkManager
  sleep 5
  echo "The OS update is complete, but the patch has ${RED}NOT been installed"${TEXTRESET}
  echo " "
  echo ${YELLOW}"Make sure your server can resolve via external DNS first.${TEXTRESET} ${RED}It should not be pointed to your AD DNS."${TEXTRESET}
  echo "This can be accomplished using ${YELLOW}nmtui${TEXTRESET}, editing the ${YELLOW}dns server${TEXTRESET}, then running ${YELLOW}systemctl restart NetworkManager"${TEXTRESET}
  echo "After that is complete, restart the patch process with this link here:"
  echo ${YELLOW}"dnf -y install wget && cd /root &&  bash <(wget -qO- https://raw.githubusercontent.com/fumatchu/RADS/main/patch.sh)"${TEXTRESET}
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
