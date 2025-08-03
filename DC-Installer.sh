#!/bin/bash
#Bootstrap to GIT REPO
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
CYAN="\e[36m"
RESET="\e[0m"
USER=$(whoami)
MAJOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')
clear
echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rocky ${CYAN}RADS/FR-RADS${TEXTRESET} ${YELLOW}Bootstrap${TEXTRESET}"
# Checking for user permissions
if [ "$USER" = "root" ]; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Running as root user."
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] This program must be run as root."
  echo "Exiting..."
  exit 1
fi

# Extract the major OS version from /etc/redhat-release
if [ -f /etc/redhat-release ]; then
  MAJOROS=$(grep -oP '\d+' /etc/redhat-release | head -1)
else
  echo -e "[${RED}ERROR${TEXTRESET}] /etc/redhat-release file not found. Cannot determine OS version."
  echo "Exiting the installer..."
  exit 1
fi

# Checking for version information
if [ "$MAJOROS" -ge 9 ]; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Detected compatible OS version: Rocky 9.x or greater"
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] Sorry, but this installer only works on Rocky 9.X or greater"
  echo -e "Please upgrade to ${GREEN}Rocky 9.x${TEXTRESET} or later"
  echo "Exiting the installer..."
  exit 1
fi

echo -e "${CYAN}==>Retrieving requirements for the installer...${TEXTRESET}"

# Function to show an animated spinner
spinner() {
  local pid=$1
  local delay=0.1
  local spinstr='|/-\'

  while ps -p $pid > /dev/null; do
    for i in $(seq 0 3); do
      printf "\r[${YELLOW}INFO${TEXTRESET}] Installing... ${spinstr:$i:1}"
      sleep $delay
    done
  done
  printf "\r[${GREEN}SUCCESS${TEXTRESET}] Installation complete!  \n"
}

# Run dnf in the background
dnf -y install wget git ipcalc dialog >/dev/null 2>&1 &

# Get the PID of the last background process
dnf_pid=$!

# Start the spinner while waiting for dnf to complete
spinner $dnf_pid

echo -e "${CYAN}==>Retrieving files from Github...${TEXTRESET}"

sleep 1


#Clone RADS

mkdir -p /root/ADDCInstaller
rm -rf /root/ADDCInstaller && git clone https://github.com/fumatchu/RADS.git /root/ADDCInstaller
chmod 700 /root/ADDCInstaller/*


#Clone FR

mkdir -p /root/FR-Installer
rm -rf /root/FR-Installer && git clone https://github.com/fumatchu/FR-RADS.git /root/FR-Installer


echo -e "[${YELLOW}INFO${TEXTRESET}] Removing Git"
dnf -y remove git >/dev/null 2>&1

 clear
  echo -e "${GREEN}
                               .*((((((((((((((((*
                         .(((((((((((((((((((((((((((/
                      ,((((((((((((((((((((((((((((((((((.
                    (((((((((((((((((((((((((((((((((((((((/
                  (((((((((((((((((((((((((((((((((((((((((((/
                .(((((((((((((((((((((((((((((((((((((((((((((
               ,((((((((((((((((((((((((((((((((((((((((((((((((.
               ((((((((((((((((((((((((((((((/   ,(((((((((((((((
              /((((((((((((((((((((((((((((.        /((((((((((((*
              ((((((((((((((((((((((((((/              ((((((((((
              ((((((((((((((((((((((((                   *((((((/
              /((((((((((((((((((((*                        (((((*
               ((((((((((((((((((             (((*            ,((
               .((((((((((((((.            /(((((((
                 ((((((((((/             (((((((((((((/
                  *((((((.            /((((((((((((((((((.
                    *(*)            ,(((((((((((((((((((((((,
                                 (((((((((((((((((((((((/
                              /((((((((((((((((((((((.
                                ,((((((((((((((,
${RESET}"
  echo -e "                         ${GREEN}Rocky Linux${RESET} ${CYAN}RADS/FR-FADS${RESET} ${YELLOW}Builder${TEXTRESET}"

  sleep 2

echo " "
echo -e "
 *********************************************

 This script was created for ${GREEN}Rocky 9.x${TEXTRESET}
 This will install:
 1. A primary Samba AD/DC (and create the Forest/Domain)
                       ${YELLOW}-OR-${TEXTRESET}
 2. An additional AD server and provision it.
                       ${YELLOW}-OR-${TEXTRESET}
 3. A Member Server to a Domain for File/Print Services
                       ${YELLOW}-OR-${TEXTRESET}
 4. Provision and integrate a FreeRADIUS server

 ${RED}Each Server must be installed on a separate server (VM/Hardware) instance${TEXTRESET}

 What this script does:
 1. Apply appropriate SELinux context and Firewall rules
 2. Install the REPO(s) and any needed dependencies
 3. Compile Samba RPMS (if deploying AD)
 4. Configure the system as needed, based on your answers
 5. Provide testing for the configured platform
 6. Install Server Management Tools

 *********************************************
"
echo " "
read -p "Press Enter to Continue"


items=(1 "Install First AD Server/Create Domain"
  2 "Install Secondary/Tertiary AD Server"
  3 "Install a Member Server for File/Print Services"
  4 "Install FreeRADIUS Server"
)

while choice=$(dialog --title "$TITLE" \
  --backtitle "Server Installer" \
  --menu "Please select the install type" 15 65 3 "${items[@]}" \
  2>&1 >/dev/tty); do
  case $choice in
  1) /root/ADDCInstaller/DCInstall.sh ;;
  2) /root/ADDCInstaller/DC1-Install.sh ;;
  3) /root/ADDCInstaller/MEMInstall.sh ;;
  4) /root/FR-Installer/install.sh ;;


  esac
done
clear
