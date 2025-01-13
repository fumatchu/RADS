#!/bin/bash
TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
USER=$(whoami)
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

cd /root/

# Define file paths
CURRENT_FILE="/usr/bin/samba-dnf-pkg-update"
PATCH_FILE="/root/RADSPatch/samba-dnf-pkg-update"
DESTINATION_FILE="/usr/bin/samba-dnf-pkg-update"

# Check if the line #Patch1.0 is present in the current file
if ! grep -q "#Patch1.0" "$CURRENT_FILE"; then
    echo "The file is an older version and will be updated"
    sleep 2

    # Move the patch file to the destination
    if mv "$PATCH_FILE" "$DESTINATION_FILE"; then
        chmod 700 "$DESTINATION_FILE"
        echo "The patch file was successfully moved to $DESTINATION_FILE."
        sleep 2
        # Ask the user if they want to run the file
        read -p "Do you want to run the file samba-dnf-pkg-update now (This will start the samba update using mock)? (yes/no): " response

        # Convert the response to lowercase
        response=$(echo "$response" | tr '[:upper:]' '[:lower:]')

        # Run the file if the user agrees
        if [ "$response" = "yes" ]; then
            bash "$DESTINATION_FILE"
        else
            echo "The file was not run."
        fi
    else
        echo "The file was not successfully moved."
    fi
else
    echo "The file already contains #Patch1.0."
fi
read -p "Press Enter"
