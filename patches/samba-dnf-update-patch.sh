#!/bin/bash

# Define colors for output
TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)

# Get current user
USER=$(whoami)

# Checking for user permissions
if [ "$USER" != "root" ]; then
  echo "${RED}This program must be run as root${TEXTRESET}"
  echo "Exiting"
  exit 1
fi

# Checking for version Information
MAJOROS=$(grep -oP '(?<=^VERSION_ID=")[0-9]+' /etc/os-release)

if [ "$MAJOROS" != "9" ]; then
  echo "${RED}Sorry, but this installer only works on Rocky 9.X${TEXTRESET}"
  echo "Please upgrade to ${GREEN}Rocky 9.x${TEXTRESET}"
  echo "Exiting the installer..."
  exit 1
fi

# Define file paths
CURRENT_FILE="/usr/bin/samba-dnf-pkg-update"
PATCH_FILE="/root/RADSPatch/samba-dnf-pkg-update"
DESTINATION_FILE="/usr/bin/samba-dnf-pkg-update"

# Check if the line #Patch1.0 is present in the current file
if ! grep -q "#Patch1.0" "$CURRENT_FILE"; then
  echo "${YELLOW}The file is an older version and will be updated${TEXTRESET}"
  sleep 2
  
  # Move the patch file to the destination
  if mv "$PATCH_FILE" "$DESTINATION_FILE"; then
    chmod 700 "$DESTINATION_FILE"
    echo "${GREEN}The patch file was successfully moved to $DESTINATION_FILE.${TEXTRESET}"
    sleep 2
    
    # Compare the moved file with the original file
    if diff -q "$DESTINATION_FILE" "$PATCH_FILE" > /dev/null; then
      echo "${GREEN}The moved file matches the original file.${TEXTRESET}"
    else
      echo "${RED}The moved file does not match the original file.${TEXTRESET}"
      echo "Exiting the script."
      exit 1
    fi

    # Ask the user if they want to run the file
    read -p "Do you want to run the file samba-dnf-pkg-update now (This will start the samba update to latest version using mock)? (yes/no): " response

    # Convert the response to lowercase
    response=$(echo "$response" | tr '[:upper:]' '[:lower:]')

    # Run the file if the user agrees
    if [ "$response" = "yes" ]; then
      bash "$DESTINATION_FILE"
    else
      echo "${RED}The file was not run.${TEXTRESET}"
      echo "You have updated the package updater file, but it has not been run. You have only patched the file."
      echo "In order to actually update the server to the latest version of samba, you must run /usr/bin/samba-dnf-pkg-update as root."
    fi
  else
    echo "${RED}The file was not successfully moved.${TEXTRESET}"
  fi
else
  echo "The file already contains #Patch1.0."
fi

read -p "Press Enter to continue..."
