#!/bin/bash
clear
echo "This is the patch file"
clear
cd /root/
# Define the file to check for and the URL to download
CHECK_FILE="/usr/bin/samba-dnf-pkg-update"
DOWNLOAD_URL="https://raw.githubusercontent.com/fumatchu/RADS/main/patches/samba-dnf-pkg-update"
DOWNLOAD_DEST="/root/samba-dnf-update-patch.sh"
FOLDER="/usr/bin/"
DOWNLOAD_FINAL_FILE="samba-dnf-pkg-update"
# Check if the file exists
if [ -f "$CHECK_FILE" ]; then
    # Download the script to the root directory
    echo "Found samba-dnf-pkg-update"
    echo "Downloading Patch"
    wget -O "$DOWNLOAD_DEST" "$DOWNLOAD_URL"
    
    # Change permissions to make it executable
    chmod 700 "$DOWNLOAD_DEST"
    
    #Move the file to /usr/bin/
    mv -v "$DOWNLOAD_FINAL_FILE" "$FOLDER"

    
    
else
    echo "File $CHECK_FILE not found. Exiting."
fi
echo "Complete"
read -p "Press Any Key"
