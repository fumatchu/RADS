#!/bin/bash
echo "This is the patch file"
read -p "Press Enter"

# Define the file to check for and the URL to download
CHECK_FILE="/usr/bin/samba-dnf-pkg-update"
DOWNLOAD_URL="https://raw.githubusercontent.com/fumatchu/RADS/main/patches/samba-dnf-update-patch.sh"
DOWNLOAD_DEST="/root/samba-dnf-update-patch.sh"

# Check if the file exists
if [ -f "$CHECK_FILE" ]; then
    # Download the script to the root directory
    wget -O "$DOWNLOAD_DEST" "$DOWNLOAD_URL"
    
    # Change permissions to make it executable
    chmod 700 "$DOWNLOAD_DEST"
    
    # Run the downloaded script
    "$DOWNLOAD_DEST"
else
    echo "File $CHECK_FILE not found. Exiting."
fi

