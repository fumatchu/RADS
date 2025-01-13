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
    wget -O "$DOWNLOAD_DEST" "$DOWNLOAD_URL"
    
    # Change permissions to make it executable
    chmod 700 "$DOWNLOAD_DEST"    
else
    echo "File $CHECK_FILE not found. Exiting."
fi

# Specify the file path
FILE_PATH="/root/samba-dnf-pkg-update"
DEST_PATH="/usr/bin/samba-dnf-pkg-update"

# Check if the file contains the line #Patch1.0
if grep -q "#Patch1.0" "$FILE_PATH"; then
    # Move the file to the destination
    mv "$FILE_PATH" "$DEST_PATH"
    echo "The file was successfully moved to $DEST_PATH."
#Cleanup
rm -r -f /root/RADSpatch/
rm -f /root/samba*
    # Ask the user if they want to run the file
    read -p "Do you want to run the file? (yes/no): " response

    # Convert the response to lowercase
    response=$(echo "$response" | tr '[:upper:]' '[:lower:]')

    # Run the file if the user agrees
    if [ "$response" = "yes" ]; then
        bash "$DEST_PATH"
    else
        echo "The file was not run."
    fi
else
    echo "The file was not successfully moved because #Patch1.0 was not found."
fi
echo "Complete"
read -p "Press Any Key"
