#!/bin/bash
# This patch file will update dnf-update errors where dc rpm does not install
# Updates dnf-smb-mon for makecache versions
# puts a checker into server manager for motd content if dnf-smb-mon sees variance
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
  if \cp -f "$PATCH_FILE" "$DESTINATION_FILE"; then
    chmod 700 "$DESTINATION_FILE"
    echo "${GREEN}The patch file was successfully moved to $DESTINATION_FILE.${TEXTRESET}"
    sleep 2
    
    # Compare the moved file with the original file
    echo "${YELLOW}Comparing the Patch file to the file on the system" ${TEXTRESET}
    if diff -q "$DESTINATION_FILE" "$PATCH_FILE" > /dev/null; then
      echo "${GREEN}The patch file matches the active file.${TEXTRESET}"
    else
      echo "${RED}The patch file does not match the active file.${TEXTRESET}"
      echo "Exiting the script."
      sleep 5
      exit 1
    fi
    #Update RADS-SM for the update script 
    # Define the file path
FILE_PATH="/root/.servman/SambaMan"

# Use sed to replace the specific line
sed -i 's|6) /root/.servman/SambaManager/sm-samba-dnf-pkg-update ;;|6) /usr/bin/samba-dnf-pkg-update ;;|' "$FILE_PATH"

# Check if the operation was successful
if [ $? -eq 0 ]; then
  echo "The line was successfully updated in $FILE_PATH."
else
  echo "Failed to update the line in $FILE_PATH."
fi
    #Cleanup
    rm -r -f /root/RADSPatch/
    

#UPDATE server-manager for smb-mon
# Define the path for the server-manager script
echo ${GREEN}"Updating Server-Manager"${TEXTRESET}
SERVER_MANAGER_PATH="/usr/bin/server-manager"

# Remove the existing server-manager file if it exists
if [ -f "$SERVER_MANAGER_PATH" ]; then
    rm "$SERVER_MANAGER_PATH"
    echo ${GREEN}"Deleted existing $SERVER_MANAGER_PATH."${TEXTRESET}
fi

# Create a new server-manager file with the given content
cat << 'EOF' > "$SERVER_MANAGER_PATH"
#!/bin/bash
TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
user=$(whoami)

# Checking for user permissions
if [ "$user" != "root" ]; then
  echo ${RED}"This program must be run as root ${TEXTRESET}"
  echo "Exiting"
  exit
else
  echo "Running Program"
fi

MOTD_FILE="/etc/motd"
EXECUTABLE="/usr/bin/samba-dnf-pkg-update"

# Check if the MOTD file is empty
if [ -s "$MOTD_FILE" ]; then
  # Display the contents of the MOTD file
  cat "$MOTD_FILE"
  
  # Prompt the user if they want to run the executable
  read -p "Do you want to run the $EXECUTABLE? (y/n): " response
  
  # Convert the response to lowercase
  response=$(echo "$response" | tr '[:upper:]' '[:lower:]')
  
  # Run the executable if the user agrees
  if [ "$response" == "y" ] || [ "$response" == "yes" ]; then
    if [ -x "$EXECUTABLE" ]; then
      echo "Running $EXECUTABLE..."
      "$EXECUTABLE"
    else
      echo "Error: $EXECUTABLE is not executable or not found."
    fi
  else
    echo "The executable was not run."
  fi
else
  echo ""
fi

items=(
  1 "Active Directory Management"
  2 "DHCP Management"
  3 "Samba Service Management"
  4 "System Management"
  5 "Server Management Options"
  6 "System Tools"
  7 "Welcome to Server Manager"
)

while choice=$(dialog --title "Server Manager" \
  --backtitle "Server Management" \
  --menu "Please select" 20 40 3 "${items[@]}" \
  2>&1 >/dev/tty); do
  case $choice in
  1) /root/.servman/ADMan ;;  # some action on 1
  2) /root/.servman/DHCPMan ;; # some action on 2
  3) /root/.servman/SambaMan ;;
  4) /root/.servman/SYSMan ;; # some action on other
  5) /root/.servman/SERVMan ;;
  6) /root/.servman/TOOLMan ;;
  7) /root/.servman/welcome.readme | more ;;
  esac
done

clear # clear after user pressed Cancel
EOF

# Set the script as executable with permissions 700
chmod 700 "$SERVER_MANAGER_PATH"
echo ${GREEN}"Created and set permissions for $SERVER_MANAGER_PATH."${TEXTRESET}

# Validate the contents of the new file
if grep -q "#!/bin/bash" "$SERVER_MANAGER_PATH"; then
    echo ${GREEN}"The contents of $SERVER_MANAGER_PATH have been verified."${TEXTRESET}
else
    echo "Error: The contents of $SERVER_MANAGER_PATH could not be verified."
fi
    
#UPDATE smb-mon

echo ${GREEN}"Updating smb-mon"${TEXTRESET}
# Define the file path
FILE_PATH="/usr/bin/dnf-smb-mon"

# Remove the existing file, if it exists
if [ -f "$FILE_PATH" ]; then
    rm -f "$FILE_PATH"
    echo "Removed existing file at $FILE_PATH"
fi

# Create a new file and add the specified content
cat << 'EOF' > "$FILE_PATH"
#!/bin/bash
#Patch 1.0
#dnf_smb_mon
#Monitoring script that will compare the @System Repository with the Upstream Repository for Samba DC
#If a match between the files are resolved, there will be no update
#If a match is NOT resolved between files, a message will be sent to MOTD and upon next login
#the (root) User should run "samba-dnf-pkg-update"

#Update the DNF cache
dnf makecache

#Get the Samba versions from the provides output
VERSIONS=$(dnf provides samba | grep -oP 'samba = \K[0-9]+.[0-9]+.[0-9]+-[0-9]+')

#Convert the versions to an array
VERSION_ARRAY=($VERSIONS)

#Check if two versions were found
if [ ${#VERSION_ARRAY[@]} -lt 2 ]; then
 echo "Not enough version information found. Please check your DNF configuration."
 exit 1
fi

#Extract the first and second versions
VERSION1=${VERSION_ARRAY[0]}
VERSION2=${VERSION_ARRAY[1]}

#Compare the versions
if [ "$VERSION1" == "$VERSION2" ]; then
 logger -s "dnf-smb-mon: The Samba versions match: $VERSION1. Repositories are in sync." 2>>/var/log/dnf-smb-mon.log
else
 cat <<EOM > /etc/motd
ATTENTION!
dnf_smb_mon sees a difference between the @System dnf repository
for Samba and the dnf repository upstream. This probably means that
the upstream Samba packages are a new version and the --dc packages
are now out of date.
Found versions: $VERSION1 and $VERSION2
You should probably run the command samba-dnf-pkg-update from the cli
or samba service management --> samba update (from server-manager).
EOM
 logger -s "dnf-smb-mon: Repositories are NOT in sync. Found versions: $VERSION1 and $VERSION2. Review and run samba-dnf-pkg-update." 2>>/var/log/dnf-smb-mon.log
fi
EOF

# Make the new file executable with 700 permissions
chmod 700 "$FILE_PATH"
echo ${GREEN}"Created new file at $FILE_PATH with 700 permissions"${TEXTRESET}

# Validate the file was updated
if [ -f "$FILE_PATH" ]; then
    echo ${GREEN}"File $FILE_PATH successfully created and updated."${TEXTRESET}
else
    echo ${RED}"Failed to create or update $FILE_PATH."${TEXTRESET}
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
