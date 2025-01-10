#!/bin/bash
#Patch menu
items=(1 "Patch samba-dnf-pkg-update"
)

while choice=$(dialog --title "$TITLE" \
  --backtitle "Patch Update" \
  --menu "Please select the install type" 15 65 3 "${items[@]}" \
  2>&1 >/dev/tty); do
  case $choice in
  1) /root/ADDCInstaller/patches/patch-samba-dnf-pkg-update ;;

 
  esac
done
clear # clear after user pressed Cancel
