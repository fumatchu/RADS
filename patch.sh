#!/bin/bash
#Patch menu
items=(1 "Patch samba-dnf-pkg-update"
)

while choice=$(dialog --title "$TITLE" \
  --backtitle "Patch Update" \
  --menu "Please select the install type" 15 65 3 "${items[@]}" \
  2>&1 >/dev/tty); do
  case $choice in
  1) clear & cd /root &&  bash <(wget -qO- https://raw.githubusercontent.com/fumatchu/RADS/main/patches/samba-dnf-update-patch.sh) ;;

 
  esac
done
clear # clear after user pressed Cancel
