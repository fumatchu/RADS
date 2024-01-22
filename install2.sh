#!/bin/sh
#Install2
IP=$(hostname -I)
DOMAIN=$(hostname | sed 's/...//')
FQDN=$(hostname)
PRI_INT=$(nmcli | grep "connected to")
REVERSE=$(echo "$IP" | { IFS=. read q1 q2 q3 q4; echo "$q3.$q2.$q1"; })
echo " "
echo " "
echo "*********************************************"
echo " "
echo "THIS IS PART TWO OF THE SCRIPT TO INSTALL SAMBA AD/DC"
echo " "
echo " "
echo " "
echo "What this script does:"
echo "1. Will configure this server to get time from pool.ntp.org"
echo "2. Download and compile the samba latest from samba.org"
echo "3. Will provision the Samba AD/DC"
echo "4. Will have you manually adjust the DNS resolver. The Server must point to itself"
echo "5. Setup krb5 from the Samba install"
echo "6. Create the samba-ad-dc service for boot"
echo "7. Do some testing to validate Samba/AD resources are running and operational"
tput setaf 1; echo "PLEASE STAY AT THE CONSOLE-THIS IS INTERACTIVE"; tput sgr0
echo " "
echo "*********************************************"
echo " "
echo "This will take around 15-20 minutes depending on your Internet connection"
echo "and processor speed/memory"
echo " "
read -p "Press Enter when you're ready"
echo " "
echo "Setting a valid time source"
read -p "Press Any Key"
sed -i '/server /c\pool pool.ntp.org iburst' /etc/chrony.conf
systemctl restart chronyd
echo "Sleeping for 10 seconds for chrony"
sleep 10s
clear
chronyc tracking
echo " " 
echo " " 
echo "We should be syncing time"
read -p "Press Any Key"
clear
cd /root/
mkdir samba-latest
wget https://download.samba.org/pub/samba/samba-latest.tar.gz

tar --strip-components=1 -zxvf samba-latest.tar.gz -C /root/samba-latest

cd /root/samba-latest
./configure

make -j 8


make install
clear
echo "************************************"
echo "The Next step will provision the domain"
echo "If you setup the server originally with the domain name you want,"
echo "You just need to input the password you want to create for the Domain Administrator account"
echo "Accept all other defaults"
echo "************************************"

read -p "Press Enter when you're ready"
clear
#Provision the Domain
samba-tool domain provision --use-rfc2307 --interactive


#Create KDC:
\cp -rf /usr/local/samba/private/krb5.conf /etc/krb5.conf


#Move the AD Service and enroll
\cp /root/ADDCInstaller/samba-ad-dc.service /etc/systemd/system/

echo "It looks like Samba compiled"
read -p "Press Any Key"
clear
echo " "
echo " "
echo "Your Primary IP address is:"
echo " "
echo " "
echo "$IP" 
echo "via the interface"
echo $PRI_INT
echo " "
echo " "
echo "This should be the IP address that you make as your primary DNS for this system"
echo " "
tput setaf 1; echo "REMOVE ALL OTHER DNS ENTRIES!"; tput sgr0
echo " "
echo "The next page will take you there to modify it via your interface"
echo "Make sure you update this, otherwise AD Registrations will fail"
echo "This is an AD server and it must point to itself"
echo "Once the DNS server entry has been modified, navigate back and quit the application"
read -p "Press Enter When Ready"

#change domain resolution
nmtui

systemctl restart NetworkManager
clear
echo " "
echo " "
echo "**********************"
echo "Now we are going to enable and start samba-ad-dc Service"
echo "**********************"

read -p "Press enter to continue"

#Start the AD Service
systemctl enable samba-ad-dc.service
systemctl start samba-ad-dc

ps-ax | grep samba

echo "Process should be up and running"
read -p "Press enter to continue"


echo " "
echo "Now we are going to do some testing"
echo "These tests came from:"
echo "https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller#Troubleshooting"
echo " "
echo "If you would like, please following along from that link"
echo " "
read -p "Press enter to continue" 
clear
echo " "
echo "First, we will provide output that samba is operational"
echo "Press "q" to exit the scroll output"
read -p "Press enter to continue"
clear
systemctl status samba-ad-dc.service
echo " "
echo "Should be running"
read -p "Press enter to continue"
clear
echo " "
echo "Now we will check Kerberos"
echo "You must supply the domain Password you created earlier"
kinit Administrator
klist
read -p "Press enter to continue"
echo " "
echo " "
clear
echo " "
echo "We should check DNS OOB"
echo " "
echo "Testing _ldap._tcp"
echo " "
echo " "
echo "The result should have similar formatting to this:"
echo " "
echo "_ldap._tcp.samdom.example.com has SRV record 0 100 389 dc1.samdom.example.com."
echo " "
echo "And the actual result is"
echo " "
echo " "
tput setaf 1; host -t SRV _ldap._tcp.$DOMAIN.; tput sgr0
echo " "
echo " "
read -p "Press enter to continue" 
clear
echo " " 
echo " "
echo "Testing _udp kerberos"
echo " "
echo " "
echo "The result should have similar formatting to this:"
echo " "
echo "_kerberos._udp.samdom.example.com has SRV record 0 100 88 dc1.samdom.example.com."
echo " "
echo "And the actual result is"
echo " "
echo " "
tput setaf 1; host -t SRV _kerberos._udp.$DOMAIN.; tput sgr0
echo " "
echo " "
read -p "Press enter to continue" 
echo " " 
echo " "
clear
echo "Testing A Record of Domain Controller"
echo " "
echo " "
echo "The result should have similar formatting to this:"
echo " "
echo "dc1.samdom.example.com has address 10.99.0.1"
echo " "
echo "And the actual result is"
echo " "
echo " "
tput setaf 1; host -t A $FQDN."; tput sgr0
echo " "
read -p "Press enter to continue" 
echo " " 
echo " "
clear
echo "If all tests returned valid, you have successfully installed AD on your Rocky Server!"
echo "Congratulations!"
echo "The last thing that should be done is add a reverse zone in DNS."
echo "Based on your configuration, and assuming a Class C subnet, your command should be:"
echo " "
echo " "
tput setaf 1; echo ""samba-tool dns zonecreate $FQDN $REVERSE.in-addr.arpa -U Administrator w/o quotes""; tput sgr0
echo " "
echo " "
echo "Please add this as approriate and apply it to the system"
echo "After that is complete, please reboot the system with the command"
tput setaf 1; echo "reboot"; tput sgr0

#clean up our mess
sed -i '$ d' /root/.bash_profile
rm -f /root/samba-latest.tar.gz
rm -r -f /root/samba-latest/

