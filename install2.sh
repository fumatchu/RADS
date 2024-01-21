#!/bin/sh
#Install2
IP=$(hostname -I)
DOMAIN=$(hostname | sed 's/...//')
FQDN=$(hostname)
PRI_INT=$(nmcli | grep "connected to")
echo " "
echo " "
echo "*********************************************"
echo " "
echo "THIS IS PART TWO OF THE SCRIPT TO INSTALL SAMBA AD/DC"
echo " "
echo " "
echo " "
echo "What this script does:"
echo "1. Downloads and compiles the samba latest from samba.org"
echo "2. Will provision the Samba AD/DC"
echo "3. Setup krb5 from the Samba install"
echo "4. Create the samba-ad-dc service for boot"
echo "5. PLEASE STAY AT THE CONSOLE-THIS IS INTERACTIVE"
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
echo "You just need to input your password...Otherwise,"
echo "Change the following entries to what you want.. Realm/Domain"
echo "Server Role should be dc (Default)"
echo "Keep DNS backend to SAMBA_INTERNAL"
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
echo "REMOVE ALL OTHER DNS ENTRIES!"
echo " "
echo "The next page will take you there to modify it via your interface"
echo "Make sure you update this, otherwise AD Registrations will fail"
echo "This is an AD server and it must point to itself"
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

#Start the AD Service
systemctl enable samba-ad-dc.service
systemctl start samba-ad-dc

echo " "
echo " "
echo "Now we are going to do some testing"

read -p "Press enter to continue" 
clear
echo " "
echo " "
echo "First, we will provide output that samba is operational"
echo "Press "q" to exit the scroll output"
read -p "Press enter to continue"
systemctl status samba-ad-dc.service
echo " "
echo "Should be running"
read -p "Press enter to continue"
clear

echo "Now we will check Kerberos"
echo "You must supply the domain Password you created earlier"
kinit Administrator
klist
read -p "Press enter to continue"
echo " "
echo " "
clear

echo "We should check DNS OOB"
echo "If you did not change the DNS IP earlier, this will probably fail"
echo "Testing _ldap._tcp"
echo "The result should have similar formatting to this:"
echo "_ldap._tcp.samdom.example.com has SRV record 0 100 389 dc1.samdom.example.com."
echo "And actual the result is"
host -t SRV _ldap._tcp.$DOMAIN.
echo " "
echo " "
echo " "
read -p "Press enter to continue" 
clear
echo " " 
echo " "
echo "Testing _udp kerberos"
echo "The result should have similar formatting to this:"
echo"_kerberos._udp.samdom.example.com has SRV record 0 100 88 dc1.samdom.example.com."
echo "And actual the result is"
host -t SRV _kerberos._udp.$DOMAIN.
read -p "Press enter to continue" 
echo " " 
echo " "
clear
echo "Testing A Record of Domain Controller"
echo "The result should have similar formatting to this:"
echo "dc1.samdom.example.com has address 10.99.0.1"
echo "And actual the result is"
host -t A $FQDN.
read -p "Press enter to continue" 
echo " " 
echo " "

echo "Clean up our mess"

#clean up our mess
sed -i '$ d' /root/.bash_profile
rm -f /root/samba-latest.tar.gz
rm -r -f /root/samba-latest/

