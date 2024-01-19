#!/bin/sh
#Install2
IP=$(hostname -I)
DOMAIN=$(hostname | sed 's/...//')
FQDN=$(hostname)
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
chronyc tracking
echo " " 
echo " " 
echo "We should be syncing time"
read -p "Press Any Key"

cd /root/
mkdir samba-latest
wget https://download.samba.org/pub/samba/samba-latest.tar.gz

tar --strip-components=1 -zxvf samba-latest.tar.gz -C /root/samba-latest

cd /root/samba-latest
./configure

make -j 8


make install

echo "************************************"
echo "The Next step will provision the domain"
echo "If you setup the server originally with the domain name you want,"
echo "You just need to input your password...Otherwise,"
echo "Change the following entries to what you want.. Realm/Domain"
echo "Server Role should be dc (Default)"
echo "Keep DNS backend to SAMBA_INTERNAL"
echo "************************************"

read -p "Press Enter when you're ready"

#Provision the Domain
samba-tool domain provision --use-rfc2307 --interactive


#Create KDC:
\cp -rf /usr/local/samba/private/krb5.conf /etc/krb5.conf


#Move the AD Service and enroll
\cp /root/ADDCInstaller/samba-ad-dc.service /etc/systemd/system/

echo "It looks like Samba compiled"
read -p "Press Any Key"

echo " "
echo " "
echo "It looks like your Main IP address is:"
echo " "
echo " "
echo "$IP"
echo " "
echo " "
echo "This should be the IP address that you make as your primary DNS for this system"
echo "REMOVE ALL OTHER DNS ENTRIES!"
echo "IT SHOULD ONLY BE THE MAIN IP OF THIS SERVER"
echo "The next page will take you there to modify it"
echo "Make sure you update this, otherwise AD Registrations will fail"
read -p "Press Enter When Ready"

#change domain resolution
nmtui

systemctl restart NetworkManager
echo " "
echo " "
echo "**********************"
echo "Now we are going to enable and start samba-ad-dc Service"
echo "**********************"

#Start the AD Service
systemctl enable samba-ad-dc.service
systemctl start samba-ad-dc


echo "Clean up our mess"

#clean up our mess
sed -i '$ d' /root/.bash_profile
rm -f /root/samba-latest.tar.gz
rm -r -f /root/samba-latest/

echo " "
echo " "
echo "Now we are going to do some testing"

read -p "Press any Key"
echo " "
echo " "
echo "First, we will provide output that samba is operational"
read -p 
ps -ax | grep samba
echo " "
echo "Should be running"
read -p "Press a Key to continue"

echo "Now we will check Kerberos"
kinit Administrator
klist
read -p "Press a Key to continue"
echo " "
echo " "

echo "We should check DNS OOB"
echo "If you did not change the IP earlier in nmtui, this will probably fail"
echo "Testing _ldap._tcp"
host -t SRV _ldap._tcp.$DOMAIN.
read -p "Press Any Key" 
echo " " 
echo " "
echo "Testing _udp kerberos"
host -t SRV _kerberos._udp.$DOMAIN.
read -p "Press Any Key" 
echo " " 
echo " "
echo "Testing A Record of Domain Controller"
host -t A $FQDN.
read -p "Press Any Key"
echo " " 
echo " "

