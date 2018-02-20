#!/bin/bash
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}If system time is wrong, lots of things break. Updating now...${NC}"

apt-get install -y ntpdate
ntpdate -s time.nist.gov
D=$(date)
echo "Date has been set to $D"

read -p "Specify the user which the sandbox will run as: " LABUSER

if [ -z "$(getent passwd "$LABUSER")" ]; then
    echo -e "${RED}Please create user $LABUSER before running this script${NC}"
    exit 1
fi

echo "The sandbox name will be used for directory naming, database name and database user."
echo "It is not essential for you to have noted down the database password as it is also written to the scripts' config files."
read -p "What name do you want to give the sandbox? " SBXNAME
read -s -p "Please create a password for the database: " DBPASS
echo ""
read -p "Please enter a country code for the SSL certificate: " CCODE
read -p "Please enter the gateway IP address you wish the VM virtual network to have: " GATEWAY_IP
read -p "Please enter the netmask for the VM virtual network: " NETMASK
echo ""
echo "You have specified the following settings:"
echo "Sandbox user: 			$LABUSER"
echo "Sandbox name: 			$SBXNAME"
echo "SSL Country Code: 		$CCODE"
echo "VM network gateway IP:		$GATEWAY_IP"
echo "VM network netmask: 		$NETMASK"
echo ""
read -p "Press enter to accept these settings and install the sandbox" CONTINUE

SCRIPTDIR=$(dirname "$(realpath "$0")")

# User requires dnsmasq to be in $PATH in order to edit libvirt virtual networks
echo "PATH=$PATH:/usr/sbin" >> "/home/$LABUSER/.bash_profile"
# Running virt-manager outputs garbage errors about inability to use accessibility bus - hide these
echo "export NO_AT_BRIDGE=1" >> "/home/$LABUSER/.bash_profile"

chown "$LABUSER:$LABUSER" "/home/$LABUSER/.bash_profile"

echo -e "${GREEN}Running basic updates...${NC}"

# stock version of postgresql (9.4) does not support ON CONFLICT
#echo "deb http://apt.postgresql.org/pub/repos/apt/ jessie-pgdg main" >> /etc/apt/sources.list.d/pgdg.list
#wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -

apt-get update -y
apt-get upgrade -y
apt-get dist-upgrade -y

echo -e "${GREEN}Installing core dependencies...${NC}"
# stretch does not include npm with default nodejs install
curl -sL https://deb.nodesource.com/setup_9.x | sudo -E bash -

apt-get install -y python3-pip nodejs nginx libjpeg-dev curl tcpdump libcap2-bin libcap-ng-dev libmagic-dev libjansson-dev libpcre3 libpcre3-dbg libpciaccess-dev
apt-get install -y libpcre3-dev postgresql-9.6 postgresql-contrib curl libpcap-dev git screen python3-lxml tor libguestfs-tools libffi-dev libssl-dev tshark
apt-get install -y libnl-3-dev libnl-route-3-dev libxml2-dev libdevmapper-dev libyajl2 libyajl-dev pkg-config libyaml-dev build-essential libpq-dev python3-libvirt
apt-get install -y libnet1-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 libnss3-dev libgeoip-dev liblua5.1-dev libhiredis-dev libevent-dev libgeoip-dev python3-dev
apt-get install -y clamav clamav-daemon clamav-freshclam python3-guestfs xsltproc pm-utils
apt-get install -y libpciaccess-dev # debian stretch
apt-get upgrade -y dnsmasq

# failed to find in stretch: libopenjpeg-dev

echo -e "${GREEN}Installing python dependencies...${NC}"
# apt-get remove -y python-cffi # probably not required anymore
pip3 install --upgrade Pillow
pip3 install --upgrade twisted
pip3 install scapy-python3 pytest vncdotool Pillow pika psycopg2 arrow pyshark psutil tabulate ipaddress xmljson
# vncdotool currently has bugs in python3 - can't move this to py3 just yet

echo -e "${GREEN}Installing Python EVTX Parser by Willi Ballenthin...${NC}"
pip3 install git+https://github.com/williballenthin/python-evtx
# cd /tmp
# git clone https://github.com/williballenthin/python-evtx
# cd python-evtx
# python3 setup.py install

echo -e "${GREEN}Installing global nodejs packages...${NC}"
apt-get install nodejs
npm cache clean -f
npm install -g n
# lots of features missing from repository version of nodejs - update it
n stable
npm install nodemon -g --save

echo -e "${GREEN}Configuring database...${NC}"
su -c "psql -c \"CREATE USER $SBXNAME WITH PASSWORD '$DBPASS';\"" postgres
su -c "psql -c \"CREATE DATABASE $SBXNAME;\"" postgres
su -c "psql $SBXNAME < $SCRIPTDIR/res/schema.sql" postgres
su -c "psql $SBXNAME -c \"GRANT ALL PRIVILEGES ON DATABASE $SBXNAME TO $SBXNAME;\"" postgres
su -c "psql $SBXNAME -c \"GRANT ALL ON TABLE workerstate TO $SBXNAME;\"" postgres
su -c "psql $SBXNAME -c \"GRANT ALL ON TABLE victims TO $SBXNAME;\"" postgres
su -c "psql $SBXNAME -c \"GRANT ALL ON TABLE suspects TO $SBXNAME;\"" postgres
su -c "psql $SBXNAME -c \"GRANT ALL ON TABLE cases TO $SBXNAME;\"" postgres
su -c "psql $SBXNAME -c \"GRANT ALL ON TABLE sysmon_evts TO $SBXNAME;\"" postgres
su -c "psql $SBXNAME -c \"GRANT ALL ON TABLE suricata_dns TO $SBXNAME;\"" postgres
su -c "psql $SBXNAME -c \"GRANT ALL ON TABLE suricata_http TO $SBXNAME;\"" postgres
su -c "psql $SBXNAME -c \"GRANT ALL ON TABLE suricata_alert TO $SBXNAME;\"" postgres
su -c "psql $SBXNAME -c \"GRANT ALL ON TABLE suricata_tls TO $SBXNAME;\"" postgres
su -c "psql $SBXNAME -c \"GRANT ALL ON TABLE pcap_summary TO $SBXNAME;\"" postgres
su -c "psql $SBXNAME -c \"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO $SBXNAME;\"" postgres

echo -e "${GREEN}Granting user permissions for packet capture...${NC}"
chmod +s /usr/sbin/tcpdump
groupadd pcap
usermod -a -G pcap "$LABUSER"
chgrp pcap /usr/sbin/tcpdump
chmod 750 /usr/sbin/tcpdump
# possibly only python needs cap_net_raw but setting on both to be sure
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.5
# setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.6
# when running as non-root, tcpdump looks for gettext in the wrong place (as does libvirt)
ln -s /usr/bin/gettext.sh /usr/local/bin/gettext.sh

echo -e "${GREEN}Directory structure creation...${NC}"
addgroup libvirt-qemu
addgroup "$SBXNAME"
mkdir -v /usr/local/unsafehex/
mkdir -v "/usr/local/unsafehex/$SBXNAME"
mkdir -v "/usr/local/unsafehex/$SBXNAME/suspects"
mkdir -v "/usr/local/unsafehex/$SBXNAME/suspects/downloads"
mkdir -v "/usr/local/unsafehex/$SBXNAME/output"
mkdir -v "/usr/local/unsafehex/$SBXNAME/runmanager"
mkdir -v "/usr/local/unsafehex/$SBXNAME/runmanager/logs"
mkdir -v "/usr/local/unsafehex/$SBXNAME/www"
mkdir -v "/usr/local/unsafehex/$SBXNAME/api"
mkdir -v /mnt/images
mkdir -v "/mnt/$SBXNAME"
chgrp "$SBXNAME" "/mnt/$SBXNAME"
chmod g+rw /mnt/"$SBXNAME"
chgrp libvirt-qemu /mnt/images
chmod g+rw /mnt/images

echo -e "${GREEN}Unwrapping sandbox manager files and utilities...${NC}"
python3 "$SCRIPTDIR/scripts/write_tor_iptables.py" "$GATEWAY_IP" "$NETMASK" "$SCRIPTDIR/src/runmanager/"
python3 "$SCRIPTDIR/scripts/write_network.py" "$GATEWAY_IP" "$NETMASK" "$SCRIPTDIR/res/vnet.xml"
cp -rv "$SCRIPTDIR/src/runmanager/"* "/usr/local/unsafehex/$SBXNAME/runmanager/"
wget https://live.sysinternals.com/Sysmon64.exe -o "/usr/local/unsafehex/$SBXNAME/suspects/downloads/Sysmon64.exe"
cp -v "$SCRIPTDIR/res/sysmon.xml" "/usr/local/unsafehex/$SBXNAME/suspects/downloads"
cp -v "$SCRIPTDIR/res/TeaService\ Setup.msi" "/usr/local/unsafehex/$SBXNAME/suspects/downloads"
cp -v "$SCRIPTDIR/res/MousePos.exe" "/usr/local/unsafehex/$SBXNAME/suspects/downloads"
cp -v "$SCRIPTDIR/res/bios.bin" "/usr/local/unsafehex/$SBXNAME/"
cp -rv "$SCRIPTDIR/src/node/"* "/usr/local/unsafehex/$SBXNAME/www/"
cp -rv "$SCRIPTDIR/src/api/"* "/usr/local/unsafehex/$SBXNAME/api/"
chmod 775 -R /usr/local/unsafehex
usermod -a -G "$SBXNAME" "$LABUSER"
python3 "$SCRIPTDIR/scripts/writerunconf.py" "$SBXNAME" "$DBPASS" "$GATEWAY_IP" "$NETMASK"
python3 "$SCRIPTDIR/scripts/writewwwconf.py" "$SBXNAME" "$DBPASS" "$GATEWAY_IP" "$NETMASK"

echo -e "${GREEN}Installing required node modules...${NC}"
cd "/usr/local/unsafehex/$SBXNAME/www"
npm i
cd "/usr/local/unsafehex/$SBXNAME/api"
npm i

echo -e "${GREEN}Building required version of libvirt...${NC}"
mkdir -v "/tmp/$SBXNAME"
mkdir -v "/tmp/$SBXNAME/libvirt"
cd "/tmp/$SBXNAME/libvirt"
wget https://libvirt.org/sources/libvirt-4.0.0.tar.xz
tar xvfJ libvirt-4.0.0.tar.xz
cd libvirt-4.0.0
./configure --with-qemu-group=libvirt-qemu --localstatedir=/usr/local/var --with-dnsmasq-path=/usr/sbin/dnsmasq
make && make install
usermod -a -G libvirt-qemu "$LABUSER"
usermod -a -G kvm "$LABUSER"
apt-get install -y libvirt-daemon libvirt-clients virt-manager
cp -v "$SCRIPTDIR/res/libvirtd.service" /etc/systemd/system
rm -v "/etc/libvirt/libvirtd.conf"
cp -v "$SCRIPTDIR/res/libvirtd.conf" /etc/libvirt/
# socket file is not necessary and if not present in /etc/systemd/system, systemd will fall back to the next available one
# better to make sure they're all gone otherwise libvirt sockets will be created in the wrong location and with wrong permissions
rm -v /lib/systemd/system/libvirtd.socket

echo -e "${GREEN}Building required version of Suricata...${NC}"
mkdir -v "/tmp/$SBXNAME/suricata"
cd "/tmp/$SBXNAME/suricata"
wget https://www.openinfosecfoundation.org/download/suricata-4.0.0.tar.gz
tar zxvf suricata-4.0.0.tar.gz
cd suricata-4.0.0
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-geoip
make && make install
make install-conf
cp -v "$SCRIPTDIR/res/suricata.yaml" /etc/suricata

echo -e "${GREEN}Setting up Emerging Threats download...${NC}"
cd "/tmp/$SBXNAME/"
git clone https://github.com/seanthegeek/etupdate.git
cp -v etupdate/etupdate /usr/sbin
/usr/sbin/etupdate -V
crontab -l > tmpcron
MINUTE=$(shuf -i 0-59 -n 1)
echo "${MINUTE} * * * * /usr/sbin/etupdate" >> tmpcron
crontab tmpcron
rm tmpcron

echo -e "${GREEN}Configuring ClamAV to accept TCP connections...${NC}"
echo "TCPSocket 9999" >> /etc/clamav/clamd.conf
echo "TCPAddr 127.0.0.1" >> /etc/clamav/clamd.conf
cp -rf "$SCRIPTDIR/res/extend.conf" /etc/systemd/system/clamav-daemon.service.d/extend.conf

echo -e "${GREEN}Setting up nginx...${NC}"
cd "/tmp/$SBXNAME/"
mkdir -v ssl
cd "/tmp/$SBXNAME/ssl"
openssl req -x509 -nodes -days 365 -newkey rsa:4096 -subj "/CN=$SBXNAME/O=$SBXNAME/C=$CCODE" -keyout "$SBXNAME".key -out "$SBXNAME".crt
openssl dhparam -dsaparam -out dhparam.pem 4096
mkdir -v /etc/nginx/ssl
chmod 700 /etc/nginx/ssl
cp -v "$SBXNAME".key "$SBXNAME".crt dhparam.pem /etc/nginx/ssl
rm -v /etc/nginx/sites-enabled/default
cp -v "$SCRIPTDIR/res/nginx" "/etc/nginx/sites-enabled/$SBXNAME"

echo -e "${GREEN}Setting permissions on sandbox file structure...${NC}"
chown root:"$SBXNAME" -R /usr/local/unsafehex

cd "$SCRIPTDIR"

echo -e "${GREEN}Starting clam and libvirt services...${NC}"
# settings on libvirt not in effect until reloaded
systemctl daemon-reload
service clamav-daemon stop
service clamav-daemon start
service clamav-freshclam stop
service clamav-freshclam start
service libvirtd stop
service libvirtd start
service libvirt-guests stop
service libvirt-guests start
service virtlockd stop
service virtlockd start
service virtlogd stop
service virtlogd start

echo -e "${GREEN}Configuring tor, virtual network, and host run scripts${NC}"
{
	echo ""
	echo "TransListenAddress $GATEWAY_IP"
	echo "TransPort 8081"
	echo "DNSListenAddress $GATEWAY_IP"
	echo "DNSPort 5353"
} >> /etc/tor/torrc

virsh -c qemu:///system net-destroy default
virsh -c qemu:///system net-undefine default
virsh -c qemu:///system net-create "$SCRIPTDIR/res/vnet.xml"

echo -e "${GREEN}Cleaning up temporary files...${NC}"
rm -rfv "/tmp/$SBXNAME"

echo -e "${GREEN}INITIAL SETUP COMPLETE${NC}"
echo -e "You will now need to fill in config options and create your Windows VMs. Please see ${RED}README.md${NC} for details."
echo -e "Please log out and back in for permissions to take effect."
exit 0