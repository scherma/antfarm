#!/bin/bash
# © https://github.com/scherma
# contact http_error_418@unsafehex.com

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

read -p "Specify the user which the sandbox will run as: " LABUSER

if [ -z $(getent passwd $LABUSER) ]; then
    echo "Please create user $LABUSER before running this script"
    exit 1
fi

echo "The sandbox name will be used for directory naming, database name and database user."
echo "It is not essential for you to have noted down the database password as it is also written to the scripts' config files."
read -p "What name do you want to give the sandbox? " SBXNAME
read -s -p "Please create a password for the database: " DBPASS
echo ""
read -p "Please enter a country code for the SSL certificate: " CCODE

SCRIPTDIR=$(pwd)

echo "PATH=$PATH:/usr/sbin" >> /home/$LABUSER/.bash_profile
echo "export NO_AT_BRIDGE=1" >> /home/$LABUSER/.bash_profile

chown $LABUSER:$LABUSER /home/$LABUSER/.bash_profile

echo -e "${GREEN}Running basic updates...${NC}"

apt-get update -y
apt-get upgrade -y
apt-get dist-upgrade -y

echo -e "${GREEN}Installing core dependencies...${NC}"

apt-get install -y python-pip nodejs nginx postgresql libjpeg-dev libopenjpeg-dev python-dev curl tcpdump libcap2-bin 
apt-get install -y postgresql-contrib curl libpcap-dev git npm screen python-lxml rabbitmq-server tor libguestfs-tools ntpdate
apt-get install -y libnl-3-dev libnl-route-3-dev libxml2-dev libdevmapper-dev libyajl2 libyajl-dev pkg-config libyaml-dev libguestfs-tools build-essential libpq-dev
apt-get install -y clamav clamav-daemon clamav-freshclam
apt-get upgrade -y dnsmasq

ntpdate -s time.nist.gov

echo -e "${GREEN}Installing python dependencies...${NC}"
pip install pika psycopg2 arrow vncdotool pyshark psutil scapy tabulate
pip install Pillow --upgrade

echo -e "Installing Python EVTX Parser from github requires git TCP port (9418)."
pip install git+git://github.com/williballenthin/python-evtx

echo -e "${GREEN}Installing global nodejs packages...${NC}"
npm cache clean -f
npm install -g n
n stable
npm install nodemon -g --save

echo -e "${GREEN}Configuring database...${NC}"
su -c "psql -c \"CREATE USER $SBXNAME WITH PASSWORD '$DBPASS';\"" postgres
su -c "psql -c \"CREATE DATABASE $SBXNAME;\"" postgres
su -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE $SBXNAME TO $SBXNAME;\"" postgres
su -c psql < $SCRIPTDIR/res/schema.sql postgres

echo -e "${GREEN}Granting user permissions for packet capture...${NC}"
chmod +s /usr/sbin/tcpdump
groupadd pcap
usermod -a -G pcap $LABUSER
chgrp pcap /usr/sbin/tcpdump
chmod 750 /usr/sbin/tcpdump
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
ln -s /usr/bin/gettext.sh /usr/local/bin/gettext.sh

echo -e "${GREEN}Directory structure creation...${NC}"
mkdir -v /usr/local/unsafehex/
mkdir -v /usr/local/unsafehex/$SBXNAME
mkdir -v /usr/local/unsafehex/$SBXNAME/suspects
mkdir -v /usr/local/unsafehex/$SBXNAME/suspects/downloads
mkdir -v /usr/local/unsafehex/$SBXNAME/output
mkdir -v /usr/local/unsafehex/$SBXNAME/runmanager
mkdir -v /usr/local/unsafehex/$SBXNAME/runmanager/logs
mkdir -v /usr/local/unsafehex/$SBXNAME/www
mkdir -v /mnt/images
chown root:libvirt-qemu /mnt/images

echo -e "${GREEN}Unwrapping sandbox manager files and utilities...${NC}"
cp -v $SCRIPTDIR/src/runmanager /usr/local/unsafehex/$SBXNAME/runmanager/
cp -v $SCRIPTDIR/res/sysmon.exe /usr/local/unsafehex/$SBXNAME/suspects/downloads
cp -v $SCRIPTDIR/res/sysmon.xml /usr/local/unsafehex/$SBXNAME/suspects/downloads
cp -v $SCRIPTDIR/res/run.ps1 /usr/local/unsafehex/$SBXNAME/suspects/downloads
cp -v $SCRIPTDIR/res/bios.bin /usr/local/unsafehex/$SBXNAME/
cp -Rv $SCRIPTDIR/src/node/* /usr/local/unsafehex/$SBXNAME/www/
mv -v /usr/local/unsafehex/$SBXNAME/www/hexlab /usr/local/unsafehex/$SBXNAME/www/$SBXNAME
addgroup $SBXNAME
chmod 775 -R /usr/local/unsafehex
usermod -a -G $SBXNAME $LABUSER
python $SCRIPTDIR/scripts/writerunconf.py "$SBXNAME" "$DBPASS"
python $SCRIPTDIR/scripts/writewwwconf.py "$SBXNAME" "$DBPASS"

echo -e "${GREEN}Building required version of libvirt...${NC}"
addgroup libvirt-qemu
mkdir -v /tmp/$SBXNAME
mkdir -v /tmp/$SBXNAME/libvirt
cd /tmp/$SBXNAME/libvirt
wget https://libvirt.org/sources/libvirt-3.1.0.tar.xz
tar xvfJ libvirt-3.1.0.tar.xz
cd libvirt-3.1.0
./configure --with-qemu-group=libvirt-qemu --localstatedir=/usr/local/var --with-dnsmasq-path=/usr/sbin/dnsmasq
make && make install
usermod -a -G libvirt-qemu $LABUSER
usermod -a -G kvm $LABUSER
apt-get install -y libvirt-daemon libvirt-clients virt-manager
cp -v $SCRIPTDIR/res/libvirtd.service /etc/systemd/system
rm -v /etc/libvirt/libvirtd.conf
cp -v $SCRIPTDIR/res/libvirtd.conf /etc/libvirt/
rm -v /lib/systemd/system/libvirtd.socket

echo -e "${GREEN}Building required version of Suricata...${NC}"
mkdir -v /tmp/$SBXNAME/suricata
cd /tmp/$SBXNAME/suricata
wget https://www.openinfosecfoundation.org/download/suricata-4.0.0.tar.gz
tar zxvf suricata-4.0.0.tar.gz
cd suricata-4.0.0
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make && make install
make install-conf

echo -e "${GREEN}Setting up Emerging Threats download...${NC}"
cd /tmp/$SBXNAME/
git clone https://github.com/seanthegeek/etupdate.git
cp -v etupdate/etupdate /usr/sbin
/usr/sbin/etupdate -V
crontab -l > tmpcron
echo '17 * * * * /usr/sbin/etupdate' >> tmpcron
crontab tmpcron
rm tmpcron

echo -e "${GREEN}Configuring ClamAV to accept TCP connections...${NC}"
echo "TCPSocket 9999" >> /etc/clamav/clamd.conf
echo "TCPAddr 127.0.0.1" >> /etc/clamav/clamd.conf
cp -rf $SCRIPTDIR/res/extend.conf /etc/systemd/system/clamav-daemon.socket.d/extend.conf

echo -e "${GREEN}Setting up nginx...${NC}"
cd /tmp/$SBXNAME/
mkdir -v ssl
cd /tmp/$SBXNAME/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:4096 -subj "/CN=$SBXNAME/O=$SBXNAME/C=$CCODE" -keyout $SBXNAME\.key -out $SBXNAME\.crt
openssl dhparam -out dhparam.pem 4096
mkdir -v /etc/nginx/keys
chmod 700 /etc/nginx/keys
cp -v $SBXNAME\.key $SBXNAME\.crt dhparam.pem /etc/nginx/keys
rm -v /etc/nginx/sites-enabled/default
cp -v $SCRIPTDIR/res/nginx /etc/nginx/sites-enabled/$SBXNAME

echo -e "${GREEN}Setting permissions on sandbox file structure...${NC}"
chown root:$SBXNAME -R /usr/local/unsafehex

echo -e "${GREEN}Cleaning up temporary files...${NC}"
cd $SCRIPTDIR
rm -rfv /tmp/$SBXNAME

echo -e "${GREEN}Starting clam and libvirt services...${NC}"
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

virsh -c qemu:///system net-destroy default
virsh -c qemu:///system net-undefine default
virsh -c qemu:///system net-create $SCRIPTDIR/res/vnet.xml

echo -e "${GREEN}INITIAL SETUP COMPLETE${NC}"
echo -e "You will now need to fill in config options and create your Windows VMs. Please see ${RED}README.md${NC} for details."
echo -e "Please log out and back in for permissions to take effect."
exit 0