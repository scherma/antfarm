#!/bin/bash
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

qemu_version=3.0.0

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
fail=0

echo -e "${GREEN}Thank you for choosing to install the Antfarm sandbox${NC}"

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
read -p "Please enter the IP of the primary interface (sandbox UI will be presented on this IP):" PRIMARY_IP
echo ""
echo "You have specified the following settings:"
echo "Sandbox user: 			$LABUSER"
echo "SSL Country Code: 		$CCODE"
echo "VM network gateway IP:		$GATEWAY_IP"
echo "VM network netmask: 		$NETMASK"
echo "Primary interface IP:     $PRIMARY_IP"    
echo ""
read -p "Press enter to accept these settings and install the sandbox" CONTINUE

SCRIPTDIR=$(dirname "$(realpath "$0")")

# User requires dnsmasq to be in $PATH in order to edit libvirt virtual networks
echo "PATH=$PATH:/usr/sbin" >> "/home/$LABUSER/.bash_profile"
# Running virt-manager outputs garbage errors about inability to use accessibility bus - hide these
echo "export NO_AT_BRIDGE=1" >> "/home/$LABUSER/.bash_profile"

chown "$LABUSER:$LABUSER" "/home/$LABUSER/.bash_profile"

function install_antfarm_dependencies() {
	echo -e "${GREEN}Running basic updates...${NC}"
	
	apt-get -qq update -y 
	apt-get -qq upgrade -y
	apt-get -qq dist-upgrade -y
	
	echo -e "${GREEN}Installing core dependencies...${NC}"
	# stretch does not include npm with default nodejs install
	# this command makes me uncomfortable
	curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
	
	# failed to find in stretch: libopenjpeg-dev
	apt-get -qq install -y python3-pip nodejs nginx libjpeg-dev curl tcpdump libcap2-bin libcap-ng-dev libmagic-dev libjansson-dev libpcre3 libpcre3-dbg \
	libpcre3-dev postgresql-9.6 postgresql-contrib curl libpcap-dev git screen python3-lxml tor libguestfs-tools libffi-dev libssl-dev tshark \
	libnl-3-dev libnl-route-3-dev libxml2-dev libdevmapper-dev libyajl2 libyajl-dev pkg-config libyaml-dev build-essential libpq-dev python3-libvirt \
	libnet1-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 libnss3-dev libgeoip-dev liblua5.1-dev libhiredis-dev libevent-dev libgeoip-dev python3-dev \
	clamav clamav-daemon clamav-freshclam python3-guestfs xsltproc pm-utils yara libyara-dev libpciaccess-dev liblzo2-dev libsnappy-dev libbz2-dev \
	libgtk-3-dev libvte-dev librdmacm-dev libgoogle-perftools-dev
	if [ $? -eq 1 ]; then
		fail=1
	fi
	apt-get -qq upgrade -y dnsmasq
	
	echo -e "${GREEN}Installing python dependencies...${NC}"
	# apt-get remove -y python-cffi # probably not required anymore
	pip3 -qq uninstall yara
	pip3 -qq install --upgrade Pillow
	pip3 -qq install --upgrade twisted
	pip3 -qq install scapy pytest vncdotool pika psycopg2 arrow pyshark psutil tabulate ipaddress xmljson yara-python python-magic pytest websockify
	
	echo -e "${GREEN}Installing Python EVTX Parser by Willi Ballenthin...${NC}"
	pip3 -qq install https://github.com/williballenthin/python-evtx
	
	echo -e "${GREEN}Installing global nodejs packages...${NC}"
	apt-get -qq install nodejs
	npm -qq cache clean -f
	npm -qq install -g n
	# lots of features missing from repository version of nodejs - update it
	n -q latest
	npm -qq install nodemon -g --save
	
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
}

function configure_antfarm_db() {
	#test postgres install here
	echo -e "${GREEN}Configuring database...${NC}"
	su -c "psql -c \"CREATE USER antfarm WITH PASSWORD '$DBPASS';\"" postgres
	su -c "psql -c \"CREATE DATABASE antfarm;\"" postgres
	su -c "psql -q antfarm < $SCRIPTDIR/res/schema.sql" postgres
	su -c "psql -q antfarm -c \"GRANT ALL PRIVILEGES ON DATABASE antfarm TO antfarm;\"" postgres
	su -c "psql -q antfarm -c \"GRANT ALL ON TABLE workerstate TO antfarm;\"" postgres
	su -c "psql -q antfarm -c \"GRANT ALL ON TABLE victims TO antfarm;\"" postgres
	su -c "psql -q antfarm -c \"GRANT ALL ON TABLE suspects TO antfarm;\"" postgres
	su -c "psql -q antfarm -c \"GRANT ALL ON TABLE cases TO antfarm;\"" postgres
	su -c "psql -q antfarm -c \"GRANT ALL ON TABLE victimfiles TO antfarm;\"" postgres
	su -c "psql -q antfarm -c \"GRANT ALL ON TABLE sysmon_evts TO antfarm;\"" postgres
	su -c "psql -q antfarm -c \"GRANT ALL ON TABLE suricata_dns TO antfarm;\"" postgres
	su -c "psql -q antfarm -c \"GRANT ALL ON TABLE suricata_http TO antfarm;\"" postgres
	su -c "psql -q antfarm -c \"GRANT ALL ON TABLE suricata_alert TO antfarm;\"" postgres
	su -c "psql -q antfarm -c \"GRANT ALL ON TABLE suricata_tls TO antfarm;\"" postgres
	su -c "psql -q antfarm -c \"GRANT ALL ON TABLE pcap_summary TO antfarm;\"" postgres
	su -c "psql -q antfarm -c \"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO antfarm;\"" postgres
}

function make_antfarm_dirs() {
	echo -e "${GREEN}Directory structure creation...${NC}"
	addgroup libvirt-qemu
	addgroup "antfarm"
	mkdir /usr/local/unsafehex/
	mkdir "/usr/local/unsafehex/antfarm"
	mkdir "/usr/local/unsafehex/antfarm/suspects"
	mkdir "/usr/local/unsafehex/antfarm/suspects/downloads"
	mkdir "/usr/local/unsafehex/antfarm/output"
	mkdir "/usr/local/unsafehex/antfarm/runmanager"
	mkdir "/usr/local/unsafehex/antfarm/runmanager/logs"
	mkdir "/usr/local/unsafehex/antfarm/utils"
	mkdir "/usr/local/unsafehex/antfarm/yara"
	mkdir "/usr/local/unsafehex/antfarm/www"
	mkdir "/usr/local/unsafehex/antfarm/api"
	mkdir "/usr/local/unsafehex/antfarm/pcaps"
	mkdir "/usr/local/unsafehex/antfarm/novnc"
	mkdir /mnt/images
	mkdir "/mnt/antfarm"
	chgrp "antfarm" "/mnt/antfarm"
	chmod g+rw /mnt/antfarm
	chgrp libvirt-qemu /mnt/images
	chmod g+rw /mnt/images	
}

function install_antfarm_core() {
	echo -e "${GREEN}Unwrapping sandbox manager files and utilities...${NC}"
	python3 "$SCRIPTDIR/scripts/write_tor_iptables.py" "$GATEWAY_IP" "$NETMASK" "$SCRIPTDIR/src/runmanager/"
	python3 "$SCRIPTDIR/scripts/write_network.py" "$GATEWAY_IP" "$NETMASK" "$SCRIPTDIR/res/vnet.xml"
	rsync -r --info=progress2 "$SCRIPTDIR/src/runmanager/"* "/usr/local/unsafehex/antfarm/runmanager/"
	chmod +x "/usr/local/unsafehex/antfarm/runmanager/runmanager"
	wget https://live.sysinternals.com/Sysmon64.exe -O "/usr/local/unsafehex/antfarm/suspects/downloads/Sysmon64.exe"
	cp "$SCRIPTDIR/res/sysmon-8-cfg.xml" "/usr/local/unsafehex/antfarm/suspects/downloads"
	wget -q https://github.com/scherma/teaservice/releases/download/v0.2/TeaService.Setup.msi -O "/usr/local/unsafehex/antfarm/suspects/downloads/TeaService Setup.msi"
	cp "$SCRIPTDIR/res/MousePos.exe" "/usr/local/unsafehex/antfarm/suspects/downloads"
	cp "$SCRIPTDIR/res/bios.bin" "/usr/local/unsafehex/antfarm/"
	rsync -r --info=progress2 "$SCRIPTDIR/src/node/"* "/usr/local/unsafehex/antfarm/www/"
	mkdir "/usr/local/unsafehex/antfarm/www/public/images"
	mkdir "/usr/local/unsafehex/antfarm/www/public/images/cases"
	rsync -r --info=progress2 "$SCRIPTDIR/src/api/"* "/usr/local/unsafehex/antfarm/api/"
	rsync -r --info=progress2 "$SCRIPTDIR/src/utils/"* "/usr/local/unsafehex/antfarm/utils/"
	rsync -r --info=progress2 "$SCRIPTDIR/src/novnc/"* "/usr/local/unsafehex/antfarm/novnc/"
	chmod +x "/usr/local/unsafehex/antfarm/utils/suricata-clean.sh"
	chmod +x "/usr/local/unsafehex/antfarm/utils/yara-update.sh"
	chmod 775 -R /usr/local/unsafehex
	usermod -a -G "antfarm" "$LABUSER"
	python3 "$SCRIPTDIR/scripts/writerunconf.py" "antfarm" "$DBPASS" "$GATEWAY_IP" "$NETMASK"
	python3 "$SCRIPTDIR/scripts/writewwwconf.py" "antfarm" "$DBPASS" "$GATEWAY_IP" "$NETMASK"
	python3 "$SCRIPTDIR/scripts/write_unit_file.py" "antfarm" "$LABUSER"
	python3 "$SCRIPTDIR/scripts/write_pcap.py" "antfarm"
}

function build_libvirt() {
	mkdir "/tmp/antfarm"
	mkdir "/tmp/antfarm/libvirt"
	cd "/tmp/antfarm/libvirt"
	if wget https://libvirt.org/sources/libvirt-4.0.0.tar.xz; then
		echo -e "${GREEN}Building required version of libvirt...${NC}"
		tar xvfJ libvirt-4.0.0.tar.xz
		cd libvirt-4.0.0
		./configure --with-qemu-group=libvirt-qemu --localstatedir=/usr/local/var --with-dnsmasq-path=/usr/sbin/dnsmasq
		if [ $? -eq 0 ]; then
			echo -e "${GREEN}Installing libvirt...${NC}"
			if make; then
				make install
				usermod -a -G libvirt-qemu "$LABUSER"
				usermod -a -G kvm "$LABUSER"
				usermod -a -G wireshark "$LABUSER"
				apt-get -qq install -y libvirt-daemon libvirt-clients virt-manager
				echo -e "${GREEN}Installing libvirt extras...${NC}"
				cp "$SCRIPTDIR/res/libvirtd.service" /etc/systemd/system
				rm "/etc/libvirt/libvirtd.conf"
				cp "$SCRIPTDIR/res/libvirtd.conf" /etc/libvirt/
				# socket file is not necessary and if not present in /etc/systemd/system, systemd will fall back to the next available one
				# better to make sure they're all gone otherwise libvirt sockets will be created in the wrong location and with wrong permissions
				rm /lib/systemd/system/libvirtd.socket
			else
				echo -e "${RED}Compiling Libvirt failed"
				fail=1
			fi
		else
			echo -e "${RED}Libvirt configure failed{NC}"
			fail=1
		fi
	fi
}

function build_suricata() {
	echo -e "${GREEN}Building required version of Suricata...${NC}"
	mkdir -v "/tmp/antfarm/suricata"
	cd "/tmp/antfarm/suricata"
	if wget https://www.openinfosecfoundation.org/download/suricata-4.0.0.tar.gz; then
		tar zxvf suricata-4.0.0.tar.gz
		cd suricata-4.0.0
		./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-geoip
		make && make install
		make install-conf
		cp "$SCRIPTDIR/res/suricata.yaml" /etc/suricata
	fi
}

function make_cron() {
	echo -e "${GREEN}Setting up Emerging Threats download...${NC}"
	cd "/tmp/antfarm/"
	git clone https://github.com/seanthegeek/etupdate.git
	cp etupdate/etupdate /usr/sbin
	/usr/sbin/etupdate -V
	crontab -l > tmpcron
	MINUTE=$(shuf -i 0-59 -n 1)
	echo "${MINUTE} * * * * /usr/sbin/etupdate" >> tmpcron
	echo "1 0 * * * /usr/local/unsafehex/antfarm/utils/suricata-clean.sh" >> tmpcron
	echo "1 0 * * MON /usr/local/unsafehex/antfarm/utils/yara-update.sh" >> tmpcron
	echo "0 * * * * su $SBXUSER -c '/usr/local/unsafehex/antfarm/utils/dumpcap.sh >> /dev/null 2>&1'" >> tmpcron
    echo "2 0 * * * /usr/bin/find /usr/local/unsafehex/antfarm/pcaps/ -mtime +2 -exec rm {} \;" >> tmpcron
	crontab tmpcron
	rm tmpcron
}

function clam_setup() {
	echo -e "${GREEN}Configuring ClamAV to accept TCP connections...${NC}"
	echo "TCPSocket 9999" >> /etc/clamav/clamd.conf
	echo "TCPAddr 127.0.0.1" >> /etc/clamav/clamd.conf
	cp -rf "$SCRIPTDIR/res/extend.conf" /etc/systemd/system/clamav-daemon.service.d/extend.conf
}

function nginx_setup() {
	# needs work to automate setup of nginx
	echo -e "${GREEN}Setting up nginx...${NC}"
	cd "/tmp/antfarm/"
	mkdir ssl
	cd "/tmp/antfarm/ssl"
	openssl req -x509 -nodes -days 365 -newkey rsa:4096 -subj "/CN=antfarm/O=antfarm/C=$CCODE" -keyout "antfarm".key -out "antfarm".crt
	openssl dhparam -dsaparam -out dhparam.pem 4096
	mkdir /etc/nginx/ssl
	chmod 700 /etc/nginx/ssl
	cp "antfarm".key "antfarm".crt dhparam.pem /etc/nginx/ssl
	rm /etc/nginx/sites-enabled/default
	cp "$SCRIPTDIR/res/nginx" "/etc/nginx/sites-enabled/antfarm"
    sed -i "s/REPLACE_ME_LISTEN_MAIN/$PRIMARY_IP/g" "/etc/nginx/sites-enabled/antfarm"
    sed -i "s/REPLACE_ME_CERT/antfarm.crt/g" "/etc/nginx/sites-enabled/antfarm"
    sed -i "s/REPLACE_ME_PKEY/antfarm.key/g" "/etc/nginx/sites-enabled/antfarm"
    sed -i "s/REPLACE_ME_SERVER_NAME/$/g" "/etc/nginx/sites-enabled/antfarm"
    sed -i "s/REPLACE_ME_LISTEN_API/$GATEWAY_IP/g" "/etc/nginx/sites-enabled/antfarm"
    sed -i "s/REPLACE_ME_SBXNAME/antfarm/g" "/etc/nginx/sites-enabled/antfarm"
}

function finishing_touches() {
	echo -e "${GREEN}Setting permissions on sandbox file structure...${NC}"
	chown root:"antfarm" -R /usr/local/unsafehex
	
	echo -e "${GREEN}Setting permissions for control of services...${NC}"
	echo "Cmnd_Alias ANTFARM_CMNDS = /bin/systemctl start antfarm, /bin/systemctl stop antfarm, /bin/systemctl restart antfarm" >> /etc/sudoers.d/antfarm
    echo "Cmnd_Alias ANTFARM_UI_CMNDS = /bin/systemctl start antfarm-ui, /bin/systemctl stop antfarm-ui, /bin/systemctl restart antfarm-ui" >> /etc/sudoers.d/antfarm
    echo "Cmnd_Alias ANTFARM_API_CMNDS = /bin/systemctl start antfarm-api, /bin/systemctl stop antfarm-api, /bin/systemctl restart antfarm-api" >> /etc/sudoers.d/antfarm
	echo "Cmnd_Alias SURICATA_CMNDS = /bin/systemctl restart suricata, /bin/systemctl start suricata, /bin/systemctl stop suricata" >> /etc/sudoers.d/antfarm
    echo "Cmnd_Alias TOR_CMNDS = /bin/systemctl start tor, /bin/systemctl stop tor, /bin/systemctl restart tor" >> /etc/sudoers.d/antfarm
    echo "Cmnd_Alias LIBVIRT_CMNDS = /bin/systemctl restart libvirtd, /bin/systemctl restart libvirt-guests" >> /etc/sudoers.d/antfarm
	echo "%antfarm ALL=(ALL) NOPASSWD: ANTFARM_CMNDS,ANTFARM_API_CMNDS,ANTFARM_UI_CMNDS,SURICATA_CMNDS,LIBVIRT_CMNDS,TOR_CMNDS" >> /etc/sudoers.d/antfarm
	
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
    service nginx stop
    service nginx start
	
	echo -e "${GREEN}Configuring tor, virtual network, and host run scripts${NC}"
	{
		echo ""
		echo "TransPort $GATEWAY_IP:8081"
		echo "DNSPort $GATEWAY_IP:5353"
	} >> /etc/tor/torrc
	
	virsh -c qemu:///system net-destroy default
	virsh -c qemu:///system net-undefine default
	virsh -c qemu:///system net-create "$SCRIPTDIR/res/vnet.xml"

    iptables -t nat -A PREROUTING -i virbr0 -p tcp -s $GATEWAY_IP/$NETMASK --dport 28080 -j ACCEPT
    iptables -t nat -A PREROUTING -i virbr0 -p tcp -s $GATEWAY_IP/$NETMASK --dport 28082 -j ACCEPT
    iptables -t nat -A PREROUTING -i virbr0 -p tcp -s $GATEWAY_IP/$NETMASK -j REDIRECT --to-ports 8081
    iptables -t nat -A PREROUTING -i virbr0 -p udp --dport 53 -j REDIRECT --to-ports 5353 -s $GATEWAY_IP/$NETMASK

    service tor stop
    service tor start
	
	echo -e "${GREEN}Cleaning up temporary files...${NC}"
	rm -rf "/tmp/antfarm"
}

function replace_qemu_clues_public() {
    echo '[+] Patching QEMU clues'
    if ! sed -i 's/QEMU HARDDISK/ACER HARDDISK/g' qemu*/hw/ide/core.c; then
        echo 'QEMU HARDDISK was not replaced in core.c'; fail=1
    fi
    if ! sed -i 's/QEMU HARDDISK/ACER HARDDISK/g' qemu*/hw/scsi/scsi-disk.c; then
        echo 'QEMU HARDDISK was not replaced in scsi-disk.c'; fail=1
    fi
    if ! sed -i 's/QEMU DVD-ROM/ACER DVD-ROM/g' qemu*/hw/ide/core.c; then
        echo 'QEMU DVD-ROM was not replaced in core.c'; fail=1
    fi
    if ! sed -i 's/QEMU DVD-ROM/ACER DVD-ROM/g' qemu*/hw/ide/atapi.c; then
        echo 'QEMU DVD-ROM was not replaced in atapi.c'; fail=1
    fi
    if ! sed -i 's/s->vendor = g_strdup("QEMU");/s->vendor = g_strdup("ACER");/g' qemu*/hw/scsi/scsi-disk.c; then
        echo 'Vendor string was not replaced in scsi-disk.c'; fail=1
    fi
    if ! sed -i 's/QEMU CD-ROM/ACER CD-ROM/g' qemu*/hw/scsi/scsi-disk.c; then
        echo 'QEMU CD-ROM was not patched in scsi-disk.c'; fail=1
    fi
    if ! sed -i 's/padstr8(buf + 8, 8, "QEMU");/padstr8(buf + 8, 8, "ACER");/g' qemu*/hw/ide/atapi.c; then
        echo 'padstr was not replaced in atapi.c'; fail=1
    fi
    if ! sed -i 's/QEMU MICRODRIVE/ACER MICRODRIVE/g' qemu*/hw/ide/core.c; then
        echo 'QEMU MICRODRIVE was not replaced in core.c'; fail=1
    fi
    if ! sed -i 's/KVMKVMKVM\\0\\0\\0/GenuineIntel/g' qemu*/target/i386/kvm.c; then
        echo 'KVMKVMKVM was not replaced in kvm.c'; fail=1
    fi
	# by @http_error_418
    if  sed -i 's/Microsoft Hv/GenuineIntel/g' qemu*/target/i386/kvm.c; then
        echo 'Microsoft Hv was not replaced in target/i386/kvm.c'; fail=1
    fi
    if ! sed -i 's/"bochs"/"hawks"/g' qemu*/block/bochs.c; then
        echo 'BOCHS was not replaced in block/bochs.c'; fail=1
    fi
    # by Tim Shelton (redsand) @ HAWK (hawk.io)
    if ! sed -i 's/"BOCHS "/"ALASKA"/g' qemu*/include/hw/acpi/aml-build.h; then
        echo 'bochs was not replaced in include/hw/acpi/aml-build.h'; fail=1
    fi
    # by Tim Shelton (redsand) @ HAWK (hawk.io)
    if ! sed -i 's/Bochs Pseudo/Intel RealTime/g' qemu*/roms/ipxe/src/drivers/net/pnic.c; then
        echo 'Bochs Pseudo was not replaced in roms/ipxe/src/drivers/net/pnic.c'; fail=1
    fi
}

function replace_seabios_clues_public() {
    echo "[+] deleting BOCHS APCI tables"
    echo "[+] Generating SeaBios Kconfig"
    #./scripts/kconfig/merge_config.sh -o . >/dev/null 2>&1
    #sed -i 's/CONFIG_ACPI_DSDT=y/CONFIG_ACPI_DSDT=n/g' .config
    #sed -i 's/CONFIG_XEN=y/CONFIG_XEN=n/g' .config
    echo "[+] Fixing SeaBios antivms"
    if ! sed -i 's/Bochs/Phnx /g' src/config.h; then
        echo 'Bochs was not replaced in src/config.h'; fail=1
    fi
    if ! sed -i 's/BOCHSCPU/PHNXCPU/g' src/config.h; then
        echo 'BOCHSCPU was not replaced in src/config.h'; fail=1
    fi
    if ! sed -i 's/"BOCHS "/"PHNX "/g' src/config.h; then
        echo 'BOCHS was not replaced in src/config.h'; fail=1
    fi
    if ! sed -i 's/BXPC/PHPC/g' src/config.h; then
        echo 'BXPC was not replaced in src/config.h'; fail=1
    fi
    if ! sed -i 's/QEMU0001/ACER0001/g' src/fw/ssdt-misc.dsl; then
        echo 'QEMU0001 was not replaced in src/fw/ssdt-misc.dsl'; fail=1
    fi
    if ! sed -i 's/QEMU\/Bochs/ACER\/Phnx /g' vgasrc/Kconfig; then
        echo 'QEMU\/Bochs was not replaced in vgasrc/Kconfig'; fail=1
    fi
    if ! sed -i 's/qemu /acer /g' vgasrc/Kconfig; then
        echo 'qemu was not replaced in vgasrc/Kconfig'; fail=1
    fi

    FILES=(
        src/hw/blockcmd.c
        src/fw/paravirt.c
    )
    for file in "${FILES[@]}"; do 
        if ! sed -i 's/"QEMU/"ACER/g' "$file"; then
            echo "QEMU was not replaced in $file"; fail=1
        fi
    done
    if ! sed -i 's/"QEMU"/"ACER"/g' src/hw/blockcmd.c; then
        echo '"QEMU" was not replaced in  src/hw/blockcmd.c'; fail=1
    fi
    FILES=(
        "src/fw/acpi-dsdt.dsl" 
        "src/fw/q35-acpi-dsdt.dsl"
    )
    for file in "${FILES[@]}"; do 
        if ! sed -i 's/"BXPC"/ARPC"/g' "$file"; then
            echo "BXPC was not replaced in $file"; fail=1
        fi
        if ! sed -i 's/"BXDSDT"/"ARDSDT"/g' "$file"; then
            echo "BXDSDT was not replaced in $file"; fail=1
        fi
    done
    if ! sed -i 's/"BXPC"/"ARPC"/g' "src/fw/ssdt-pcihp.dsl"; then
        echo 'BXPC was not replaced in src/fw/ssdt-pcihp.dsl'; fail=1
    fi
    if ! sed -i 's/"BXDSDT"/"ARDSDT"/g' "src/fw/ssdt-pcihp.dsl"; then
        echo 'BXDSDT was not replaced in src/fw/ssdt-pcihp.dsl'; fail=1
    fi
    if ! sed -i 's/"BXPC"/"ARPC"/g' "src/fw/ssdt-proc.dsl"; then
        echo 'BXPC was not replaced in "src/fw/ssdt-proc.dsl"'; fail=1
    fi
    if ! sed -i 's/"BXSSDT"/"ARSSDT"/g' "src/fw/ssdt-proc.dsl"; then
        echo 'BXSSDT was not replaced in src/fw/ssdt-proc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXPC"/"ARPC"/g' "src/fw/ssdt-misc.dsl"; then
        echo 'BXPC was not replaced in src/fw/ssdt-misc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXSSDTSU"/"ARSSDTSU"/g' "src/fw/ssdt-misc.dsl"; then
        echo 'BXDSDT was not replaced in src/fw/ssdt-misc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXSSDTSUSP"/"ARSSDTSUSP"/g' src/fw/ssdt-misc.dsl; then
        echo 'BXSSDTSUSP was not replaced in src/fw/ssdt-misc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXSSDT"/"ARSSDT"/g' src/fw/ssdt-proc.dsl; then
        echo 'BXSSDT was not replaced in src/fw/ssdt-proc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXSSDTPCIHP"/"ARSSDTPCIHP"/g' src/fw/ssdt-pcihp.dsl; then
        echo 'BXPC was not replaced in src/fw/ssdt-pcihp.dsl'; fail=1
    fi
    FILES=(
        src/fw/q35-acpi-dsdt.dsl
        src/fw/acpi-dsdt.dsl
        src/fw/ssdt-misc.dsl
        src/fw/ssdt-proc.dsl
        src/fw/ssdt-pcihp.dsl
        src/config.h
    )
    for file in "${FILES[@]}"; do 
        if ! sed -i 's/"BXPC"/"A M I"/g' "$file"; then
            echo "BXPC was not replaced in $file"; fail=1
        fi
    done
}

function seabios_func() {
    cd /tmp || return     
    echo -e '${GREEN}Installing SeaBios dependencies${NC}'
    apt-get install git iasl -y
    if [ -d seabios ]; then
        rm -r seabios
    fi
    if git clone https://github.com/coreboot/seabios.git; then
        cd seabios || return
        if declare -f -F "replace_seabios_clues"; then
            replace_seabios_clues
        else
            replace_seabios_clues_public
        fi
        # sudo make help
        # sudo make menuconfig -> BIOS tables -> disable Include default ACPI DSDT
        if make -j "$(getconf _NPROCESSORS_ONLN)"; then
            echo -e '${GREEN}Replacing old bios.bin to new out/bios.bin${NC}'
            bios=0
            FILES=(
                "/usr/share/qemu/bios.bin"
                "/usr/share/qemu/bios-256k.bin" 
            )
            for file in "${FILES[@]}"; do 
                cp -f out/bios.bin "$file"
                bios=1
            done
            if [ $bios -eq 1 ]; then
                echo -e '${GREEN}Patched bios.bin placed correctly${NC}'
            else
                echo -e '${RED}Bios patching failed${NC}'
            fi
        else
            echo -e '${RED}Bios compilation failed${NC}'
        fi
        cd - || return
    else
        echo -e '${RED}Check if git installed or network connection is OK${NC}'
    fi
}

function qemu_func() {
    cd /tmp || return 

    echo -e '${GREEN}Cleaning QEMU old install if exists${NC}'
    rm -r /usr/share/qemu >/dev/null 2>&1
    sudo dpkg -r ubuntu-vm-builder python-vm-builder >/dev/null 2>&1
    sudo dpkg -l |grep qemu |cut -d " " -f 3|xargs sudo dpkg --purge --force-all >/dev/null 2>&1

    echo -e '${GREEN}Downloading QEMU source code${NC}'
    if [ ! -f qemu-$qemu_version.tar.xz ]; then 
        wget https://download.qemu.org/qemu-$qemu_version.tar.xz
    fi
    if [ $(tar xf qemu-$qemu_version.tar.xz) ]; then
        echo -e "${RED}Failed to extract, check if download was correct${NC}"
        exit 1
    fi
    fail=0

    if [ $? -eq 0 ]; then
        if declare -f -F "replace_qemu_clues"; then
            replace_qemu_clues
        else
            replace_qemu_clues_public
        fi
        if [ $fail -eq 0 ]; then
            echo -e '${GREEN}Starting compile of qemu...{$NC}'
            cd qemu-$qemu_version || return
			# needs to be updated with the exact options required
            ./configure --prefix=/usr --libexecdir=/usr/lib/qemu --localstatedir=/var --bindir=/usr/bin/ --target-list=i386-softmmu,x86_64-softmmu,i386-linux-user,x86_64-linux-user --enable-gnutls --enable-docs --enable-gtk --enable-vnc --enable-vnc-sasl --enable-vnc-png --enable-vnc-jpeg --enable-curl --enable-kvm --enable-linux-aio --enable-cap-ng --enable-vhost-net --enable-vhost-crypto --enable-spice --enable-usb-redir --enable-lzo --enable-snappy --enable-bzip2 --enable-coroutine-pool --enable-libssh2 --enable-libxml2 --enable-tcmalloc --enable-replication --enable-tools --enable-capstone --enable-virtfs --enable-bzip2 --enable-linux-user --enable-nettle --enable-fdt --enable-libusb --enable-snappy --enable-seccomp --enable-tpm
            if  [ $? -eq 0 ]; then
                echo '${GREEN}Installing qemu...${NC}'
                #dpkg -i qemu*.deb
                if [ -f /usr/share/qemu/qemu_logo_no_text.svg ]; then
                    rm /usr/share/qemu/qemu_logo_no_text.svg
                fi
                make -j"$(getconf _NPROCESSORS_ONLN)"
                checkinstall -D --pkgname=qemu-$qemu_version --nodoc --showinstall=no --default
                # hack for libvirt/virt-manager
                if [ ! -f /usr/bin/qemu-system-x86_64-spice ]; then 
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/qemu-system-x86_64-spice
                fi
                if [ ! -f /usr/bin/kvm-spice ]; then 
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/kvm-spice
                fi
                if [ ! -f /usr/bin/kvm ]; then 
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/kvm
                fi
                if  [ $? -eq 0 ]; then
                    echo -e '${GREEN}Patched, compiled and installed${NC}'
                else
                    echo -e '${RED}Install failed${NC}'
                fi
            else
                echo -e '${RED}Compilling failed${NC}'
            fi
        else
            echo -e '${RED}Check previous output${NC}'
            exit
        fi

    else
        echo -e '${RED}Download QEMU source was not possible${NC}'
    fi
}

INSTALL_CMDS=["install_antfarm_dependencies", "configure_antfarm_db", "make_antfarm_dirs", "build_libvirt", "build_suricata", "make_cron", "clam_setup", "nginx_setup", "seabios_func", "qemu_func", "finishing_touches"]

for cmd in "${INSTALL_CMDS[@]}"; do
	read -p "Enter for next stage..." CONTINUE
	cmd
	if [ fail -eq 1 ]; then
		echo -e "${RED}Errors occurred and the installation has failed. See previous output for details. Aborting."
		exit 1
	fi
done

	
echo -e "${GREEN}INITIAL SETUP COMPLETE${NC}"
echo -e "You will now need to fill in config options and create your Windows VMs. Please see ${RED}README.md${NC} for details."
echo -e "Please log out and back in for permissions to take effect."
exit 0