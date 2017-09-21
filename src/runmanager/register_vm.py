#!/usr/bin/env python
# coding: utf-8
# © https://github.com/scherma
# contact http_error_418@unsafehex.com

import libvirt, argparse, ConfigParser, psycopg2, psycopg2.extras, tabulate, arrow, os, logging
from lxml import etree

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('config', default='runmanager.conf', type=argparse.FileType())
	args = parser.parse_args()

	conf = ConfigParser.ConfigParser()
	conf.readfp(args.config)
	
	db = conf.get('General', 'dbname')
	user = conf.get('General', 'dbuser')
	password = conf.get('General', 'dbpass')
	
	host = 'localhost'
	conn_string = "host='{0}' dbname='{1}' user='{2}' password='{3}'".format(host, db, user, password)
	conn = psycopg2.connect(conn_string)
	conn.autocommit = True
	cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
	
	lv_conn = libvirt.open("qemu:///system")
	
	domains = lv_conn.listAllDomains()
	
	cursor.execute("""SELECT uuid FROM "victims" """)
	registered = cursor.fetchall()
	
	unregistered = []
	
	
	for dom in domains:
		dom_uuid = dom.UUIDString()
		if not (dom_uuid in [rdom['uuid'] for rdom in registered]):
			state, reason = dom.state()
			if state == libvirt.VIR_DOMAIN_PAUSED:
				unregistered.append(dom)
			
	if len(unregistered) > 0:
		print("There are {0} unregistered VMs:\n".format(len(unregistered)))
		rows = []
		for i, dom in enumerate(unregistered):
			row = []
			row.append(str(i))
			row.append(dom.name())
			row.append(dom.UUIDString())
			rows.append(row)
			
		print(tabulate.tabulate(rows, headers=["", "Name", "UUID"]))
		print("\n")
			
		selected = None
		while not isinstance(selected, libvirt.virDomain):
			try:
				selected = unregistered[int(raw_input("Please choose a VM no.: "))]
			except (ValueError, IndexError):
				print("Invalid selection, please try again.")
		
		tree = etree.fromstring(selected.XMLDesc(0))
		
		disks = tree.findall(".//disk[@device='disk']")
		
		chosendisk = None
		chosendisk = disks[0].xpath("./source")[0].get("file")
		#for i, disk in enumerate(disks):
		#	if disk.find("./boot") is not None:
		#		source = disk.xpath("./source")[0]
		#		chosendisk = source.get("file")
				
		print("Please enter the following settings according to how you have configured your VM")
		hostname = raw_input("Hostname: ")
		opsys = raw_input("Operating system: ")
		username = raw_input("Username: ")
		password = raw_input("Password: ")
		ip = raw_input("IP address: ")
		display_x = raw_input("Display width: ")
		display_y = raw_input("Display height: ")
		print("\n")
		office_type = None
		versions = [
			"None",
			"MS Office 2007",
			"MS Office 2010",
			"MS Office 2013",
			"Office 365"
		]
		
		while office_type not in range(0, len(versions)):
			print("What installation of MS Office is there?")
			vopts = [[i, val] for i, val in enumerate(versions)]
			
			print(tabulate.tabulate(vopts))
			office_type = int(raw_input("Please enter a number corresponding to your installation: "))
		

		print("\nYour VM will be registered with the following settings:\n")
		
		options = [
			["libvirtname", selected.name()],
			["uuid", selected.UUIDString()],
			["hostname", hostname],
			["os", opsys],
			["ip", ip],
			["username", username],
			["password", password],
			["diskfile", chosendisk],
			["resolution", "{0}x{1}".format(display_x, display_y)],
			["office version", versions[office_type]]
			]
		
		print(tabulate.tabulate(options, headers=["Option", "Value"]))
		
		raw_input("Press enter to confirm this selection (ctrl + c to abort)")
		
		cursor.execute("""INSERT INTO "victims" (libvirtname, uuid, hostname, os, ip, username, password, diskfile, status, runcounter, display_x, display_y, ms_office_type) """ +
					   """VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
					   (selected.name(), selected.UUIDString(), hostname, opsys, ip, username, password, chosendisk, 'production', 0, int(display_x), int(display_y), office_type))
		
		print("VM registered in database")
		
		dlfname = os.path.join(conf.get('General', 'basedir'), conf.get('General', 'instancename'), 'suspects', 'downloads', 'run.ps1')
		
		content = """# © https://github.com/scherma
# contact http_error_418@unsafehex.com
param(
    [Parameter(Mandatory=$true)][string]$filename,
    [Parameter(Mandatory=$true)][string]$dldir
)

$client = New-Object System.Net.WebClient
$dlname = [uri]::EscapeDataString($filename)
$client.DownloadFile("http://{0}:{1}/$dldir/$dlname", "C:\\Users\\{2}\\Downloads\\$filename")

cmd /c start "C:\\Users\\{2}\\Downloads\\$filename" """.format(conf.get('General', 'gateway_ip'), '8080', username)

		with open(dlfname, 'w') as f:
			f.write(content)
			print('Wrote file {0} - please place this in your VM\'s "C:\\Program Files" directory'.format(dlfname))
		
	else:
		print("No unregistered VMs found. Please note that only VMs that are unregistered AND paused will be listed.")
		print("Please also ensure that your VM's most recent snapshot is in the 'paused' state.")
		
			
	
if __name__ == "__main__":
	main()