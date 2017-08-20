#!/usr/bin/env python
# coding: utf-8
# © https://github.com/scherma
# contact http_error_418@unsafehex.com

import libvirt, argparse, ConfigParser, psycopg2, psycopg2.extras, tabulate, arrow
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
		os = raw_input("Operating system: ")
		username = raw_input("Username: ")
		password = raw_input("Password: ")
		ip = raw_input("IP address: ")
		
				
		print("\nYour VM will be registered with the following settings:\n")
		
		options = [
			["libvirtname", selected.name()],
			["uuid", selected.UUIDString()],
			["hostname", hostname],
			["os", os],
			["ip", ip],
			["username", username],
			["password", password],
			["diskfile", chosendisk]
			]
		
		print(tabulate.tabulate(options, headers=["Option", "Value"]))
		
		raw_input("Press enter to confirm this selection (ctrl + c to abort)")
		
		cursor.execute("""INSERT INTO "victims" (libvirtname, uuid, hostname, os, ip, username, password, diskfile, status, runcounter) """ +
					   """VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
					   (selected.name(), selected.UUIDString(), hostname, os, ip, username, password, chosendisk, 'production', 0))
		
		print("VM registered in database")
		
	else:
		print("No unregistered VMs found. Please note that only VMs that are unregistered AND paused will be listed.")
		print("Please also ensure that your VM's most recent snapshot is in the 'paused' state.")
		
			
	
if __name__ == "__main__":
	main()