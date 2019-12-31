#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import libvirt, logging, time, argparse, configparser, pyvnc, arrow, subprocess, psutil
from runinstance import get_screen_image

logger = logging.getLogger("antfarm")

class Janitor:
    def __init__(self, config, vmdata, cursor, dbconn):
        self._conf = config
        self.vmdata = vmdata
        self._lv_conn = libvirt.open("qemu:///system")
        self._cursor = cursor
        self._dbconn = dbconn
        self.dom = self._lv_conn.lookupByUUIDString(self.vmdata["uuid"])
        logger.debug("Janitor was called in to work. He needs coffee.")
        
    def restart(self):
        logger.info("Restart called")
        snapshot = self.dom.snapshotLookupByName(self.vmdata["snapshot"])
        logger.debug("Got snapshot")
        self.dom.revertToSnapshot(snapshot)
        logger.debug("Revert complete")
        self.dom.resume()
        time.sleep(5)
       
        while True:
            state, reason = self.dom.state()
            if state == libvirt.VIR_DOMAIN_RUNNING:
                logger.debug("Victim going to sleep...")
                self.dom.shutdown()
                time.sleep(2)
            elif state == libvirt.VIR_DOMAIN_SHUTOFF:
                logger.debug("Victim is asleep")
                self.dom.create()
                time.sleep(5)
                state, reason = self.dom.state()
                if state == libvirt.VIR_DOMAIN_RUNNING:
                    logger.info("Victim woke up")
                    break
                else:
                    logger.error("Victim didn't wake... nudging again")
            elif state == libvirt.VIR_DOMAIN_SHUTDOWN:
                # domain still shutting down
                time.sleep(5)
            else:
                logger.debug("Domain state is {}, reason {} - no action taken".format(state, reason))
        

    def screenshot(self, path):
        i = get_screen_image(self.dom, self._lv_conn)
        i.save(path)
        
    def login(self):
        cstr = "{0}::{1}".format(self.vmdata["vnc"]["address"], self.vmdata["vnc"]["port"])
        connector = pyvnc.Connector(cstr, self.vmdata["password"], (self.vmdata["display_x"], self.vmdata["display_y"]))
        connector.login(self.vmdata["password"])
        logger.info("Logged in... I think")
        
        
    def logoff(self):
        logger.info("Logoff called. Abadi, abadi, ah, uh... that's all folks!")
        self.client.singleKey("lsuper")
        self.client.singleKey("right")
        self.client.singleKey("right")
        self.client.singleKey("down")
        self.client.singleKey("down")
        self.client.singleKey("enter")
        self.client.pause("10")
                
    def standard_maintenance(self):
        logger.info("Entering standard maintenance cycle...")
        self._cursor.execute("""UPDATE victims SET status = 'maintenance' WHERE uuid = %s""", (self.dom.UUIDString(),))
        logger.debug("Set maintenance status on victim")
        self.restart()
        tformat = 'YYYY-MM-DD HH:mm:ss'
        restarttime = arrow.utcnow().format(tformat)
        time.sleep(90) # awaiting a screen is unreliable as hell. This SHOULD work instead...
        self._cursor.execute("""UPDATE workerstate SET id = %s WHERE uuid = %s""", (self.dom.ID(), self.dom.UUIDString()))
        self.login()
        time.sleep(12 * 60) # some malware looks for system uptime
        self.dom.suspend()
        old_snapshot = self.dom.snapshotLookupByName(self.vmdata["snapshot"])
        new_snapshot_name = "{} maintenance".format(arrow.now().format("YYYY-MM-DD HH:mm:ss"))
        new_snapshot_xml = "<domainsnapshot><name>{}</name></domainsnapshot>".format(new_snapshot_name)
        logger.debug("Creating new snapshot")
        self.dom.snapshotCreateXML(new_snapshot_xml)
        logger.debug("Removing old snapshot")
        old_snapshot.delete()
        logger.debug("Resetting run counter")
        self._cursor.execute(
            """UPDATE victims SET runcounter = 0, last_reboot = %s, snapshot = %s, status = 'production' WHERE uuid = %s""", 
            (restarttime, new_snapshot_name, self.dom.UUIDString()))
        self._dbconn.commit()
        logger.info("Maintenance complete")

def restart_pcap():
    for proc in psutil.process_iter(attrs=["name"]):
        if proc.info["name"] == "dumpcap":
            proc.terminate()
            subprocess.Popen(["/bin/bash", "/usr/local/unsafehex/antfarm/utils/dumpcap.sh"])
            break

def restart_services():
    logger.debug("Restarting libvirtd...")
    subprocess.call(["sudo", "/bin/systemctl", "restart", "libvirtd"])
    logger.debug("Restarting libvirt-guests...")
    subprocess.call(["sudo", "/bin/systemctl", "restart", "libvirt-guests"])
    logger.debug("Restarting tor...")
    subprocess.call(["sudo", "/bin/systemctl", "restart", "tor"])
    logger.debug("Restarting suricata...")
    subprocess.call(["sudo", "/bin/systemctl", "restart", "suricata"])
    logger.debug("Restarting dumpcap...")
    restart_pcap()

def start_all_services():
    logger.debug("Starting suricata...")
    subprocess.call(["sudo", "/bin/systemctl", "start", "suricata"])
    logger.debug("Starting libvirtd...")
    subprocess.call(["sudo", "/bin/systemctl", "start", "libvirtd"])
    logger.debug("Starting libvirt-guests...")
    subprocess.call(["sudo", "/bin/systemctl", "start", "libvirt-guests"])
    logger.debug("Starting tor...")
    subprocess.call(["sudo", "/bin/systemctl", "start", "tor"])
    logger.debug("Starting UI...")
    subprocess.call(["sudo", "/bin/systemctl", "start", "antfarm-ui"])
    logger.debug("Starting API...")
    subprocess.call(["sudo", "/bin/systemctl", "start", "antfarm-api"])

        

def main():
    logging.basicConfig()
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    parser = argparse.ArgumentParser()
    parser.add_argument('config', type=argparse.FileType())
    args = parser.parse_args()
    
    conf = configparser.ConfigParser()
    
    conf.readfp(args.config)
    
    vmdata = {
        "uuid": "7c0a242d-6b7f-4061-86e9-3bed0aff218e",
        "vnc": { "address": "127.0.0.1", "port": "5900"},
        "password": "tallyho40",
        "resolution": (1680,1050)
    }
    
    j = Janitor(conf, vmdata)
    j.standard_maintenance()
    
if __name__ == '__main__':
    main()
