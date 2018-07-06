#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import libvirt, logging, time, argparse, configparser, pyvnc, arrow, subprocess
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
        snapshot = self.dom.snapshotCurrent()
        logger.debug("Got snapshot")
        self.dom.revertToSnapshot(snapshot)
        logger.debug("Revert complete")
        self.dom.resume()
        time.sleep(5)
        self.dom.shutdown()
        
        #cstr = "{0}::{1}".format(self.vmdata["vnc"]["address"], self.vmdata["vnc"]["port"])
        #connector = pyvnc.Connector(cstr, self.vmdata["password"], self.vmdata["resolution"])
        #connector.client.timeout = 10
        #connector.restart()
        
        while True:
            state, reason = self.dom.state()
            if state == libvirt.VIR_DOMAIN_SHUTOFF:
                logger.debug("Domain went to bed")
                break
            else:
                self.dom.shutdown()
                time.sleep(2)
        self.dom.create()
        logger.info("Restart complete")

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
        self.restart()
        tformat = 'YYYY-MM-DD HH:mm:ss'
        restarttime = arrow.utcnow().format(tformat)
        time.sleep(90) # awaiting a screen is unreliable as hell. This SHOULD work instead...
        # make sure pcapring is turned back on
        self._cursor.execute("""UPDATE workerstate SET id = %s WHERE uuid = %s""", (self.dom.ID(), self.dom.UUIDString()))
        self._cursor.execute("""UPDATE victims SET runcounter = 0, last_reboot = %s WHERE uuid = %s""", (restarttime, self.dom.UUIDString()))
        self._dbconn.commit()
        subprocess.call(["sudo", "/bin/systemctl", "restart", "suricata"])
        self.login()
        time.sleep(12 * 60) # some malware looks for system uptime
        self.dom.suspend()
        new_snapshot_name = "{} maintenance".format(arrow.now().format("YYYY-MM-DD HH:mm:ss"))
        new_snapshot_xml = "<domainsnapshot><name>{}</name></domainsnapshot>".format(new_snapshot_name)
        old_snapshot = self.dom.snapshotCurrent()
        logger.debug("Creating new snapshot")
        self.dom.snapshotCreateXML(new_snapshot_xml)
        logger.debug("Removing old snapshot")
        old_snapshot.delete()
        logger.info("Maintenance complete")
        

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
