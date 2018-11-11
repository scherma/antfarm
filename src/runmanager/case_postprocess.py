#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import arrow, db_calls, psycopg2, psycopg2.extras, sys, logging, configparser, re

logger = logging.getLogger("antfarm.worker")

class Postprocessor:
    def __init__(self, uuid, dbcursor):
        self.uuid = uuid
        self._dbcursor = dbcursor
        self.events = db_calls.all_case_events(uuid, self._dbcursor)
        
    def is_sysmon_artifact(self, evt):
        if evt["eventid"] == 1:
            cmdlines = [
                r"C:\\Windows\\system32\\schtasks.exe /delete /f /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\Uploader\"",
                r"C:\\Windows\\system32\\sc.exe start w32time task_started",
                r"taskhost.exe \$\(Arg0\)",
                r'"taskhost.exe"',
                r"taskhost.exe SYSTEM",
                r"C:\\Windows\\System32\\wsqmcons.exe",
                r"C:\\Windows\\splwow64.exe"
            ]
            
            for cmdline in cmdlines:
                if re.search(cmdline, evt["eventdata"]["CommandLine"], re.IGNORECASE):
                    return True
        elif evt["eventid"] == 7:
            if evt["eventdata"]["ImageLoaded"] == "C:\\Windows\\System32\\wlanapi.dll":
                return True
        elif evt["eventid"] == 13:
            rmatches = [
                r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\[^\\]+\\OpenWithList\\a$",
                r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer$",
                r"\\Software\\Microsoft\\Office\\Common\\Smart Tag\\Applications\\OpusApp\\FriendlyName"
            ]
            for rmatch in rmatches:
                if re.search(rmatch, evt["eventdata"]["TargetObject"], re.IGNORECASE):
                    return True
        return False
    
    def is_suricata_dns_artifact(self, evt):
        rmatches = [
            r"8.8.8.8.in-addr.arpa$",
            r"\.msftncsi\.com$",
            r"\.windowsupdate\.com$",
            r"\.microsoft\.com$",
            r"\.symcd\.com$",
            r"\.symcb\.com$",
            r"\.verisign\.com$",
            r"\.symantec\.com$",
            r"\.bing\.com$",
            r"\.identrust\.com$",
            r"\.google\.com$",
            r"\.amazontrust\.com$",
            r"\.comodoca\.com$",
            r"\.trustwave\.com$",
            r"\.usertrust\.com$",
            r"\.digicert\.com$",
            r"\.godaddy\.com$",
            r"\.geotrust\.com$",
            r"\.globalsign\.com$",
            r"\.rapidssl\.com$",
            r"\.msftncsi\.com$"
        ]
        for rmatch in rmatches:
            if re.search(rmatch, evt["dnsdata"]["rrname"], re.IGNORECASE):
                return True
        return False
    
    def is_suricata_http_artifact(self, evt):
        rmatches = [
            r"ctldl\.windowsupdate\.com$"
        ]
        for rmatch in rmatches:
            if "hostname" in evt["httpdata"] and re.search(rmatch, evt["httpdata"]["hostname"]):
                return True
        return False
    
    def is_suricata_tls_artifact(self, evt):
        return False
    
    def is_suricata_alert_artifact(self, evt):
        return False
    
    def is_filesystem_artifact(self, evt):
        rmatches = [
            r"^C:\\Windows\\Temp\\.*?\.sqm$",
            r"^C:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache"
        ]
        for rmatch in rmatches:
            if re.search(rmatch, evt["os_path"], re.IGNORECASE):
                artifact = True
        return False
    
    def update_events(self):
        logger.info("Tagging artifacts...")
        total = 0
        for evt in self.events["dns"]:
            if self.is_suricata_dns_artifact(evt):
                db_calls.tag_artifact(evt, "dns", self._dbcursor)
                total += 1
        
        for evt in self.events["http"]:
            if self.is_suricata_http_artifact(evt):
                db_calls.tag_artifact(evt, "http", self._dbcursor)
                total += 1
        
    #    for evt in pp.events["tls"]:
    #        if pp.is_suricata_tls_artifact(evt):
    #            print(evt)
                
        for evt in self.events["alert"]:
            if self.is_suricata_alert_artifact(evt):
                db_calls.tag_artifact(evt, "alert", self._dbcursor)
                total += 1
                
        for evt in self.events["sysmon"]:
            if self.is_sysmon_artifact(evt):
                db_calls.tag_artifact(evt, "sysmon", self._dbcursor)
                total += 1
        
        for evt in self.events["files"]:
            if self.is_filesystem_artifact(evt):
                db_calls.tag_artifact(evt, "filesystem", self._dbcursor)
                total += 1
        
        logger.debug("{} artifacts found and tagged".format(total))
    
def main():
    conf = configparser.ConfigParser()
    
    conf.readfp(open("runmanager.conf"))
    
    host = "localhost"
    conn_string = "host='{0}' dbname='{1}' user='{2}' password='{3}'".format(host, conf.get("General", "dbname"), conf.get("General", "dbuser"), conf.get("General" ,"dbpass"))
    conn = psycopg2.connect(conn_string)
    conn.autocommit = True
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    pp = Postprocessor(sys.argv[1], cursor)
        
    pp.update_events()
      
if __name__ == "__main__":
    main()