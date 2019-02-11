#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import arrow, db_calls, psycopg2, psycopg2.extras, sys, logging, configparser, re, argparse, requests, json

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
                r"C:\\Windows\\splwow64.exe",
                r"C:\\Program Files\\Internet Explorer\\iexplore.exe",
                r"C:\\Windows\\system32\\wermgr.exe -queuereporting",
                r"C:\\Windows\\System32\\sdclt.exe /CONFIGNOTIFICATION"
            ]
            
            parentlines = [
                r"C:\\Windows\\System32\\wsqmcons.exe",
            ]
            for cmdline in cmdlines:
                if re.search(cmdline, evt["eventdata"]["CommandLine"], re.IGNORECASE):
                    return True
            for parentline in parentlines:
                if re.search(parentline, evt["eventdata"]["ParentCommandLine"], re.IGNORECASE):
                    return True
        elif evt["eventid"] == 7:
            images = {
                "c:\\windows\\system32\\wlanapi.dll": 
                    [r"c:\\windows\\coffeesvc.exe$", r"C:\\Windows\\System32\\svchost.exe$"],
                "c:\\windows\\system32\\cryptdll.dll": 
                    [r"c:\\windows\\system32\\svchost.exe$"],
                "c:\\windows\\system32\\samlib.dll":
                    [r"c:\\program files\\internet explorer\\iexplore.exe$"]
            }
            if evt["eventdata"]["ImageLoaded"].lower() in images:
                for imagepattern in images[evt["eventdata"]["ImageLoaded"].lower()]:
                    if re.search(imagepattern, evt["eventdata"]["Image"], re.IGNORECASE):
                        return True
        elif evt["eventid"] == 12:
            rmatches = [
                r"\\Software\\Microsoft\\Internet Explorer\\Toolbar$"
            ]
            for rmatch in rmatches:
                if re.search(rmatch, evt["eventdata"]["TargetObject"], re.IGNORECASE):
                    return True
        elif evt["eventid"] == 13:
            rmatches = [
                r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\[^\\]+\\OpenWithList\\a$",
                r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer$",
                r"\\Software\\Microsoft\\Office\\Common\\Smart Tag\\Applications\\OpusApp\\FriendlyName",
                r"\\System\\CurrentControlSet\\Control\\Power\\User\\PowerSchemes",
                r"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\WinSATRestorePower$"
            ]
            for rmatch in rmatches:
                if re.search(rmatch, evt["eventdata"]["TargetObject"], re.IGNORECASE):
                    return True
        return False
    
    def is_suricata_dns_artifact(self, evt):
        rmatches = [
            r"\.in-addr\.arpa$",
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
            r"\.msftncsi\.com$",
            r"\.windows\.com$",
            r"\.verisign\.com$",
            r"\.bing\.com$",
            r"\.windows\.com$"
        ]
        rdmatches = [
            r"\.akamaitechnologies\.com$",
            r"\.a-msedge\.net$"
        ]

        for rdmatch in rdmatches:
            if "rdata" in evt["dnsdata"] and re.search(rdmatch, evt["dnsdata"]["rdata"], re.IGNORECASE):
                return True

        for rmatch in rmatches:
            if re.search(rmatch, evt["dnsdata"]["rrname"], re.IGNORECASE):
                return True
        return False
    
    def is_suricata_http_artifact(self, evt):
        rmatches = [
            r"\.windowsupdate\.com$",
            r"\.microsoft\.com$",
            r"\.symcd\.com$",
            r"\.windows\.com$",
            r"\.verisign\.com$",
            r"\.bing\.com$",
            r"\.windows\.com$"
        ]
        for rmatch in rmatches:
            if "hostname" in evt["httpdata"] and re.search(rmatch, evt["httpdata"]["hostname"]):
                return True
        return False
    
    def is_suricata_tls_artifact(self, evt):
        rmatches = [
            r"\.windowsupdate\.com$",
            r"\.microsoft\.com$",
            r"\.symcd\.com$",
            r"\.windows\.com$",
            r"\.verisign\.com$",
            r"\.bing\.com$"
        ]
        for rmatch in rmatches:
            if "sni" in evt["tlsdata"] and re.search(rmatch, evt["tlsdata"]["sni"]):
                return True
        return False
    
    def is_suricata_alert_artifact(self, evt):
        return False
    
    def is_filesystem_artifact(self, evt):
        rmatches = [
            r"^C:\\Windows\\Temp\\.*?\.sqm$",
            r"^C:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache",
            r"^C:\\ProgramData\\Microsoft\\Windows\\WER",
            r"^C:\\ProgramData\\Microsoft\\RAC\\Temp",
            r"^C:\\Windows\\Performance\\WinSAT"
            r"^C:\\ProgramData\\Microsoft\\Vault",
            r"^C:\\Windows\\System32\\LogFiles",
            r"C:\\Windows\\System32\\config\\SYSTEM$",
            r"C:\\Windows\\System32\\config\\SOFTWARE$",
            r"C:\\Windows\\System32\\config\\SECURITY$",
            r"\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCache\w+\.tmp$",
            r"\\Appdata\\Local\\Microsoft\\Windows\\History\\History.IE5\\MSHist\d+\\container.dat$",
            r"NTUSER.DAT$",
            r"\\~\$Normal.dotm$"
        ]
        for rmatch in rmatches:
            if re.search(rmatch, evt["os_path"], re.IGNORECASE):
                return True
            elif evt["file_stat"] == {}:
                return True
        return False
    
    def is_pcap_artifact(self, evt):
        if evt["protocol"] == "UDP":
            dns_servers = ["208.67.220.220", "208.67.222.222", "8.8.8.8", "8.8.4.4"]
            if evt["dest_port"] == 53 and evt["dest_ip"] in dns_servers:
                # dns lookups are tagged by suricata
                return True
            elif evt["src_port"] == 53 and evt["src_ip"] in dns_servers:
                return True
            elif evt["dest_port"] in [5355, 123]:
                # link local multicast name resolution
                return True
            elif evt["src_port"] == 137 and evt["dest_port"] == 137:
                # netbios
                return True
        elif evt["protocol"] == "TCP":
            if evt["dest_port"] in [80, 443]:
                # http and https are tagged by suricata
                return True

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

        for evt in self.events["tls"]:
            if self.is_suricata_tls_artifact(evt):
                db_calls.tag_artifact(evt, "tls", self._dbcursor)
                total += 1
                        
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

        for evt in self.events["pcap"]:
            if self.is_pcap_artifact(evt):
                db_calls.tag_artifact(evt, "pcap", self._dbcursor)
                total += 1
        
        logger.debug("{} artifacts found and tagged for cases {}".format(total, self.uuid))




    
def main():
    conf = configparser.ConfigParser()

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", dest="case_uuid")
    parser.add_argument("-c", dest="config")
    args = parser.parse_args()

    if args.config:
        conf.readfp(open(args.config))
    else:
        conf.readfp(open("runmanager.conf"))
    
    host = "localhost"
    conn_string = "host='{0}' dbname='{1}' user='{2}' password='{3}'".format(host, conf.get("General", "dbname"), conf.get("General", "dbuser"), conf.get("General" ,"dbpass"))
    conn = psycopg2.connect(conn_string)
    conn.autocommit = True
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    
    if args.case_uuid:
        pp = Postprocessor(args.case_uuid, cursor)
        
        pp.update_events()
    else:
        for case in get_cases_to_process():
            pp = Postprocessor(case["uuid"], cursor)
            pp.update_events()

def get_cases_to_process():
    cases = get_case_listing()
    return cases

def get_case_listing(uri="/cases/json"):
    cases = []
    while True:
        r = requests.get("http://127.0.0.1:3000" + uri, verify=False)
        if r.status_code == 200:
            obj = json.loads(r.text)
            cases.extend(obj["cases"])
            if obj["next"] == "":
                break
            else:
                uri = obj["next"]
        else:
            break
    logger.debug("Got {} cases".format(len(cases)))
    return cases

if __name__ == "__main__":
    main()