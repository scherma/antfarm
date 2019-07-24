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
        self.artifact_rules = self.prep_rules()

    def prep_rules(self):
        rulestruct = {}
        rules = db_calls.artifact_rules(self._dbcursor)
        for rule in rules:
            key = str(rule["evttype"])
            if key not in rulestruct:
                rulestruct[key] = []
            rulestruct[key].append(rule)
        return rulestruct

    def get_element(self, d, path_arr):
        el = path_arr.pop(0)
        if len(path_arr) == 0:
            return d[el]
        else:
            return self.get_element(d[el], path_arr)


    def test_item(self, item, rule):
        maybe = True
        for condition in rule["conditions"]:
            if condition["field"] in item:
                # first get the target field to run comparisons on
                el = item[condition["field"]]
                if "object_path" in condition:
                    # if the field is jsonb, locate the desired element of the json object
                    try:
                        el = self.get_element(el, list.copy(condition["object_path"]))
                    except KeyError:
                        # if the element is not present in json object, rule does not match
                        maybe = False
                        break
                # if any of the patterns match, condition is matched
                pmatch = False
                if condition["method"] == "rex":
                    for pattern in condition["pattern"]:
                        if re.search(pattern, el, re.IGNORECASE):
                            pmatch = True
                elif condition["method"] == "eq":
                    for pattern in condition["pattern"]:
                        if type(el) == str:
                            if pattern.lower() == el.lower():
                                pmatch = True
                        elif type(el) == int:
                            if pattern == el:
                                pmatch = True
                # if any condition is NOT matched, rule is not a match
                if not pmatch:
                    maybe = False
                    break
                else:
                    pass
            else:
                logger.debug("Cannot test rule ID {} against item: field {} not present in item".format(rule["id"], condition["field"]))
                maybe = False
        return maybe
        
        
    def is_sysmon_artifact(self, evt):
        maybe = False
        if evt["eventid"] == 1:
            if "1" in self.artifact_rules:
                for rule in self.artifact_rules["1"]:
                    if self.test_item(evt, rule):
                        maybe = True

        elif evt["eventid"] == 7:
            if "6" in self.artifact_rules:
                for rule in self.artifact_rules["6"]:
                    if self.test_item(evt, rule):
                        maybe = True

        elif evt["eventid"] == 12:
            if "11" in self.artifact_rules:
                for rule in self.artifact_rules["11"]:
                    if self.test_item(evt, rule):
                        maybe = True

        elif evt["eventid"] == 13:
            if "12" in self.artifact_rules:
                for rule in self.artifact_rules["12"]:
                    if self.test_item(evt, rule):
                        maybe = True

        return maybe
    
    def is_suricata_dns_artifact(self, evt):
        maybe = False
        if "20" in self.artifact_rules:
            for rule in self.artifact_rules["20"]:
                if self.test_item(evt, rule):
                    maybe = True
        return maybe
    
    def is_suricata_http_artifact(self, evt):
        maybe = False
        if "21" in self.artifact_rules:
            for rule in self.artifact_rules["21"]:
                if self.test_item(evt, rule):
                    maybe = True
        return maybe
    
    def is_suricata_tls_artifact(self, evt):
        maybe = False
        if "22" in self.artifact_rules:
            for rule in self.artifact_rules["22"]:
                if self.test_item(evt, rule):
                    maybe = True
        return maybe
    
    def is_suricata_alert_artifact(self, evt):
        maybe = False
        if "23" in self.artifact_rules:
            for rule in self.artifact_rules["23"]:
                if self.test_item(evt, rule):
                    maybe = True
        return maybe
    
    def is_filesystem_artifact(self, evt):
        maybe = False
        if "30" in self.artifact_rules:
            for rule in self.artifact_rules["30"]:
                if self.test_item(evt, rule):
                    maybe = True
        return maybe
    
    def is_pcap_artifact(self, evt):
        maybe = False
        if "31" in self.artifact_rules:
            for rule in self.artifact_rules["31"]:
                if self.test_item(evt, rule):
                    maybe = True
        return maybe

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