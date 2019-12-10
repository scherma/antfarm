#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import arrow, db_calls, psycopg2, psycopg2.extras, sys, logging, configparser, re, argparse, requests, json, arrow

logger = logging.getLogger("antfarm.worker")

class Postprocessor:
    def __init__(self, uuid, dbcursor, reset=False):
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
        logger.debug("Rules retrieved and prepped")
        return rulestruct

    def get_element(self, d, path_arr):
        el = path_arr.pop(0)
        if len(path_arr) == 0:
            return d[el]
        else:
            return self.get_element(d[el], path_arr)


    def test_item(self, item, rule):
        return self.all_conditions_match(item, rule["conditions"])

        #maybe = False
        #for condition in rule["conditions"]:
        #    if condition["field"] in item:
        #        # first get the target field to run comparisons on
        #        el = item[condition["field"]]
        #        if "object_path" in condition:
        #            # if the field is jsonb, locate the desired element of the json object
        #            try:
        #                el = self.get_element(el, list.copy(condition["object_path"]))
        #            except KeyError:
        #                # if the element is not present in json object, rule does not match
        #                break
        #        # if any of the patterns match, condition is matched
        #        pmatch = False
        #        if condition["method"] == "rex":
        #            for pattern in condition["pattern"]:
        #                if re.search(pattern, el, re.IGNORECASE):
        #                    pmatch = True

        #        elif condition["method"] == "eq":
        #            for pattern in condition["pattern"]:
        #                if type(el) == str:
        #                    if pattern.lower() == el.lower():
        #                        pmatch = True
        #                elif type(el) == int:
        #                    if pattern == el:
        #                        pmatch = True
        #        # if any condition is NOT matched, rule is not a match
        #        if pmatch:
        #            #logger.debug("One of the patterns matched; tagging item as artifact")
        #            maybe = True
        #            break
        #    else:
        #        logger.debug("Cannot test rule ID {} against item: field {} not present in item".format(rule["id"], condition["field"]))
        #        maybe = False
        #return maybe

    def condition_is_true(self, item, condition):
        if condition["field"] in item:
            element = item[condition["field"]]
            if "object_path" in condition:
                try:
                    element = self.get_element(element, list.copy(condition["object_path"]))
                except KeyError:
                    logger.debug("Couldn't get path {} from source item".format(condition["object_path"]))
                    return False
                    
            # if any of the patterns match, condition is a match
            if condition["method"] == "rex":
                for pattern in condition["pattern"]:
                    if re.search(pattern, element, re.IGNORECASE):
                        return True
            elif condition["method"] == "eq":
                for pattern in condition["pattern"]:
                    if type(element) == str:
                        if pattern.lower() == element.lower():
                            return True
                    elif type(element) == int:
                        if pattern == element:
                            return True
        
        # if nothing has matched to this point, item is not a match
        return False

    def all_conditions_match(self, item, conditions):
        for condition in conditions:
            if not self.condition_is_true(item, condition):
                return False
        
        # if none of the conditions have returned false, all are true and rule has matched
        return True
        

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

        elif evt["eventid"] == 11:
            if "10" in self.artifact_rules:
                for rule in self.artifact_rules["10"]:
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
        summary = {
            "dns": 0,
            "http": 0,
            "tls": 0,
            "alert": 0,
            "sysmon": 0,
            "files": 0,
            "pcap": 0
        }

        total = 0
        logger.debug("Scanning {} DNS events...".format(len(self.events["dns"])))
        for evt in self.events["dns"]:
            if self.is_suricata_dns_artifact(evt):
                db_calls.tag_artifact(evt, "dns", self._dbcursor)
                total += 1
            else:
                summary["dns"] += 1
        
        
        logger.debug("Scanning {} HTTP events...".format(len(self.events["http"])))
        for evt in self.events["http"]:
            if self.is_suricata_http_artifact(evt):
                db_calls.tag_artifact(evt, "http", self._dbcursor)
                total += 1
            else:
                summary["http"] += 1

        logger.debug("Scanning {} TLS events...".format(len(self.events["tls"])))
        for evt in self.events["tls"]:
            if self.is_suricata_tls_artifact(evt):
                db_calls.tag_artifact(evt, "tls", self._dbcursor)
                total += 1
            else:
                summary["tls"] += 1
                        
        logger.debug("Scanning {} Suricata alerts...".format(len(self.events["alert"])))
        for evt in self.events["alert"]:
            if self.is_suricata_alert_artifact(evt):
                db_calls.tag_artifact(evt, "alert", self._dbcursor)
                total += 1
            else:
                summary["alert"] += 1
                
        logger.debug("Scanning {} Sysmon events...".format(len(self.events["sysmon"])))
        for evt in self.events["sysmon"]:
            if self.is_sysmon_artifact(evt):
                db_calls.tag_artifact(evt, "sysmon", self._dbcursor)
                total += 1
            else:
                summary["sysmon"] += 1
        
        logger.debug("Scanning {} filesystem events...".format(len(self.events["files"])))
        for evt in self.events["files"]:
            if self.is_filesystem_artifact(evt):
                db_calls.tag_artifact(evt, "filesystem", self._dbcursor)
                total += 1
            else:
                summary["files"] += 1

        logger.debug("Scanning {} PCAP flows...".format(len(self.events["pcap"])))
        for evt in self.events["pcap"]:
            if self.is_pcap_artifact(evt):
                db_calls.tag_artifact(evt, "pcap", self._dbcursor)
                total += 1
            else:
                summary["pcap"] += 1

        db_calls.append_summary(self.uuid, summary, self._dbcursor)
        
        logger.debug("{} artifacts found and tagged for cases {}".format(total, self.uuid))
        logger.debug("Summary of items not tagged as artifacts: {}".format(summary))




    
def main():
    conf = configparser.ConfigParser()

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", dest="case_uuid")
    parser.add_argument("-c", dest="config")
    parser.add_argument("-s", dest="start", default="1970-01-01")
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
        for case in get_cases_to_process(arrow.get(args.start)):
            pp = Postprocessor(case["uuid"], cursor)
            pp.update_events()

def get_cases_to_process(start=arrow.get("1970-01-01")):
    cases = get_case_listing(start=start)
    return cases

def get_case_listing(uri="/cases/json", start=arrow.get("1970-01-01")):
    cases = []
    while True:
        r = requests.get("http://127.0.0.1:3000" + uri, verify=False)
        if r.status_code == 200:
            obj = json.loads(r.text)
            for case in obj["cases"]:
                if arrow.get(case["submittime"]) > start:
                    cases.append(case)
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
