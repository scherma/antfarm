#!/usr/bin/env python
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com


import psycopg2, psycopg2.extras, json, logging, xmljson
from lxml import etree

logger = logging.getLogger(__name__)

def insert_dns(evts, uuid, cursor):
    dns_sql = """INSERT INTO suricata_dns (uuid, src_ip, src_port, dest_ip, dest_port, timestamp, dnsdata) VALUES %s ON CONFLICT DO NOTHING"""
    values = []
    for evt in evts:     
        row = (uuid, evt["src_ip"], evt["src_port"], evt["dest_ip"], evt["dest_port"], evt["timestamp"], json.dumps(evt["dns"]))
        values.append(row)

    psycopg2.extras.execute_values(cursor, dns_sql, values)
    logger.debug("inserted {0} dns events for case {1}".format(len(values), uuid))

def insert_http(evts, uuid, cursor):
    http_sql = """INSERT INTO suricata_http (uuid, src_ip, src_port, dest_ip, dest_port, timestamp, httpdata) VALUES %s ON CONFLICT DO NOTHING"""
    values = []
    for evt in evts:     
        row = (uuid, evt["src_ip"], evt["src_port"], evt["dest_ip"], evt["dest_port"], evt["timestamp"], json.dumps(evt["http"]))
        values.append(row)

    psycopg2.extras.execute_values(cursor, http_sql, values)
    logger.debug("inserted {0} http events for case {1}".format(len(values), uuid))

def insert_alert(evts, uuid, cursor):
    alert_sql = """INSERT INTO suricata_alert (uuid, src_ip, src_port, dest_ip, dest_port, timestamp, alert, payload) VALUES %s ON CONFLICT DO NOTHING"""
    values = []
    for evt in evts:
        if "payload" not in evt:
            evt["payload"] = None
        row = (uuid, evt["src_ip"], evt["src_port"], evt["dest_ip"], evt["dest_port"], evt["timestamp"], json.dumps(evt["alert"]), evt["payload"])
        values.append(row)

    psycopg2.extras.execute_values(cursor, alert_sql, values)
    logger.debug("inserted {0} alert events for case {1}".format(len(values), uuid))
    
def insert_tls(evts, uuid, cursor):
    tls_sql = """INSERT INTO suricata_tls (uuid, src_ip, src_port, dest_ip, dest_port, timestamp, tlsdata) VALUES %s ON CONFLICT DO NOTHING"""
    values = []
    for evt in evts:     
        row = (uuid, evt["src_ip"], evt["src_port"], evt["dest_ip"], evt["dest_port"], evt["timestamp"], json.dumps(evt["tls"]))
        values.append(row)

    psycopg2.extras.execute_values(cursor, tls_sql, values)
    logger.debug("inserted {0} tls events for case {1}".format(len(values), uuid))
    
def insert_sysmon(events_list, uuid, cursor):
    schema = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    
    values = []
    sql = """INSERT INTO sysmon_evts (uuid, recordid, eventid, timestamp, executionprocess, executionthread, computer, eventdata, evt_xml) VALUES %s"""
    
    for event in events_list:
        j = xmljson.badgerfish.data(event)
        system = j["{0}Event".format(schema)]["{0}System".format(schema)]
        evtdata = {}
        for item in j["{0}Event".format(schema)]["{0}EventData".format(schema)]["{0}Data".format(schema)]:
            if "$" not in item:
                evtdata[item["@Name"]] = None
            else:
                evtdata[item["@Name"]] = item["$"]
            if item["@Name"] == "Hashes":
                hasheslist = item["$"].split(",")
                evtdata["Hashes"] = {}
                for h in hasheslist:
                    parts = h.split("=")
                    hashtype = parts[0]
                    hashval = parts[1]
                    evtdata["Hashes"][hashtype] = hashval
                    
        evtjson = json.dumps(evtdata)
        recordID = system["{0}EventRecordID".format(schema)]["$"]
        eventID = system["{0}EventID".format(schema)]["$"]
        timestamp = "{0} +0000".format(system["{0}TimeCreated".format(schema)]["@SystemTime"])
        executionProcess = system["{0}Execution".format(schema)]["@ProcessID"]
        executionThread = system["{0}Execution".format(schema)]["@ThreadID"]
        computer = system["{0}Computer".format(schema)]["$"]
        
        row = (uuid, recordID, eventID, timestamp, executionProcess, executionThread, computer, evtjson, etree.tostring(event))
        
        values.append(row)
    
    psycopg2.extras.execute_values(cursor, sql, values)
    logger.debug("Inserted {0} sysmon events for case {1}".format(len(values), uuid))