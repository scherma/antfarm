#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com


import psycopg2, psycopg2.extras, json, logging, xmljson, sys, os, arrow, pathlib
from lxml import etree

logger = logging.getLogger("antfarm.worker")

def insert_dns(evts, uuid, cursor):
    dns_sql = """INSERT INTO suricata_dns (uuid, src_ip, src_port, dest_ip, dest_port, timestamp, dnsdata) VALUES %s ON CONFLICT DO NOTHING"""
    values = []
    for evt in evts:     
        row = (uuid, evt["src_ip"], evt["src_port"], evt["dest_ip"], evt["dest_port"], evt["timestamp"], json.dumps(evt["dns"]))
        values.append(row)

    psycopg2.extras.execute_values(cursor, dns_sql, values)
    logger.debug("inserted {0} dns events for case {1}".format(len(values), uuid))
    
def get_case_status(uuid, cursor):
    sql = """SELECT status FROM cases WHERE uuid=%s"""
    cursor.execute(sql, (uuid,))
    rows = cursor.fetchall()
    return rows[0]["status"]

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
    
def insert_files(filesdict, uuid, cursor):
    try:
        files_sql = """INSERT INTO victimfiles (uuid, file_path, os_path, file_stat, yararesult, saved, avresult, mimetype, sha256) VALUES %s ON CONFLICT DO NOTHING"""
        values = []
        for path, data in filesdict.items():
            yara_json = {}
            if "yara" in data:
                yara_json = build_yara_json(data["yara"])
            row = (uuid, path, data["os_path"], json.dumps(data["statns"]), json.dumps(yara_json), data["saved"], data["avresult"], data["mimetype"], data["sha256"])
            values.append(row)
        
        psycopg2.extras.execute_values(cursor, files_sql, values)
        logger.debug("Indexed {} files for case {}".format(len(values), uuid))
    
    except Exception:
        ex_type, ex, tb = sys.exc_info()
        fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
        lineno = tb.tb_lineno
        logger.error("Exception {0} {1} in {2}, line {3} parsing filesystem data, events not written to DB".format(ex_type, ex, fname, lineno))

def insert_pcap_streams(streams, uuid, cursor):
    streams_sql = """INSERT INTO pcap_summary (uuid, timestamp, src_ip, src_port, dest_ip, dest_port, protocol) VALUES %s"""
    values = []
    for stream in streams:
        ts = arrow.get(stream["timestamp"]).format("YYYY-MM-DD HH:mm:ss.SSS Z")
        row = (uuid, ts, stream["src"], stream["srcport"], stream["dst"], stream["dstport"], stream["protocol"])
        values.append(row)
    psycopg2.extras.execute_values(cursor, streams_sql, values)
    logger.debug("Inserted {} streams from pcap for case {}".format(len(values), uuid))
    
    
def yara_detection(yara_matches, sha256, cursor):
    match_json = build_yara_json(yara_matches)
    yara_sql = """UPDATE suspects SET yararesult = %s WHERE sha256 = %s"""
    cursor.execute(yara_sql, (json.dumps(match_json), sha256))
    logger.debug("Added yara detection to suspect {}".format(sha256))
    
def build_yara_json(yara_matches):
    match_json = {}
    for match in yara_matches:
        match_json[match.rule] = {}
        match_json[match.rule]["Author"] = match.meta["author"] if "author" in match.meta else "unknown"
        match_json[match.rule]["Description"] = match.meta["description"] if "description" in match.meta else "unknown"
        match_json[match.rule]["Reference"] = match.meta["reference"] if "reference" in match.meta else "unknown"
        match_json[match.rule]["Date"] = match.meta["date"] if "date" in match.meta else "unknown"
        match_json[match.rule]["tags"] = match.tags
    return match_json
    
def insert_sysmon(events_list, uuid, cursor):
    schema = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    
    values = []
    sql = """INSERT INTO sysmon_evts (uuid, recordid, eventid, timestamp, executionprocess, executionthread, computer, eventdata, evt_xml) VALUES %s"""
    
    try:
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
            
            row = (uuid, recordID, eventID, timestamp, executionProcess, executionThread, computer, evtjson, etree.tostring(event).decode("utf-8"))
            
            values.append(row)
        psycopg2.extras.execute_values(cursor, sql, values)
        logger.debug("Inserted {0} sysmon events for case {1}".format(len(values), uuid))
    
    except Exception:
        ex_type, ex, tb = sys.exc_info()
        fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
        lineno = tb.tb_lineno
        logger.error("Exception {0} {1} in {2}, line {3} parsing Sysmon data, events not written to DB".format(ex_type, ex, fname, lineno))
        
def all_case_events(uuid, cursor):
    sysmonsql = """SELECT * FROM sysmon_evts WHERE uuid = %s"""
    httpsql = """SELECT * FROM suricata_http WHERE uuid = %s"""
    dnssql = """SELECT * FROM suricata_dns WHERE uuid = %s"""
    alertsql = """SELECT * FROM suricata_alert WHERE uuid = %s"""
    tlssql  = """SELECT * FROM suricata_tls WHERE uuid = %s"""
    filessql = """SELECT * FROM victimfiles WHERE uuid = %s"""
    pcapsql = """SELECT * FROM pcap_summary WHERE uuid = %s"""
    
    cursor.execute(sysmonsql, (uuid,))
    sysmonrows = cursor.fetchall()
    cursor.execute(httpsql, (uuid,))
    httprows = cursor.fetchall()
    cursor.execute(dnssql, (uuid,))
    dnsrows = cursor.fetchall()
    cursor.execute(alertsql, (uuid,))
    alertrows = cursor.fetchall()
    cursor.execute(tlssql, (uuid,))
    tlsrows = cursor.fetchall()
    cursor.execute(filessql, (uuid,))
    filesrows = cursor.fetchall()
    cursor.execute(pcapsql, (uuid,))
    pcaprows = cursor.fetchall()
    
    return {"sysmon": sysmonrows, "http": httprows, "dns": dnsrows, "alert": alertrows, "files": filesrows, "tls": tlsrows, "pcap": pcaprows}

def tag_artifact(evtdata, evttype, cursor):
    if evttype == "sysmon":
        sql = """UPDATE sysmon_evts SET is_artifact = true WHERE uuid = %s AND recordid = %s"""
        cursor.execute(sql, (evtdata["uuid"], evtdata["recordid"]))
    elif evttype == "dns":
        sql = """UPDATE suricata_dns SET is_artifact = true WHERE uuid = %s AND id = %s"""
        cursor.execute(sql, (evtdata["uuid"], evtdata["id"]))
    elif evttype == "tls":
        sql = """UPDATE suricata_tls SET is_artifact = true WHERE uuid = %s AND id = %s"""
        cursor.execute(sql, (evtdata["uuid"], evtdata["id"]))
    elif evttype == "http":
        sql = """UPDATE suricata_http SET is_artifact = true WHERE uuid = %s AND id = %s"""
        cursor.execute(sql, (evtdata["uuid"], evtdata["id"]))
    elif evttype == "alert":
        sql = """UPDATE suricata_alert SET is_artifact = true WHERE uuid = %s AND id = %s"""
        cursor.execute(sql, (evtdata["uuid"], evtdata["id"]))
    elif evttype == "filesystem":
        sql = """UPDATE victimfiles SET is_artifact = true WHERE uuid = %s AND file_path = %s"""
        cursor.execute(sql, (evtdata["uuid"], evtdata["file_path"]))
    elif evttype == "pcap":
        sql = """UPDATE pcap_summary SET is_artifact = true WHERE id = %s"""
        cursor.execute(sql, (evtdata["id"],))

def append_summary(uuid, summary, cursor):
    sql = """UPDATE cases SET summary = %s WHERE uuid = %s"""
    cursor.execute(sql, (json.dumps(summary), uuid))
    return cursor.rowcount
    
def timestomped_files(uuid, cursor):
    sql = """SELECT * FROM sysmon_evts WHERE uuid = %s AND eventid = 2"""
    cursor.execute(sql, (uuid,))
    data = cursor.fetchall()
    timestomped = []
    for row in data:
        try:
            if isinstance(row["eventdata"], dict) and "CreationUtcTime" in row:
                if arrow.get(row["CreationUtcTime"]) < arrow.get(row["PreviousCreationUtcTime"]):
                    timestomped.append(eventdata["TargetFileName"].replace("\\", "/")[2:])
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            logger.error("Exception {0} {1} in {2}, line {3} parsing timestomping data; skipping timestomp test".format(ex_type, ex, fname, lineno))
            logger.debug("Row data: {}".format(row))
            
    return timestomped
        
def artifact_rules(cursor, enabled=True):
    sql = ""
    if enabled:
        sql = """SELECT filter_config.*,filter_evttypes.* FROM filter_config FULL JOIN filter_evttypes ON filter_config.evttype = filter_evttypes.evttype WHERE filter_config.enabled = true"""
    else:
        sql = """SELECT filter_config.*,filter_evttypes.* FROM filter_config FULL JOIN filter_evttypes ON filter_config.evttype = filter_evttypes.evttype"""
    cursor.execute(sql)
    return cursor.fetchall()