#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import logging, libvirt, psycopg2, psycopg2.extras, os, psutil, arrow, socket, json, sys
import runinstance, threading, time, pcap_parser, maintenance, db_calls, subprocess, signal
from lxml import etree
import configparser
from io import StringIO, BytesIO


logger = logging.getLogger("antfarm")

class Worker():
    def __init__(self, config, vmdata, NUM_LEVEL, RUN_NUM_LEVEL):        
        self._conf = config
        self._vm_uuid = vmdata["uuid"]
        
        self.logger = logger.getChild("worker-{}".format(self._vm_uuid))
        self.logger.setLevel(NUM_LEVEL)
        logfile = os.path.join(self._conf.get('General', 'logdir'), str(self._vm_uuid)) + '.log'
        logger.info("Logging run at level {}".format(RUN_NUM_LEVEL))
        fh = logging.FileHandler(logfile)
        
        fmt = '[%(asctime)s] %(levelname)s\t%(message)s'
        dfmt ='%Y%m%d %H:%M:%S'
        formatter = logging.Formatter(fmt=fmt, datefmt=dfmt)
        
        log_modules = [__name__, "pyvnc", "vmworker", "runinstance", "db_calls", "victimfiles", "maintenance", "yarahandler"]
        for module in log_modules:
            logging.getLogger(module).setLevel(NUM_LEVEL)
        
        fh.setLevel(RUN_NUM_LEVEL)
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        self.logfilehandler = fh

        self._cursor, self._dbconn = self._db_conn(self._conf.get('General', 'dbname'), self._conf.get('General', 'dbuser'), self._conf.get('General' ,'dbpass'))
        self._lv_conn = libvirt.open("qemu:///system")
        self._victim_params = self._get_victim_params()
    
    def _get_victim_params(self):
        self._cursor.execute('SELECT * FROM victims WHERE uuid=%s LIMIT 1', (self._vm_uuid,))
        data = self._cursor.fetchall()
        params = data[0]
        params["last_reboot"] = arrow.get(params["last_reboot"]).format('YYYY-MM-DD HH:mm:ss.SSSZ')
        params["vnc"] = self._get_vnc()
        logger.debug("Got details for VM UUID {0}, IP is {1}, username is '{2}'".format(self._vm_uuid, params["ip"], params["username"]))
        return params

    def _get_vnc(self):
        dom = self._lv_conn.lookupByUUIDString(self._vm_uuid)
        domstruct = etree.fromstring(dom.XMLDesc())
        vncport = etree.XPath("/domain/devices/graphics")(domstruct)[0].get("port")
        vncconnect = {"address": "127.0.0.1", "port": vncport}
        return vncconnect
    
    def prep_for_run(self):
        self._mntdir = self._check_mntdir()
        self._dldir = self._check_dldir()
        self.outputdata = {}
        self._cursor.execute("""INSERT INTO "workerstate" (uuid, pid, position, params) VALUES (%s, %s, %s, '{}')""", (self._vm_uuid, os.getpid(), 'instantiated'))
        self.logger.info("Instantiated worker object")
        
        
    def _db_conn(self, db, user, password):
        host = 'localhost'
        conn_string = "host='{0}' dbname='{1}' user='{2}' password='{3}'".format(host, db, user, password)
        conn = psycopg2.connect(conn_string)
        conn.autocommit = True
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        self.logger.debug('DB connection started on {0} to db "{1}" with user "{2}"'.format(host, db, user))
        return cursor, conn
    
    def _check_mntdir(self):
        # make sure directory for mounting vm disk to exists and nothing is mounted to it
        mntdir = os.path.join(self._conf.get('General', 'mountdir'), '{0}'.format(self._vm_uuid))
        self.logger.debug("Selected mount directory {0}".format(mntdir))
        if not os.path.isdir(mntdir):
            self.logger.debug("Mount directory does not exist, creating...")
            os.makedirs(mntdir)
        return mntdir
        
    def _check_dldir(self):
        dldir = os.path.join(self._conf.get('General', 'basedir'), self._conf.get('General', 'instancename'), 'suspects', 'downloads', str(self._vm_uuid))
        self.logger.debug("Selected download directory {0}".format(dldir))
        if not os.path.exists(dldir):
            self.logger.debug("Download directory {} does not exist, creating...".format(dldir))
            os.makedirs(dldir)
            
        return dldir
        
                
    def _exit(self, value=0):
        self._cursor.execute("""DELETE FROM workerstate WHERE uuid = %s""", (self._vm_uuid,))
        dbconn.close()
        self.logger.info("Closed connection to DB - cleanup complete, exiting now.")
        self.logger.removeHandler(self.logfilehandler)
        exit(value)
    
    def _db_cleanup(self, vm_uuid):
        self._dbconn.rollback()
        self._cursor.execute("""DELETE FROM "workerstate" WHERE uuid=%s""", (vm_uuid,))
        self._dbconn.commit()
        self.logger.info("Removed worker state entry from DB")
            
    def _list_unavailable_vms(self):
        self._cursor.execute("""SELECT uuid FROM "workerstate" """)
        records = self._cursor.fetchall()
        in_use = []
        for r in records:
            in_use.append(r["uuid"])
        self.logger.debug('In use VM IDs: {0}'.format(json.dumps(in_use)))
        return in_use
    
    def _list_available_vms(self):
        domains = self._lv_conn.listDomainsID()
        self._cursor.execute("""SELECT * FROM victims WHERE status = 'production'""")
        rows = self._cursor.fetchall()
        production_uuids = []
        for row in rows:
            production_uuids.append(row["uuid"])
        self.logger.debug("Production VM UUIDs: {0}".format(json.dumps(production_uuids)))
        available = []
        in_use = self._list_unavailable_vms()
        if domains:
            for dom in domains:
                uuid = self._lv_conn.lookupByID(dom).UUIDString()
                if uuid not in in_use and uuid in production_uuids:
                    available.append(dom)
        else:
            self.logger.error("No victims online")
        return available
    
    def _state_update(self, state, params=(False, None)):
        if not params[0]:
            self._cursor.execute("""UPDATE "workerstate" SET position = %s WHERE uuid=%s""", (state, self._vm_uuid))
            self._dbconn.commit()
            self.logger.debug("Worker state changed to '{0}'".format(state))
        else:
            uuid = ""
            if "uuid" in params[1]:
                uuid = params[1]["uuid"]
            d = dict(params[1])
            tformat = 'YYYY-MM-DD HH:mm:ss'
            d["submittime"] = arrow.get(d["submittime"]).format(tformat)
            if d["starttime"]:
                d["starttime"] = arrow.get(d["starttime"]).format(tformat)
            if d["endtime"]:
                d["endtime"] = arrow.get(d["endtime"]).format(tformat)
            pstring = json.dumps(d)
            self._cursor.execute("""UPDATE "workerstate" SET (position, params, job_uuid) = (%s, %s, %s) WHERE uuid=%s""", (state, pstring, uuid, self._vm_uuid))
            self._dbconn.commit()
            self.logger.debug("Worker state changed to '{0}' with details '{1}'".format(state, params))
            
    def _case_update(self, status, case_uuid):
        self._cursor.execute("""UPDATE "cases" SET status = %s WHERE uuid=%s""", (status, case_uuid))
        self._dbconn.commit()
        self.logger.debug("Case status for case UUID {0} changed to '{1}'".format(case_uuid, status))

    # core sequence of actions to take for a received job
    def process(self, params):
        self.logger.debug("Message received: {0}".format(params))
        try:
            dom = self._lv_conn.lookupByUUIDString(self._vm_uuid)            
            state = "available"
            tryctr = 0
            
            while True:
                available = True
                pid = None
                for c in psutil.net_connections():
                    if c.laddr.port == int(self._victim_params["vnc"]["port"]) and c.status == 'ESTABLISHED':
                        available = False
                        pid = c.pid
                if available:
                    break
                else:
                    if tryctr > 3:
                        logger.info("PID {} has been hogging VNC connection. Terminating with extreme prejudice...".format(pid))
                        subprocess.call("kill", "-9", "{}".format(pid))
                    if state != "vnc_blocked":
                        self._state_update("vnc_blocked")
                        self._case_update("vnc_blocked", params["uuid"])
                        state = "vnc_blocked"
                        self.logger.error("VNC connection blocked, sleeping 20 seconds...")
                        time.sleep(20)
                    tryctr += 1
            
            self.outputdata["received job"] = params
                
            cfg = self._conf
            suspect = runinstance.RunInstance(
                self._cursor,
                self._dbconn,
                self._vm_uuid,
                cfg,
                params["fname"],
                params["uuid"],
                params["submittime"],
                params["hashes"],
                self._victim_params,
                ttl=params["runtime"],
                interactive=params["interactive"],
                reboots=params["reboots"],
                banking=params["banking"],
                web=params["web"]
                )
            
            finished = False
            while not finished:
                try:
                    self._case_update('received', suspect.uuid)
                    tformat = 'YYYY-MM-DD HH:mm:ss.SSSZ'
                                
                    updateparams = (self._vm_uuid,
                                    suspect.victim_params["os"],
                                    arrow.get(suspect.submittime).format(tformat),
                                    arrow.get(suspect.starttime).format(tformat),
                                    suspect.reboots,
                                    bool(suspect.interactive),
                                    bool(suspect.banking),
                                    bool(suspect.web),
                                    suspect.ttl,
                                    json.dumps(self._victim_params),
                                    suspect.uuid)
                    
                    self._cursor.execute("""UPDATE cases SET (vm_uuid, vm_os, submittime, starttime, reboots, interactive, banking, web, runtime, victim_params)=""" +
                                        """(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) WHERE uuid=%s""", updateparams)
                    self._dbconn.commit()
                    
                    self._state_update('initialising', (True, suspect._dump_dict()))
                    self._case_update('initialising', suspect.uuid)
                    
                    imgshort = os.path.join(suspect.rootdir, 'www', 'public', 'images', 'cases', suspect.uuid[0:2])
                    if not os.path.exists(imgshort):
                        os.mkdir(imgshort)
                    imgdir = os.path.join(imgshort, suspect.uuid)
                    if not os.path.exists(imgdir):
                        os.mkdir(imgdir)
                    
                    state, reason = dom.state()
                    if state in [libvirt.VIR_DOMAIN_SHUTOFF, libvirt.VIR_DOMAIN_SHUTDOWN]:
                        # need domain to be running first
                        self.logger.info("Victim is offline. Starting first...")
                        dom.create()
                        time.sleep(5)

                        # vnc port only valid after domain is started
                        self._victim_params["vnc"] = self._get_vnc()
                    
                    # revert to most recent snapshot
                    self.logger.info("Restoring snapshot {}".format(self._victim_params["snapshot"]))
                    snapshot = dom.snapshotLookupByName(self._victim_params["snapshot"])
                    dom.revertToSnapshot(snapshot)
                    
                    self._state_update('restored', (False,None))
                    self._case_update('restored', suspect.uuid)
                                
                    # adjust run time to allow for all activity
                    # 1 minute for setup, 1 minute run time minimum
                    mintime = 120
                    if suspect.banking:
                        mintime += 45
                    if suspect.web:
                        mintime += 30
                    mintime += (suspect.reboots * 35)
                    
                    if mintime > suspect.ttl:
                        suspect.ttl = mintime
                        
                    # run process as per params given
                    self.logger.debug("Issuing command set to victim, worker allowing {0} seconds runtime".format(suspect.ttl))
                    self._state_update('running', (False,None))
                    self._case_update('running', suspect.uuid)
                    
                    begin = arrow.utcnow()
                    end = begin.shift(seconds=+suspect.ttl)
                    suspect.do_run(dom, self._lv_conn)
                    suspect.present_vnc()
                    
                    # if minimum runtime not yet elapsed, let malware run until it has
                    while arrow.utcnow() < end:
                        time.sleep(5)
                    
                    self.logger.info("Runtime limit reached, holding for agent confirmation...")
                    
                    checks = 6
                    while db_calls.get_case_status(suspect.uuid, self._cursor) != "agent done":
                        if checks > 0:
                            time.sleep(5)
                            checks -= 1
                        else:
                            logger.warning("Agent failed to post commpletion in within time limit")
                            break
                                    
                    # make a screenshot
                    suspect.screenshot(dom, self._lv_conn)
                    
                    # pause the vm before mounting filesystem
                    dom.suspend()
                    self.logger.info("Victim suspended, starting data collection")
                    self._state_update('collecting', (False,None))
                    self._case_update('collecting', suspect.uuid)
                    suspect.endtime = arrow.utcnow().format(tformat)
                    self._cursor.execute("""UPDATE cases SET endtime=%s WHERE uuid=%s""", (suspect.endtime, suspect.uuid))
                    self._state_update('collecting', (False, None))
                    finished = True
                except Exception:
                    ex_type, ex, tb = sys.exc_info()
                    fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
                    lineno = tb.tb_lineno
                    self.logger.error("Exception {0} {1} in {2}, line {3} while processing job, retrying run".format(ex_type, ex, fname, lineno))
                    self._case_update('retrying', suspect.uuid)
                    # reset start time so data from previous attempt is not included
                    suspect.starttime = arrow.utcnow().timestamp
            # gather data
            suspect.construct_record(self._victim_params)
            self.logger.debug("Output written")
            self._case_update('complete', suspect.uuid)
             
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            self.logger.error("Exception {0} {1} in {2}, line {3} while processing job, aborting".format(ex_type, ex, fname, lineno))
            self._case_update('failed', suspect.uuid)
        finally:
            suspect.remove_vnc()
            self._state_update('cleanup', (False,None))
            self.logger.removeHandler(suspect.runlog)
            self.logger.removeHandler(self.logfilehandler)
            del(suspect)
            # ensure vm suspended
            self._lv_conn.lookupByUUIDString(self._vm_uuid).suspend()
            self._cursor.execute("""UPDATE victims SET (runcounter)=(runcounter + 1) WHERE uuid=%s""", (self._victim_params["uuid"],))
            self._cursor.execute("""DELETE FROM workerstate WHERE uuid = %s""", (self._victim_params["uuid"],))
            self._dbconn.commit()
        
    def do_maintenance(self):
        logger.info("Entering maintenance cycle...")
        janitor = maintenance.Janitor(self._conf, self._victim_params, self._cursor, self._dbconn)
        janitor.standard_maintenance()
        self._state_update('idle')
