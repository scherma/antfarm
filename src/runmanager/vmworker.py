#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import logging, libvirt, psycopg2, psycopg2.extras, pika, os, psutil, arrow, socket, json, sys, runinstance, threading, time, pcap_parser
from lxml import etree
import configparser
from io import StringIO, BytesIO

fmt = '[%(asctime)s] %(levelname)s\t%(message)s'
dfmt ='%Y%m%d %H:%M:%S'
formatter = logging.Formatter(fmt=fmt, datefmt=dfmt)

LOGGER = logging.getLogger(__name__)

class Worker():
    def __init__(self, config, vmdata, RUN_NUM_LEVEL=logging.INFO):
        self._conf = config
        self._vm_uuid = vmdata["uuid"]
        self._vm_id = vmdata["id"]
        self._mntdir = self._check_mntdir()
        self._dldir = self._check_dldir()
        self._lv_conn = libvirt.open("qemu:///system")
        self._cursor, self._dbconn = self._db_conn(self._conf.get('General', 'dbname'), self._conf.get('General', 'dbuser'), self._conf.get('General' ,'dbpass'))
        self._victim_params = self._get_victim_params()
        self.outputdata = {}
        
        logfile = os.path.join(self._conf.get('General', 'logdir'), str(self._vm_uuid)) + '.log'
    
        fh = logging.FileHandler(logfile)
        fh.setLevel(RUN_NUM_LEVEL)
        fh.setFormatter(formatter)
        LOGGER.addHandler(fh)
        
        LOGGER.info("Instantiated worker object")
        
        
    def _db_conn(self, db, user, password):
        host = 'localhost'
        conn_string = "host='{0}' dbname='{1}' user='{2}' password='{3}'".format(host, db, user, password)
        conn = psycopg2.connect(conn_string)
        conn.autocommit = True
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        LOGGER.debug('DB connection started on {0} to db "{1}" with user "{2}"'.format(host, db, user))
        return cursor, conn
    
    def _check_mntdir(self):
        # make sure directory for mounting vm disk to exists and nothing is mounted to it
        mntdir = os.path.join(self._conf.get('General', 'mountdir'), '{0}'.format(self._vm_uuid))
        LOGGER.debug("Selected mount directory {0}".format(mntdir))
        if not os.path.isdir(mntdir):
            LOGGER.debug("Mount directory does not exist, creating...")
            os.makedirs(mntdir)
        return mntdir
        
    def _check_dldir(self):
        dldir = os.path.join(self._conf.get('General', 'basedir'), self._conf.get('General', 'instancename'), 'suspects', 'downloads', str(self._vm_id))
        LOGGER.debug("Selected download directory {0}".format(dldir))
        if not os.path.exists(dldir):
            LOGGER.debug("Download directory {} does not exist, creating...".format(dldir))
            os.makedirs(dldir)
            
        return dldir
        
                
    def _exit(self, value=0):
        dbconn.close()
        LOGGER.info("Closed connection to DB - cleanup complete, exiting now.")
        exit(value)
    
    def _db_cleanup(self, vm_uuid):
        self._dbconn.rollback()
        self._cursor.execute("""DELETE FROM "workerstate" WHERE uuid=%s""", (vm_uuid,))
        self._dbconn.commit()
        LOGGER.info("Removed worker state entry from DB")
            
    def _list_unavailable_vms(self):
        self._cursor.execute("""SELECT uuid FROM "workerstate" """)
        records = self._cursor.fetchall()
        in_use = []
        for r in records:
            in_use.append(r["uuid"])
        LOGGER.debug('In use VM IDs: {0}'.format(json.dumps(in_use)))
        return in_use
    
    def _list_available_vms(self):
        domains = self._lv_conn.listDomainsID()
        self._cursor.execute("""SELECT * FROM victims WHERE status = 'production'""")
        rows = self._cursor.fetchall()
        production_uuids = []
        for row in rows:
            production_uuids.append(row["uuid"])
        LOGGER.debug("Production VM UUIDs: {0}".format(json.dumps(production_uuids)))
        available = []
        in_use = self._list_unavailable_vms()
        if domains:
            for dom in domains:
                uuid = self._lv_conn.lookupByID(dom).UUIDString()
                if uuid not in in_use and uuid in production_uuids:
                    available.append(dom)
        else:
            LOGGER.error("No victims online")
        return available
    
    def _state_update(self, state, params=(False, None)):
        if not params[0]:
            self._cursor.execute("""UPDATE "workerstate" SET position = %s WHERE uuid=%s""", (state, self._vm_uuid))
            self._dbconn.commit()
            LOGGER.debug("Worker state changed to '{0}'".format(state))
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
            LOGGER.debug("Worker state changed to '{0}' with details '{1}'".format(state, params))
            
    def _case_update(self, status, case_uuid):
        self._cursor.execute("""UPDATE "cases" SET status = %s WHERE uuid=%s""", (status, case_uuid))
        self._dbconn.commit()
        LOGGER.info("Case status for case UUID {0} changed to '{1}'".format(case_uuid, status))
    
    def _get_victim_params(self):
        self._cursor.execute('SELECT * FROM victims WHERE uuid=%s LIMIT 1', (self._vm_uuid,))
        data = self._cursor.fetchall()
        params = data[0]
        params["last_reboot"] = arrow.get(params["last_reboot"]).format('YYYY-MM-DD HH:mm:ss.SSSZ')
        LOGGER.debug("Got details for VM UUID {0}, IP is {1}, username is '{2}'".format(self._vm_uuid, params["ip"], params["username"]))
        return params

    # core sequence of actions to take for a received job
    def process(self, params):
        LOGGER.info("Message received: {0}".format(params))
        try:
            dom = self._lv_conn.lookupByUUIDString(self._vm_uuid)
            domstruct = etree.fromstring(dom.XMLDesc())
            vncport = etree.XPath("/domain/devices/graphics")(domstruct)[0].get("port")
            vncconnect = {"address": "127.0.0.1", "port": vncport}
            
            state = "available"
            tryctr = 0
            
            while True:
                available = True
                for c in psutil.net_connections():
                    if c.laddr[1] == int(vncport) and c.status == 'ESTABLISHED':
                        available = False
                if available:
                    break
                else:
                    if tryctr > 3:
                        raise RuntimeError("VNC unavailable - possible VNC library problem. Aborting.")
                    if state != "vnc_blocked":
                        self._state_update("vnc_blocked")
                        self._case_update("vnc_blocked", params["uuid"])
                        state = "vnc_blocked"
                    LOGGER.error("VNC connection blocked, sleeping 20 seconds...")
                    time.sleep(20)
                    tryctr += 1
            
            self.outputdata["received job"] = params
                
            self._victim_params["vnc"] = vncconnect
            
            cfg = self._conf
            suspect = runinstance.RunInstance(
                self._cursor,
                self._dbconn,
                self._vm_id,
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
                            suspect.uuid)
            
            self._cursor.execute("""UPDATE cases SET (vm_uuid, vm_os, submittime, starttime, reboots, interactive, banking, web, runtime)=""" +
                                """(%s, %s, %s, %s, %s, %s, %s, %s, %s) WHERE uuid=%s""", updateparams)
            self._dbconn.commit()
            
            self._state_update('initialising', (True, suspect._dump_dict()))
            self._case_update('initialising', suspect.uuid)
            
            imgshort = os.path.join(suspect.rootdir, 'www', 'public', 'images', 'cases', suspect.uuid[0:2])
            if not os.path.exists(imgshort):
                os.mkdir(imgshort)
            imgdir = os.path.join(imgshort, suspect.uuid)
            if not os.path.exists(imgdir):
                os.mkdir(imgdir)
            
            # revert to most recent snapshot
            LOGGER.debug("Restoring VM snapshot")
            snapshot = dom.snapshotCurrent()
            dom.revertToSnapshot(snapshot)
            
            self._state_update('restored', (False,None))
            self._case_update('restored', suspect.uuid)
            LOGGER.debug("Resuming VM")
            #dom.resume()
            
            # start capture
            t = threading.Thread(name="pcap", target=suspect.capture)
            t.start()
            
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
            LOGGER.info("Issuing command set to victim, worker allowing {0} seconds runtime".format(suspect.ttl))
            self._state_update('running', (False,None))
            self._case_update('running', suspect.uuid)
            
            begin = arrow.utcnow()
            end = begin.shift(seconds=+suspect.ttl)
            suspect.do_run(dom, self._lv_conn)
            
            # if minimum runtime not yet elapsed, let malware run until it has
            while arrow.utcnow() < end:
                time.sleep(5)
            
            LOGGER.info("Runtime limit reached, starting data collection")
            
            suspect.stop_capture = True
            
            # make sure the pcap has actually stopped before suspending vm
            # pcap thread only exits if packet is received after the stop flag is set
            # therefore need to force a packet that will be logged by the pcap thread
            while t.isAlive():
                time.sleep(2)
                try:
                    socket.create_connection((suspect.victim_params["ip"], 389), timeout=1)
                except:
                    pass
                
            # make a screenshot
            imgpath = os.path.join(suspect.imgdir, "1.png")
            suspect.screenshot(dom, self._lv_conn)
            LOGGER.debug("Creating screenshot at {0}".format(imgpath))
            
            # pause the vm before mounting filesystem
            dom.suspend()
            LOGGER.debug("VM suspended, starting data collection")
            self._state_update('collecting', (False,None))
            self._case_update('collecting', suspect.uuid)
            suspect.endtime = arrow.utcnow().format(tformat)
            self._cursor.execute("""UPDATE cases SET endtime=%s WHERE uuid=%s""", (suspect.endtime, suspect.uuid))
            self._state_update('collecting', (False, None))
            # gather data
            suspect.construct_record(self._victim_params)
            LOGGER.debug("Output written")
            self._case_update('complete', suspect.uuid)
             
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            LOGGER.error("Exception {0} {1} in {2}, line {3} while processing job, aborting".format(ex_type, ex, fname, lineno))
            self._case_update('failed', suspect.uuid)
        finally:
            self._state_update('cleanup', (False,None))
            # ensure capture thread exits
            suspect.stop_capture = True
            try:
                socket.create_connection((suspect.victim_params["ip"], 389), timeout=1)
            except:
                pass
            LOGGER.removeHandler(suspect.runlog)
            # ensure vm suspended
            self._lv_conn.lookupByUUIDString(self._vm_uuid).suspend()
            self._cursor.execute("""UPDATE victims SET (runcounter)=(runcounter + 1) WHERE uuid=%s""", (self._victim_params["uuid"],))
            self._dbconn.commit()
            self._state_update('idle', params=(False, dict()))
        