#!/usr/bin/env python2
# coding: utf-8
# © https://github.com/scherma
# contact http_error_418@unsafehex.com

import libvirt, sys, os, argparse, logging, uuid, time, pika, json, psycopg2, psycopg2.extras, arrow, db_calls
import shutil, time, evtx_dates, threading, socket, pcap_parser, pyvnc, psutil, ConfigParser, xmljson
import scapy.all as scapy
from subprocess import call
from lxml import etree
from StringIO import StringIO
from PIL import Image
from vncdotool import api as vncapi

logger = logging.getLogger(__name__)

class StopCaptureException(RuntimeError):
    def __init__(self, message, errors):
        super(RuntimeError, self).__init__(message)
        self.errors = errors
        
    def __init__(self, message):
        super(RuntimeError, self).__init__(message)

# Represents a VM; listens to rabbitmq for incoming jobs and creates a RunInstance to deliver them to the VM
class Worker():
    def __init__(self, config):
        self.conf = config
        self.mntdir = None
        self.lv_conn = libvirt.open("qemu:///system")
        self.cursor, self.dbconn = self._db_conn(self.conf.get('General', 'dbname'), self.conf.get('General', 'dbuser'), self.conf.get('General' ,'dbpass'))
        self.vm_uuid = self._select_vm()
        self.victim_params = self._get_victim_params()
        self.outputdata = {}
        
    def _db_conn(self, db, user, password):
        host = 'localhost'
        conn_string = "host='{0}' dbname='{1}' user='{2}' password='{3}'".format(host, db, user, password)
        conn = psycopg2.connect(conn_string)
        conn.autocommit = True
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        logger.debug('DB connection started on {0} to db "{1}" with user "{2}"'.format(host, db, user))
        return cursor, conn
        
    def _select_vm(self):
        available = self._list_available_vms()
        logger.debug('Available VM IDs: {0}'.format(json.dumps(available)))
        if len(available) == 0:
            logger.error("No available VMs, cannot start worker")
            raise KeyError("No VMs available for use")
        else:
            try:
                uuid = self.lv_conn.lookupByID(available[0]).UUIDString()
                self.cursor.execute("""INSERT INTO "workerstate" (uuid, id, pid, position, params) VALUES (%s, %s, %s, %s, '{}')""", (uuid, available[0], os.getpid(), 'idle'))
                self.dbconn.commit()
                
                logger.info('Selected VM UUID {0} and registered worker in DB'.format(uuid))
                
                # make sure directory for mounting vm disk to exists and nothing is mounted to it
                mntdir = os.path.join(self.conf.get('General', 'mountdir'), '{0}'.format(uuid))
                logger.debug("Selected mount directory {0}".format(mntdir))
                if not os.path.isdir(mntdir):
                    logger.debug("Mount directory does not exist, creating...")
                    os.makedirs(mntdir)
                self.mntdir = mntdir
                # ensure mount dir is clean from previous run
                call(['guestunmount', self.mntdir])
                return uuid
            except Exception as e:
                logger.error("Fatal error during VM selection: {0}".format(e))
                self._db_cleanup(uuid)
                self._exit(1)
                
    def _exit(self, value=0):
        self.dbconn.close()
        logger.info("Closed connection to DB - cleanup complete, exiting now.")
        exit(value)
    
    def _db_cleanup(self, vm_uuid):
        self.dbconn.rollback()
        self.cursor.execute("""DELETE FROM "workerstate" WHERE uuid=%s""", (vm_uuid,))
        self.dbconn.commit()
        logger.info("Removed worker state entry from DB")
            
    def _list_unavailable_vms(self):
        self.cursor.execute("""SELECT uuid FROM "workerstate" """)
        records = self.cursor.fetchall()
        in_use = []
        for r in records:
            in_use.append(r["uuid"])
        logger.debug('In use VM IDs: {0}'.format(json.dumps(in_use)))
        return in_use
    
    def _list_available_vms(self):
        domains = self.lv_conn.listDomainsID()
        self.cursor.execute("""SELECT * FROM victims WHERE status = 'production'""")
        rows = self.cursor.fetchall()
        production_uuids = []
        for row in rows:
            production_uuids.append(row["uuid"])
        logger.debug("Production VM UUIDs: {0}".format(json.dumps(production_uuids)))
        available = []
        in_use = self._list_unavailable_vms()
        if domains:
            for dom in domains:
                uuid = self.lv_conn.lookupByID(dom).UUIDString()
                if uuid not in in_use and uuid in production_uuids:
                    available.append(dom)
        else:
            logger.error("No victims online")
        return available
    
    def _state_update(self, state, params=(False, None)):
        if not params[0]:
            self.cursor.execute("""UPDATE "workerstate" SET position = %s WHERE uuid=%s""", (state, self.vm_uuid))
            self.dbconn.commit()
            logger.debug("Worker state changed to '{0}'".format(state))
        else:
            uuid = ""
            if "uuid" in params[1]:
                uuid = params[1]["uuid"]
            pstring = json.dumps(params[1])
            self.cursor.execute("""UPDATE "workerstate" SET (position, params, job_uuid) = (%s, %s, %s) WHERE uuid=%s""", (state, pstring, uuid, self.vm_uuid))
            self.dbconn.commit()
            logger.debug("Worker state changed to '{0}' with details '{1}'".format(state, params))
            
    def _case_update(self, status, case_uuid):
        self.cursor.execute("""UPDATE "cases" SET status = %s WHERE uuid=%s""", (status, case_uuid))
        self.dbconn.commit()
        logger.info("Case status for case UUID {0} changed to '{1}'".format(case_uuid, status))
    
    def _get_victim_params(self):
        self.cursor.execute('SELECT * FROM victims WHERE uuid=%s LIMIT 1', (self.vm_uuid,))
        data = self.cursor.fetchall()
        params = data[0]
        params["last_reboot"] = arrow.get(params["last_reboot"]).format('YYYY-MM-DD HH:mm:ss.SSSZ')
        logger.debug(params)
        logger.debug("Got details for VM UUID {0}, IP is {1}, username is '{2}'".format(self.vm_uuid, params["ip"], params["username"]))
        return params

    # core sequence of actions to take for a received job
    def process(self, ch, method, properties, body):
        logger.info("Message received: {0}".format(body))
        dom = self.lv_conn.lookupByUUIDString(self.vm_uuid)
        domstruct = etree.fromstring(dom.XMLDesc())
        vncport = etree.XPath("/domain/devices/graphics")(domstruct)[0].get("port")
        vncconnect = {"address": "127.0.0.1", "port": vncport}
        
        state = "available"
        tryctr = 0
        params = json.loads(body)
        
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
                logger.error("VNC connection blocked, sleeping 20 seconds...")
                time.sleep(20)
                tryctr += 1
        
        self.outputdata["received job"] = params
        ch.basic_ack(delivery_tag = method.delivery_tag)
            
        self.victim_params["vnc"] = vncconnect
        
        try:
            cfg = self.conf
            suspect = RunInstance(
                self.cursor,
                self.dbconn,
                cfg,
                params["fname"],
                params["uuid"],
                params["submittime"],
                params["hashes"],
                self.victim_params,
                ttl=params["ttl"],
                interactive=params["interactive"],
                reboots=params["reboots"],
                banking=params["banking"],
                web=params["web"]
                )
            
            self._case_update('received', suspect.uuid)
            tformat = 'YYYY-MM-DD HH:mm:ss.SSSZ'
            
            updateparams = (self.vm_uuid,
                            suspect.victim_params["os"],
                            arrow.get(suspect.submittime).format(tformat),
                            arrow.get(suspect.starttime).format(tformat),
                            suspect.reboots,
                            suspect.interactive,
                            suspect.banking,
                            suspect.web,
                            suspect.ttl,
                            suspect.uuid)
            logger.debug(updateparams)
            self.cursor.execute("""UPDATE cases SET (vm_uuid, vm_os, submittime, starttime, reboots, interactive, banking, web, runtime)=""" +
                                """(%s, %s, %s, %s, %s, %s, %s, %s, %s) WHERE uuid=%s""", updateparams)
            self.dbconn.commit()
            
            self._state_update('initialising', (True, suspect._dump_dict()))
            self._case_update('initialising', suspect.uuid)
            
            imgshort = os.path.join(suspect.rootdir, 'www', self.conf.get('General', 'instancename'), 'public', 'images', 'cases', suspect.uuid[0:2])
            if not os.path.exists(imgshort):
                os.mkdir(imgshort)
            imgdir = os.path.join(imgshort, suspect.uuid)
            if not os.path.exists(imgdir):
                os.mkdir(imgdir)
            
            # revert to most recent snapshot
            logger.debug("Restoring VM snapshot")
            snapshot = dom.snapshotCurrent()
            dom.revertToSnapshot(snapshot)
            
            self._state_update('restored', (False,None))
            self._case_update('restored', suspect.uuid)
            logger.debug("Resuming VM")
            dom.resume()
            
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
            logger.info("Issuing command set to victim, worker allowing {0} seconds runtime".format(suspect.ttl))
            self._state_update('running', (False,None))
            self._case_update('running', suspect.uuid)
            
            begin = arrow.utcnow()
            end = begin.shift(seconds=+suspect.ttl)
            suspect.do_run(dom, self.lv_conn)
            
            # if minimum runtime not yet elapsed, let malware run until it has
            while arrow.utcnow() < end:
                time.sleep(5)
            
            logger.info("Runtime limit reached, starting data collection")
            
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
            suspect.screenshot(dom, self.lv_conn)
            logger.debug("Creating screenshot at {0}".format(imgpath))
            
            # pause the vm before mounting filesystem
            dom.suspend()
            logger.debug("VM suspended, starting data collection")
            self._state_update('collecting', (False,None))
            self._case_update('collecting', suspect.uuid)
            suspect.endtime = arrow.utcnow().format(tformat)
            self.cursor.execute("""UPDATE cases SET endtime=%s WHERE uuid=%s""", (suspect.endtime, suspect.uuid))
            self._state_update('collecting', (False, None))
            # gather data
            logger.debug("Mounting virtual disk {0} to mountpoint {1}".format(self.victim_params["diskfile"], self.mntdir))
            # http://manpages.ubuntu.com/manpages/wily/man1/guestfs-faq.1.html
            # qemu user or group must have permissions for the image file for this to work
            call(['guestmount', '--ro', '-a', self.victim_params["diskfile"], '-m', '/dev/sda2', self.mntdir])
            
            # write output to file/database
            suspect.construct_record(self.mntdir, self.victim_params)
            logger.debug("Output written")
            self._case_update('complete', suspect.uuid)
             
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            logger.error("Exception {0} {1} in {2}, line {3} while processing job, aborting".format(ex_type, ex, fname, lineno))
            self._case_update('failed', suspect.uuid)
        finally:
            self._state_update('cleanup', (False,None))
            # ensure capture thread exits
            suspect.stop_capture = True
            try:
                socket.create_connection((suspect.victim_params["ip"], 389), timeout=1)
            except:
                pass
            logger.removeHandler(suspect.runlog)
            # ensure drive is unmounted before next run
            call(['guestunmount', self.mntdir])
            # ensure vm suspended
            self.lv_conn.lookupByUUIDString(self.vm_uuid).suspend()
            self.cursor.execute("""UPDATE victims SET (runcounter)=(runcounter + 1) WHERE uuid=%s""", (self.victim_params["uuid"],))
            self.dbconn.commit()
            self._state_update('idle', params=(True, dict()))
    
    def work(self, host='localhost', chname='suspects'):
        conn = pika.BlockingConnection(pika.ConnectionParameters(host))
        channel = conn.channel()
        channel.queue_declare(queue=chname, durable=True)
        channel.basic_consume(self.process, chname)
        logger.debug("Starting connection to rabbitmq channel '{0}' on {1}".format(chname, host))
        try:
            logger.info("Startup complete, ready to receive jobs")
            channel.start_consuming()
        except KeyboardInterrupt:
            logger.debug("Keyboard interrupt received")
            channel.stop_consuming()
        finally:
            logger.info("Worker shutdown triggered")
            self.lv_conn.lookupByUUIDString(self.vm_uuid).suspend()
            logger.info("Paused worker VM")
            conn.close()
            logger.debug("Closed connection to rabbitmq")
            # ensure no transactions blocking the removal of worker from DB
            self._db_cleanup(self.vm_uuid)
            self._exit()
            

# Manages connection to VM and issuing of commands
class RunInstance():
    def __init__(   self,
                    cursor,
                    dbconn,
                    conf,
                    fname,
                    uuid,
                    submittime,
                    hashes,
                    victim_params,
                    ttl=180, 
                    interactive=False, 
                    reboots=0,
                    web=True,
                    banking=False,
                    filespath = "suspects",
                    outdir = "output"
                    ):
        
        self.conf = conf
        self.rootdir = os.path.join(conf.get('General', 'basedir'), self.conf.get('General', 'instancename'))
        self.uuid = uuid
        self.starttime = arrow.utcnow().timestamp
        self.endtime = None
        self.submittime = submittime
        self.hashes = hashes
        self.ttl = ttl
        self.interactive = interactive
        self.reboots = reboots
        self.banking = banking
        self.web = web
        self.filespath = os.path.join(self.rootdir, filespath)
        self.fname = self._suspect_exists(fname)
        self.victim_params = victim_params
        self.runcmds = []
        self.rundir = self._make_outputdir(outdir)
        self.imgdir = self._make_imgdir()
        self.runlog = self._register_logger()
        self.pcap_file = os.path.join(self.rundir, "capture.pcap")
        self.stop_capture = False
        self.imgsequence = 0
        self.cursor = cursor
        self.dbconn = dbconn
        
    @property
    def rawfile(self):
        return os.path.join(self.filespath, self.hashes["sha256"][0:2], self.hashes["sha256"])
    
    @property
    def downloadfile(self):
        return os.path.join(self.filespath, 'downloads', self.fname)
    
    @property
    def banking(self):
        return int(self._banking)
    
    @banking.setter
    def banking(self, value):
        self._banking = bool(value)
    
    @property
    def web(self):
        return int(self._web)
    
    @banking.setter
    def web(self, value):
        self._web = bool(value)
        
    @property
    def interactive(self):
        return int(self._interactive)
    
    @interactive.setter
    def interactive(self, value):
        self._interactive = bool(value)
        
    @property
    def stop_capture(self):
        return bool(self._stop_capture)

    @stop_capture.setter
    def stop_capture(self, value):
        self._stop_capture = bool(value)
        
    def _dump_dict(self):
        tformat = 'YYYY-MM-DD HH:mm:ss.SSSZ'
        selfdict =  {
            "rootdir": self.rootdir,
            "uuid": self.uuid,
            "starttime": self.starttime,
            "endtime": self.endtime,
            "submittime": self.submittime,
            "hashes": self.hashes,
            "ttl": self.ttl,
            "interactive": self.interactive,
            "reboots": self.reboots,
            "banking": self.banking,
            "web": self.web,
            "filespath": self.filespath,
            "fname": self.fname,
            "victim_params": self.victim_params,
            "runcmds": self.runcmds,
            "rundir": self.rundir,
            "pcap_file": self.pcap_file,
            "stop_capture": self.stop_capture
        }
        logger.debug(selfdict)
        return selfdict
        
    def _make_outputdir(self, outdir):
        short = self.hashes["sha256"][0:2]
        bdir = os.path.join(self.rootdir, outdir, short)
        if not os.path.exists(bdir):
            os.mkdir(bdir)
        fdir = os.path.join(bdir, self.hashes["sha256"])
        if not os.path.exists(fdir):
            os.mkdir(fdir)
        # rundir should not exist before the run - if it does, UUID is broken somehow!
        rundir = os.path.join(fdir, self.uuid)
        os.mkdir(rundir)
        logger.debug("Created run instance directory {0}".format(rundir))
        return rundir
    
    def _make_imgdir(self):
        imgshort = os.path.join(self.rootdir, 'www', self.conf.get('General', 'instancename'), 'public', 'images', 'cases', self.uuid[0:2])
        if not os.path.exists(imgshort):
            os.mkdir(imgshort)
            logger.debug("Made images base dir {0}".format(imgshort))
        imgdir = os.path.join(imgshort, self.uuid)
        if not os.path.exists(imgdir):
            os.mkdir(imgdir)
            logger.debug("Made images final dir {0}".format(imgdir))
        return imgdir
    
    def _register_logger(self):
        formatter = logging.Formatter(fmt='[%(asctime)s] %(levelname)s\t%(message)s', datefmt='%Y%m%d %H:%M:%S')
        runlog = logging.FileHandler(os.path.join(self.rundir, 'run.log'))
        runlog.setLevel(getattr(logging, self.conf.get('General', 'runloglevel')))
        runlog.setFormatter(formatter)
        logger.addHandler(runlog)
        return runlog

    def _suspect_exists(self, fname):
        open(self.rawfile).close()
        logger.debug("Confirmed file '{0}' exists with sha256 '{1}'".format(fname, self.hashes["sha256"]))
        return fname
        
    # make a screenshot
    # https://www.linuxvoice.com/issues/003/LV3libvirt.pdf
    def screenshot(self, dom, lv_conn):
        imgpath = os.path.join(self.imgdir, "{0}.png".format(self.imgsequence))
        thumbpath = os.path.join(self.imgdir, "{0}-thumb.png".format(self.imgsequence))
        
        s = lv_conn.newStream()
        # cause libvirt to take the screenshot
        dom.screenshot(s, 0)
        # copy the data into a buffer
        buf = StringIO()
        s.recvAll(self._sc_writer, buf)
        s.finish()
        # write the buffer to file
        buf.seek(0)
        i = Image.open(buf)
        i.save(imgpath)
        i.thumbnail((400, 400))
        i.save(thumbpath)
        logger.debug("Took screenshot {0}".format(imgpath))
        self.imgsequence += 1
    
    def _sc_writer(self, stream, data, b):
        b.write(data)
                    
    def case_update(self, status):
        self.cursor.execute("""UPDATE "cases" SET status = %s WHERE uuid=%s""", (status, self.uuid))
        self.dbconn.commit()
    
    def write_capture(self, pkt):
        scapy.wrpcap(self.pcap_file, pkt, append=True)
        if self.stop_capture:
            logger.info("Wrote pcap to file {0}".format(self.pcap_file))
            summary_file = os.path.join(self.rundir, 'pcap_summary.json')
            c = pcap_parser.conversations(self.pcap_file)
            sql = """INSERT INTO pcap_summary (uuid, src_ip, src_port, dest_ip, dest_port, protocol) VALUES %s"""
            values = []
            for cevent in c:
                row = (self.uuid, cevent["src"], cevent["srcport"], cevent["dst"], cevent["dstport"], cevent["protocol"])
                values.append(row)
            psycopg2.extras.execute_values(self.cursor, sql, values)
            with open(summary_file, 'w') as f:
                f.write(json.dumps(c))
            logger.debug("Stop capture issued, raising exception to terminate thread")
            raise StopCaptureException("Stop Capture flag set")
    
    def capture(self):
        fl = "host {0} and not (host {1} and dst port 8080)".format(self.victim_params["ip"], self.conf.get("General", "gateway_ip"))
        logger.debug("Packet capture starting with filter '{0}'".format(fl))
        scapy.sniff(iface="vnet0", filter=fl, prn=self.write_capture)
            
    def events_to_store(self, searchfile, startdate, enddate):
        with open(searchfile) as f:
            events = {}
            evctr = 0
            for line in f:
                d = json.loads(line)
                t = arrow.get(d["timestamp"])
                # ensure only event types we can handle safely get looked at
                if d["event_type"] in ["tls", "http", "dns", "alert"]:
                    if ((d["src_ip"] == self.victim_params["ip"] or d["dest_ip"] == self.victim_params["ip"]) and
                    d["src_ip"] != self.conf.get("General", "gateway_ip") and d["dest_ip"] != self.conf.get("General", "gateway_ip") and t >= startdate and t <= enddate):
                        if d["event_type"] != "alert" or (d["event_type"] == "alert" and d["alert"]["category"] != "Generic Protocol Command Decode"):
                            if d["event_type"] not in events:
                                events[d["event_type"]] = [d]
                            else:
                                events[d["event_type"]].append(d)
                            evctr += 1
            logger.debug("Identified {0} events to include from {1}".format(evctr, searchfile))
                        
            return events
        
    def behaviour(self, dom, lv_conn):
        cstr = "{0}::{1}".format(self.victim_params["vnc"]["address"], self.victim_params["vnc"]["port"])
        vncconn = pyvnc.Connector(cstr, self.victim_params["password"], (self.victim_params["display_x"], self.victim_params["display_y"]))
        logger.debug("Initialised VNC connection")
        t = arrow.now()
        wintime = t.strftime('%H:%M:%S')
        windate = t.strftime('%d/%m/%Y')
        vncconn.prepVM(windate, wintime)
        logger.debug("Victim date/time set to {0} {1}".format(windate, wintime))
        
        ext = self.fname.split(".")[-1]
        
        macrotypes = ["doc", "xls", "ppt", "dot", "xlm", "docm", "dotm", "docb", "xlsm", "xltm", "pptm"]
        
        vncconn.downloadAndRun(self.fname)
        if ext in macrotypes:
            vncconn.enable_macros(self.victim_params["ms_office_type"])
        
        logger.info("VM prepped for suspect execution, starting behaviour sequence")
        if self.interactive:
            logger.info("Passing control to user")
        else:
            vncconn.basic()
            logger.info("Basic behaviour complete")
            self.screenshot(dom, lv_conn)
            if self.banking:
                vncconn.bank()
                self.screenshot(dom, lv_conn)
                logger.info("Banking happened")
            if self.reboots:
                vncconn.restart()
                logger.info("System rebooted")
            if self.web:
                vncconn.web()
                self.screenshot(dom, lv_conn)
                logger.info("Web activity happened")
            if self.reboots > 1:
                vncconn.restart()
                logger.info("System rebooted")
        logger.info("Behaviour sequence complete")
        vncconn.disconnect()
        logger.debug("VNC disconnect issued")
        
    def do_run(self, dom, lv_conn):
        logger.debug("Started run sequence")
        # prep the file for run
        shutil.copy(self.rawfile, self.downloadfile)
        logger.debug("File copied ready for download")
        try:
            self.behaviour(dom, lv_conn)
        # except block for debugging purposes - clean this up for production
        except Exception as e:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            raise RuntimeError("Exception {0} {1} in {2}, line {3} while processing job, run not completed. Aborting.".format(ex_type, ex, fname, lineno))
        finally:
            #ssh.close()
            os.remove(self.downloadfile)
            logger.debug("Removed download file")
    
    def construct_record(self, guestmount_path, victim_params):
        dtstart = arrow.get(self.starttime)
        dtend = arrow.get(self.endtime)
        try:
            # get sysmon events
            logger.debug("Gathering sysmon output between {0} and {1}".format(dtstart.format('YYYY-MM-DD HH:mm:ss'), dtend.format('YYYY-MM-DD HH:mm:ss')))
            sysmon_path = os.path.join(guestmount_path, "Windows", "System32", "winevt", "Logs", "Microsoft-Windows-Sysmon%4Operational.evtx")
            sysmon_file = os.path.join(self.rundir, "sysmon.xml")
            evctr = 0
            # write sysmon events
            matching_evtx = evtx_dates.matching_records(sysmon_path, dtstart, dtend)
            evts = []
            with open(sysmon_file, 'w') as f:
                f.write('<Events>\n')
                for e in matching_evtx:
                    f.write(etree.tostring(e, pretty_print=True))
                    evts.append(e)
                    evctr += 1
                f.write('</Events>')
                logger.info("Wrote {0} sysmon events to {1}".format(evctr, sysmon_file))
                
            db_calls.insert_sysmon(evts, self.uuid, self.cursor)
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            logger.error("Exception {0} {1} in {2}, line {3} while processing sysmon output".format(ex_type, ex, fname, lineno))
           
        try: 
            # record runinstance properties
            properties_file = os.path.join(self.rundir, "properties.json")
            with open(properties_file, 'w') as p:
                writeprops = dict(self._dump_dict())
                if "password" in writeprops:
                    del writeprops["victim_params"]["password"]
                writeprops["status"] = "completed"
                p.write(json.dumps(writeprops, indent=4, separators=(",", ": ")))
                logger.info("Wrote properties file {0}".format(properties_file))
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            msg = "Exception {0} {1} in {2}, line {3} while processing job, properties file not written".format(ex_type, ex, fname, lineno)
            logger.error(msg)
            properties_file = os.path.join(self.rundir, "properties.json")
            with open(properties_file, 'w') as p:
                writeprops = {"status": "failed",
                              "reason": msg}
                p.write(json.dumps(writeprops, indent=4, separators=(",", ": ")))
                   
        try:
            # record suricata events
            eventlog = os.path.join(self.rundir, "eve.json")
            with open(eventlog, 'w') as e:
                events = {}
                if os.path.exists(self.conf.get('General', 'suricata_log')):
                    events = self.events_to_store(self.conf.get('General', 'suricata_log'), dtstart, dtend)
                else:
                    logger.debug("Suricata eve.json file not present")
                e.write(json.dumps(events))
                qty = {}
                for evtype in events:
                    qty[evtype] = len(events[evtype])
                    if evtype == "dns":
                        db_calls.insert_dns(events[evtype], self.uuid, self.cursor)
                    if evtype == "http":
                        db_calls.insert_http(events[evtype], self.uuid, self.cursor)
                    if evtype == "alert":
                        db_calls.insert_alert(events[evtype], self.uuid, self.cursor)
                    if evtype == "tls":
                        db_calls.insert_tls(events[evtype], self.uuid, self.cursor)
                logger.info("Wrote events to {0}: {1}".format(eventlog, str(qty)))
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            logger.error("Exception {0} {1} in {2}, line {3} while processing job, Suricata data not written".format(ex_type, ex, fname, lineno))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--loglevel', dest='loglevel')
    parser.add_argument('--logdir', dest='logdir')
    parser.add_argument('--runloglevel', dest='runloglevel')
    parser.add_argument('-n', '--instancename', dest='instancename')
    parser.add_argument('-m', '--mountdir', dest='mountdir')
    parser.add_argument('config', default='runmanager.conf', type=argparse.FileType())
    args = parser.parse_args()
    
    conf = ConfigParser.ConfigParser()
    conf.readfp(args.config)
    if args.loglevel:
        conf.set('General', 'loglevel', args.loglevel)
    if args.logdir:
        conf.set('General', 'logdir', args.logdir)
    if args.instancename:
        conf.set('General', 'instancename', args.instancename)
    if args.mountdir:
        conf.set('General', 'mountdir', args.mountdir)
    
    num_level = getattr(logging, conf.get('General', 'loglevel').upper(), None)
    if not isinstance(num_level, int):
        raise ValueError('Invalid log level "{0}"'.format(num_level))
    
    run_num_level = getattr(logging, conf.get('General', 'runloglevel').upper(), None)
    if not isinstance(num_level, int):
        raise ValueError('Invalid log level "{0}"'.format(run_num_level))
    
    
    
    
    fmt = '[%(asctime)s] %(levelname)s\t%(message)s'
    dfmt ='%Y%m%d %H:%M:%S'
    formatter = logging.Formatter(fmt=fmt, datefmt=dfmt)
    
    logging.basicConfig(level=logging.CRITICAL, format=fmt, datefmt=dfmt)
    
    #ch = logging.StreamHandler()
    #ch.setLevel(num_level)
    #ch.setFormatter(formatter)
    #logger.addHandler(ch)
    #logger.setLevel(num_level)
    
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    logging.getLogger("pyvnc").setLevel(logging.DEBUG)
    logging.getLogger("db_calls").setLevel(logging.DEBUG)
    
    if not os.access(conf.get('General', 'mountdir'), os.W_OK):
        logger.error("Mount directory {0} not writeable!".format(conf.get('General', 'mountdir')))
        exit(1)                 
    
    logger.debug('Starting worker...')
    
    try:        
        w = Worker(conf)
    except KeyError:
        logger.error("Invalid configuration supplied!")
        exit(1)
    
    logfile = os.path.join(conf.get('General', 'logdir'), str(w.vm_uuid)) + '.log'
    
    fh = logging.FileHandler(logfile)
    fh.setLevel(num_level)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    logger.info('Worker started')
    
    w.work()
    

if __name__ == "__main__":
    main()
