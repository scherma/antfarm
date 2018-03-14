#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import logging, os, configparser, libvirt, json, arrow, pyvnc, shutil, guestfs, time, victimfiles
import tempfile, evtx_dates, db_calls, psycopg2, psycopg2.extras, sys, pcap_parser
import scapy.all as scapy
from lxml import etree
from io import StringIO, BytesIO
from PIL import Image

logger = logging.getLogger(__name__)

# Manages connection to VM and issuing of commands
class RunInstance():
    def __init__(   self,
                    cursor,
                    dbconn,
                    domid,
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
        self.domid = domid
        
    @property
    def rawfile(self):
        return os.path.join(self.filespath, self.hashes["sha256"][0:2], self.hashes["sha256"])
    
    @property
    def downloadfile(self):
        return os.path.join(self.filespath, 'downloads', str(self.domid), self.fname)
    
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
        if not os.path.exists(rundir):
            os.mkdir(rundir)
            fscopy = os.path.join(rundir, 'filesystem')
            os.mkdir(fscopy)
        logger.debug("Created run instance directory {0}".format(rundir))
        return rundir
    
    def _make_imgdir(self):
        imgshort = os.path.join(self.rootdir, 'www', 'public', 'images', 'cases', self.uuid[0:2])
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
        RUN_NUM_LEVEL = getattr(logging, self.conf.get('General', 'runloglevel'))
        runlog.setLevel(RUN_NUM_LEVEL)
        runlog.setFormatter(formatter)
        log_modules = [__name__, "pyvnc", "vmworker", "runinstance", "db_calls", "victimfiles"]
        for module in log_modules:
            logging.getLogger(module).setLevel(RUN_NUM_LEVEL)
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
        i = get_screen_image(dom, lv_conn)
        #s = lv_conn.newStream()
        # cause libvirt to take the screenshot
        #dom.screenshot(s, 0)
        # copy the data into a buffer        
        #if sys.version_info[0] == 2 and sys.version_info[1] == 7:
        #    buf = StringIO()
        #    s.recvAll(self._sc_writer, buf)
        #elif sys.version_info[0] == 3 and sys.version_info[1] >= 5:
        #    buf = BytesIO()
        #    s.recvAll(self._sc_writer, buf)
        #s.finish()
        # write the buffer to file
        #buf.seek(0)
        #i = Image.open(buf)
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
        fl = "host {0} and not (host {1} and port 28080)".format(self.victim_params["ip"], self.conf.get("General", "gateway_ip"))
        logger.debug("Packet capture starting with filter '{0}'".format(fl))
        scapy.sniff(iface="vnet0", filter=fl, prn=self.write_capture)
            
    def events_to_store(self, searchfile, startdate, enddate):
        with open(searchfile) as f:
            events = {}
            evctr = 0
            for line in f:
                d = json.loads(line.rstrip(' \t\r\n\0').lstrip(' \t\r\n\0'))
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
        # give 15 seconds for execution to take place before starting behaviour
        time.sleep(15)
        try: 
            cstr = "{0}::{1}".format(self.victim_params["vnc"]["address"], self.victim_params["vnc"]["port"])
            vncconn = pyvnc.Connector(cstr, self.victim_params["password"], (self.victim_params["display_x"], self.victim_params["display_y"]))
            logger.debug("Initialised VNC connection")
            
            vncconn.run_sample(self.victim_params["malware_pos_x"], self.victim_params["malware_pos_y"])
            
            ext = self.fname.split(".")[-1]
            
            macrotypes = ["doc", "xls", "ppt", "dot", "xlm", "docm", "dotm", "docb", "xlsm", "xltm", "pptm"]
            
            self.screenshot(dom, lv_conn)
            if ext in macrotypes:
                vncconn.enable_macros(self.victim_params["ms_office_type"])
                vncconn.enable_dde()
                self.screenshot(dom, lv_conn)
                vncconn.client.pause(10)
                vncconn.close_window()
            
            #logger.info("VM prepped for suspect execution, starting behaviour sequence")
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
        
        except Exception as e:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            raise RuntimeError("Exception {0} {1} in {2}, line {3} while processing job, run not completed. Aborting.".format(ex_type, ex, fname, lineno))
        
    def do_run(self, dom, lv_conn):
        logger.debug("Started run sequence")
        # prep the file for run
        shutil.copy(self.rawfile, self.downloadfile)
        logger.debug("File copied ready for download")
        try:
            dom.resume()
            logger.debug("Resumed VM in preparation for run")
            case_obtained = False
            while not case_obtained:
                self.cursor.execute("""SELECT status FROM cases WHERE uuid=%s""", (self.uuid,))
                rows = self.cursor.fetchall()
                if rows and rows[0]["status"] == "obtained":
                    break
                else:
                    time.sleep(5)
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
    
    def construct_record(self, victim_params):        
        dtstart = arrow.get(self.starttime)
        dtend = arrow.get(self.endtime)
        try:
            logger.info("Obtaining new files from guest filesystem")
            vf = victimfiles.VictimFiles(self.victim_params["diskfile"], '/dev/sda2')
            fsroot = os.path.join(self.rundir, 'filesystem')
            vf.download_new_files(dtstart, fsroot)
            vf.download_modified_registries(dtstart, fsroot, self.victim_params["username"])
            
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            logger.error("Exception {0} {1} in {2}, line {3} while processing filesystem output".format(ex_type, ex, fname, lineno))
                   
        try:
            # record suricata events
            eventlog = os.path.join(self.rundir, "eve.json")
            with open(eventlog, 'w') as e:
                events = {}
                if os.path.exists(self.conf.get('General', 'suricata_log')):
                    events = self.events_to_store(self.conf.get('General', 'suricata_log'), dtstart, dtend)
                else:
                    logger.debug("Suricata eve.json file not present")
                #e.write(json.dumps(events))
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
            
def get_screen_image(dom, lv_conn):
    s = lv_conn.newStream()
    # cause libvirt to take the screenshot
    dom.screenshot(s, 0)
    # copy the data into a buffer        
    buf = BytesIO()
    s.recvAll(sc_writer, buf)
    s.finish()
    # write the buffer to file
    buf.seek(0)
    i = Image.open(buf)
    
    return i

def sc_writer(stream, data, b):
    b.write(data)
            
class StopCaptureException(RuntimeError):
    def __init__(self, message, errors):
        super(RuntimeError, self).__init__(message)
        self.errors = errors
        
    def __init__(self, message):
        super(RuntimeError, self).__init__(message)
