#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import logging, os, configparser, libvirt, json, arrow, pyvnc, shutil, time, victimfiles, glob, websockify, multiprocessing, signal
import tempfile, evtx_dates, db_calls, psycopg2, psycopg2.extras, sys, pcap_parser, yarahandler, magic, case_postprocess
import scapy.all as scapy
from lxml import etree
from io import StringIO, BytesIO
from PIL import Image

logger = logging.getLogger("antfarm.worker")

# Manages connection to VM and issuing of commands
class RunInstance():
    def __init__(   self,
                    cursor,
                    dbconn,
                    domuuid,
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
                    collect_registries=False,
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
        self.collect_registries = collect_registries
        self.web = web
        self.filespath = os.path.join(self.rootdir, filespath)
        self.fname = self._suspect_exists(fname)
        self.victim_params = victim_params
        self.runcmds = []
        self.rundir = self._make_outputdir(outdir)
        self.imgdir = self._make_imgdir()
        self.runlog = self._register_logger()
        self.pcap_file = os.path.join(self.rundir, "capture.pcap")
        #self.stop_capture = False
        self.imgsequence = 0
        self.cursor = cursor
        self.dbconn = dbconn
        self.domuuid = domuuid
        self.yara_test()
        self.vf = None
        self.websockserver = None

    def __del__(self):
        self._unregister_logger()
        self.remove_vnc()
        
    @property
    def rawfile(self):
        return os.path.join(self.filespath, self.hashes["sha256"][0:2], self.hashes["sha256"])
    
    @property
    def downloadfile(self):
        return os.path.join(self.filespath, 'downloads', str(self.domuuid), self.fname)
    
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
            "pcap_file": self.pcap_file
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
        log_modules = [__name__, "pyvnc", "vmworker", "runinstance", "db_calls", "victimfiles", "yarahandler"]
        for module in log_modules:
            logging.getLogger(module).setLevel(RUN_NUM_LEVEL)
        logger.addHandler(runlog)
        return runlog

    def _unregister_logger(self):
        logger.removeHandler(self.runlog)

    def _suspect_exists(self, fname):
        open(self.rawfile).close()
        logger.debug("Confirmed file '{0}' exists with sha256 '{1}'".format(fname, self.hashes["sha256"]))
        return fname
    
    def yara_test(self):
        matches = yarahandler.testyara(self.conf, self.rawfile)
        if matches:
            logger.info("Found yara matches: {}".format(matches))
            db_calls.yara_detection(matches, self.hashes["sha256"], self.cursor)
        else:
            logger.info("No yara matches found")
        
    # make a screenshot
    # https://www.linuxvoice.com/issues/003/LV3libvirt.pdf
    def screenshot(self, dom, lv_conn):
        imgpath = os.path.join(self.imgdir, "{0}.png".format(self.imgsequence))
        thumbpath = os.path.join(self.imgdir, "{0}-thumb.png".format(self.imgsequence))
        i = get_screen_image(dom, lv_conn)
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
        
    def get_pcap(self):
        try:
            folder = "/usr/local/unsafehex/{}/pcaps".format(self.conf.get("General", "instancename"))
            def getmtime(name):
                path = os.path.join(folder, name)
                return os.path.getmtime(path)
            pcaps = sorted(os.listdir(folder), key=getmtime, reverse=True)
            
            to_read = []
            
            start = arrow.get(self.starttime)
            end = arrow.get(self.endtime)
            
            hours_list = arrow.Arrow.range("hour", start, end)

            for pcap_file in pcaps:
                pf = os.path.join(folder, pcap_file)
                if arrow.get(os.path.getmtime(pf)) > start:
                    to_read.append(pf)

            logger.debug("Reading from pcaps: {}".format(to_read))
            
            #for hour in hours_list:
            #    pcap_file = "{}.pcap".format(hour.format("HH"))
            #    to_read.append(pcap_file)
                                    
            fl = "host {0} and not (host {1} and port 28080)".format(self.victim_params["ip"], self.conf.get("General", "gateway_ip"))
            logger.debug("Reading pcapring with filter {}".format(fl))
            logger.debug("Time parameters: {} :: {}".format(start, end))
            written = 0
            for pcap in to_read:
                logger.debug("Reading {}".format(pcap))
                packets = scapy.sniff(offline=pcap, filter=fl)
                for packet in packets:
                    ptime = arrow.get(packet.time)
                    if ptime >= start and ptime <= end:
                        scapy.wrpcap(self.pcap_file, packet, append=True)
                        written += 1
                    
            logger.info("Wrote {} packets to file {}".format(written, self.pcap_file))
            
            conversations = pcap_parser.conversations(self.pcap_file)
            db_calls.insert_pcap_streams(conversations, self.uuid, self.cursor)
        
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            logger.error("Exception {0} {1} in {2}, line {3} while processing pcap".format(ex_type, ex, fname, lineno))
        
    def events_to_store(self, searchfiles, startdate, enddate):
        events = {}
        logger.debug("Searching suricata log files: {}".format(searchfiles))
        for searchfile in searchfiles:
            evctr = 0
            if os.path.exists(searchfile):
                with open(searchfile) as f:
                    for line in f:
                        d = json.loads(line.rstrip(' \t\r\n\0').lstrip(' \t\r\n\0'))
                        t = arrow.get(d["timestamp"])
                        # ensure only event types we can handle safely get looked at
                        if d["event_type"] in ["tls", "http", "dns", "alert"]:
                            # include everything from selected host
                            if ((d["src_ip"] == self.victim_params["ip"] or d["dest_ip"] == self.victim_params["ip"]) and
                                # that falls within the run time
                                (t >= startdate and t <= enddate) and not
                                # except where the target is the API service
                                (d["dest_ip"] == self.conf.get("General", "gateway_ip") and d["dest_port"] == 28080)):
                                if d["event_type"] != "alert" or (d["event_type"] == "alert" and d["alert"]["category"] != "Generic Protocol Command Decode"):
                                    if d["event_type"] not in events:
                                        events[d["event_type"]] = [d]
                                    else:
                                        events[d["event_type"]].append(d)
                                    evctr += 1
            logger.info("Identified {0} events to include from {1}".format(evctr, searchfile))
                        
        return events
    
    def behaviour(self, dom, lv_conn):
        try: 
            cstr = "{0}::{1}".format(self.victim_params["vnc"]["address"], self.victim_params["vnc"]["port"])
            vncconn = pyvnc.Connector(cstr, self.victim_params["password"], (self.victim_params["display_x"], self.victim_params["display_y"]))
            logger.debug("Initialised VNC connection")

            click_after = arrow.now().format("YYYY-MM-DD HH:mm:ss")
            for i in range(0,5):
                vncconn.run_sample(self.victim_params["malware_pos_x"], self.victim_params["malware_pos_y"])
                time.sleep(6)
                if self.sample_has_run(click_after):
                    self.screenshot(dom, lv_conn)
                    break
                logger.error("Didn't see a process creation. That's odd...")
                        
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

    def sample_has_run(self, click_after):
        self.cursor.execute("""SELECT * FROM sysmon_evts WHERE uuid=%s AND eventid=1 AND timestamp > %s""", (self.uuid, click_after))
        rows = self.cursor.fetchall()
        # check if any processes have been started from Explorer
        for row in rows:
            if row["eventid"] == 1:
                if row["eventdata"]["ParentImage"] == "C:\\Windows\\explorer.exe":
                    return True
        return False
        
    def do_run(self, dom, lv_conn):
        logger.info("Started run sequence")
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
            
            logger.info("Suspect was delivered, starting behaviour sequence")
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
            
    def targeted_files_list(self):
        targeted_files = []
        targeted_files.extend(db_calls.timestomped_files(self.uuid, self.cursor))
        return targeted_files
    
    def construct_record(self, victim_params):        
        dtstart = arrow.get(self.starttime)
        dtend = arrow.get(self.endtime)
        try:
            logger.info("Obtaining new files from guest filesystem")
            self.vf = victimfiles.VictimFiles(self.conf, self.victim_params["diskfile"], '/dev/sda2')
            filesdict = self.vf.download_new_files(dtstart, self.rundir)
            registriesdict = self.vf.download_modified_registries(dtstart, self.rundir, self.victim_params["username"], self.collect_registries)
            targetedfilesdict = self.vf.download_specific_files(self.targeted_files_list(), self.rundir)
            compileddict = {**filesdict, **registriesdict, **targetedfilesdict}
            db_calls.insert_files(compileddict, self.uuid, self.cursor)
            
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            logger.error("Exception {0} {1} in {2}, line {3} while processing filesystem output".format(ex_type, ex, fname, lineno))
        finally:
            try:
                del(vf)
            except Exception:
                pass
                   
        try:
            # record suricata events
            eventlog = os.path.join(self.rundir, "eve.json")
            with open(eventlog, 'w') as e:
                files = self._suricata_logfiles
                events = self.events_to_store(files, dtstart, dtend)
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

        try: 
            self.get_pcap()
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            logger.error("Exception {0} {1} in {2}, line {3} while processing job, pcap processing failed".format(ex_type, ex, fname, lineno))

        try:
            pp = case_postprocess.Postprocessor(self.uuid, self.cursor)
            pp.update_events()
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            logger.error("Exception {0} {1} in {2}, line {3} while processing job, case postprocessing failed".format(ex_type, ex, fname, lineno))
            
    
    @property
    def _suricata_logfiles(self):
        evefiles = sorted(glob.glob("/var/log/suricata/eve-*.json"), key=os.path.getmtime, reverse=True)
        
        to_read = []
        
        start = arrow.get(self.starttime)
        end = arrow.get(self.endtime)
        
        for evefile in evefiles:
            evefiletime = arrow.get(evefile.split("-")[1].split(".")[0], "YYYYMMDDHHmmss")
        
            if evefiletime < start:
                to_read.insert(0, evefile)
                break
            else:
                to_read.insert(0, evefile)
            
        return to_read
    
    def present_vnc(self):
        lport = 6800 + (int(self.victim_params["vnc"]["port"]) - 5900)
        dport = self.victim_params["vnc"]["port"]
        self.vncthread = multiprocessing.Process(target=vncsocket, args=("127.0.0.1", lport, dport))
        self.vncthread.start()
        logger.info("Started websockify server on {} -> {}".format(lport, dport))
    
    def remove_vnc(self):
        if self.vncthread and isinstance(self.vncthread, multiprocessing.Process):
            self.vncthread.terminate()
            logger.info("Stopped websockify server")

def vncsocket(host, lport, dport):
    logger.debug("Spinning up websocket process...")
    server = websockify.WebSocketProxy(**{"target_host": host, "target_port": dport, "listen_port": lport})
    server.start_server()
            
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
