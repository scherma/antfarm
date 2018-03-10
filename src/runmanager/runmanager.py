#!/usr/bin/env python2
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import libvirt, psycopg2, psycopg2.extras, configparser, logging,os, sys, vmworker, threading, argparse, json, time

logger = logging.getLogger(__name__)

fmt = '[%(asctime)s] %(levelname)s\t%(message)s'
dfmt ='%Y%m%d %H:%M:%S'
formatter = logging.Formatter(fmt=fmt, datefmt=dfmt)

NUM_LEVEL = 3
RUN_NUM_LEVEL = 3


class Broker():
    def __init__(self, config):
        self.conf = config
        self.lv_conn = libvirt.open("qemu:///system")
        self.cursor, self.dbconn = self._db_conn(self.conf.get('General', 'dbname'), self.conf.get('General', 'dbuser'), self.conf.get('General' ,'dbpass'))
        self._wipe_workerstate()
        self._register_workers()
        
    def _db_conn(self, db, user, password):
        host = 'localhost'
        conn_string = "host='{0}' dbname='{1}' user='{2}' password='{3}'".format(host, db, user, password)
        conn = psycopg2.connect(conn_string)
        conn.autocommit = True
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        logger.debug('DB connection started on {0} to db "{1}" with user "{2}"'.format(host, db, user))
        return cursor, conn
        
    def _register_workers(self):
        for uuid, vm in self._list_available_vms().items():
            self.cursor.execute("""INSERT INTO "workerstate" (uuid, id, pid, position, params) VALUES (%s, %s, %s, %s, '{}')""", (uuid, vm["id"], os.getpid(), 'idle'))
            self.dbconn.commit()
            vm["state"] = "idle"
            logger.info('Selected VM UUID {0} and registered worker in DB'.format(uuid))
            
    def _list_available_victims(self):
        self.cursor.execute("""SELECT id, uuid FROM workerstate WHERE position = 'idle'""")
        victims = self.cursor.fetchall()
        return victims
                        
    def _exit(self, value=0):
        self.dbconn.close()
        logger.info("Closed connection to DB - cleanup complete, exiting now.")
        exit(value)
    
    def _wipe_workerstate(self):
        self.dbconn.rollback()
        self.cursor.execute("""DELETE FROM "workerstate" WHERE 1=1""")
        self.dbconn.commit()
        logger.info("Emptied workerstate table")
        
    def _list_available_vms(self):
        # get all started/suspended domains
        domains = self.lv_conn.listDomainsID()
        self.cursor.execute("""SELECT * FROM victims WHERE status = 'production'""")
        rows = self.cursor.fetchall()
        production_uuids = []
        for row in rows:
            production_uuids.append(row["uuid"])
        logger.debug("Production VM UUIDs: {0}".format(json.dumps(production_uuids)))
        available = {}
        # check which ones match the victims table
        if domains:
            for dom in domains:
                uuid = self.lv_conn.lookupByID(dom).UUIDString()
                if uuid in production_uuids:
                    available[uuid] = {"id": dom, "uuid": uuid}
        else:
            errmsg = "No victims online"
            logger.error(errmsg)
            raise ResourceUnavailable(errmsg)
        return available
    
    def _cleanup(self):
        lv_conn = libvirt.open("qemu:///system")
        for vm in self.vm_tracker:
            lv_conn.lookupByUUIDString(vm["uuid"]).suspend()
            logger.info("Paused worker VMs")
        self._wipe_workerstate()
        
    def _check_cases(self):
        self.cursor.execute("""SELECT cases.*, suspects.sha256, suspects.sha1, suspects.md5 FROM cases LEFT JOIN suspects ON cases.sha256=suspects.sha256 WHERE status='submitted' ORDER BY cases.priority DESC, cases.submittime ASC""")
        rows = self.cursor.fetchall()
        return rows
        
        
    def manage(self, host='localhost'):
        try:
            while True:
                cases = self._check_cases()
                if cases:
                    available = self._list_available_victims()
                    logger.info("Found {0} available victims".format(len(available)))
                    for case in cases:
                        if available:
                            case["hashes"] = {"sha256": case["sha256"], "sha1": case["sha1"], "md5": case["md5"]}
                            print(case)
                            case["reboots"] = int(case["reboots"]);
                            victim = available.pop()
                            logger.info("Allocated case {0} to victim uuid {1}".format(case["uuid"], victim["uuid"]))
                            w = vmworker.Worker(self.conf, victim, RUN_NUM_LEVEL)
                            w._state_update("assigned", (True, case))
                            t = threading.Thread(target=w.process, args=(case,))
                            t.start()
                        else:
                            logger.info("Found {0} case(s) ready to assign but no workers were available".format(len(cases)))
                            break
                    
                time.sleep(10)
        
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            logger.error("Fatal exception in manager: {0} {1} in {2}, line {3}, exiting main thread".format(ex_type, ex, fname, lineno))
        finally:
            self.cursor.execute("""SELECT * FROM workerstate""")
            rows = self.cursor.fetchall()
            logger.info("Removing all workers from active table")
            self.cursor.execute("""DELETE FROM workerstate WHERE 1=1""")
            self.dbconn.commit()
            logger.info("Suspending all VMs")
            for row in rows:
                self.lv_conn.lookupByID(row["id"]).suspend()
            
            logger.info("Cleanup complete, exiting manager")
        
            
            
class ResourceUnavailable(IndexError):
    def __init__(self, message):
        super(IndexError, self).__init__(message)



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--loglevel', dest='loglevel')
    parser.add_argument('--logdir', dest='logdir')
    parser.add_argument('--runloglevel', dest='runloglevel')
    parser.add_argument('-n', '--instancename', dest='instancename')
    parser.add_argument('-m', '--mountdir', dest='mountdir')
    parser.add_argument('config', default='runmanager.conf', type=argparse.FileType())
    args = parser.parse_args()
    
    conf = None
    
    if sys.version_info[0] == 2 and sys.version_info[1] == 7:
        conf = ConfigParser.ConfigParser()
    elif sys.version_info[0] == 3 and sys.version_info[1] >= 5:
        conf = configparser.ConfigParser()
    
    conf.readfp(args.config)
    if args.loglevel:
        conf.set('General', 'loglevel', args.loglevel)
    if args.logdir:
        conf.set('General', 'logdir', args.logdir)
    if args.instancename:
        conf.set('General', 'instancename', args.instancename)
    if args.mountdir:
        conf.set('General', 'mountdir', args.mountdir)
    
    NUM_LEVEL = getattr(logging, conf.get('General', 'loglevel').upper(), None)
    if not isinstance(NUM_LEVEL, int):
        raise ValueError('Invalid log level "{0}"'.format(NUM_LEVEL))
    
    RUN_NUM_LEVEL = getattr(logging, conf.get('General', 'runloglevel').upper(), None)
    if not isinstance(RUN_NUM_LEVEL, int):
        raise ValueError('Invalid log level "{0}"'.format(RUN_NUM_LEVEL))
    
    logging.basicConfig(level=logging.CRITICAL, format=fmt, datefmt=dfmt)
    
    #ch = logging.StreamHandler()
    #ch.setLevel(num_level)
    #ch.setFormatter(formatter)
    #logger.addHandler(ch)
    #logger.setLevel(num_level)
    
    log_modules = [__name__, "pyvnc", "vmworker", "runinstance", "db_calls", "victimfiles"]
    for module in log_modules:
        logging.getLogger(module).setLevel(NUM_LEVEL)
    
    if not os.access(conf.get('General', 'mountdir'), os.W_OK):
        logger.error("Mount directory {0} not writeable!".format(conf.get('General', 'mountdir')))
        exit(1)                 
    
    logger.debug('Starting broker...')
    
    try:        
        b = Broker(conf)
    except KeyError:
        logger.error("Invalid configuration supplied!")
        exit(1)
    
    logger.info('Broker starting')
    
    b.manage()
    

if __name__ == "__main__":
    main()
