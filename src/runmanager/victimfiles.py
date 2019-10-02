#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import arrow, guestfs, logging, os, sys, db_calls, yarahandler, pathlib, zipfile, re, socket, magic, hashlib

logger = logging.getLogger("antfarm.worker")
        
class VictimFiles:
    def __init__(self, conf, guest_image, partition):
        self.g = guestfs.GuestFS(python_return_dict=True)
        self.partition = partition
        self.conf = conf
        
        # required to resolve error "Assertion `ret == cpu->kvm_msr_buf->nmsrs` failed"; caused by running within vmware
        self.g.set_backend_setting("force_tcg", "1")
        
        self.g.add_drive_opts(guest_image, readonly=True)
        logger.debug("Launching guestfs...")
        self.g.launch()
        logger.debug("Mounting guest filesystem...")
        self.g.mount(self.partition, "/")
    
        
    def __del__(self):
        logger.info("Unmounting...")
        self.g.umount("/")
        
    def find_new_files(self, starttime):
        files = []
        for f in self.g.filesystem_walk(self.partition):
            if arrow.get(f["tsk_crtime_sec"]) > starttime:
                files.append(f)
        return files
    
    def to_exclude(self, fpath):
        exclude = False
        reason = None
        startpaths = [
            r"^/Users/[^/]+/AppData/Local/Microsoft/Windows/(Temporary Internet Files|WebCache|History)/",
            r"^/Windows/Prefetch/",
            r"^/ProgramData/Microsoft/Search/",
            r"^/Windows/inf/"
        ]
        for startpath in startpaths:
            if re.search(startpath, fpath):
                exclude = True
                reason = 'Matched start path "{}"'.format(startpath)
                break
            
        return exclude, reason
    
    def download_new_files(self, starttime, dest_root, from_suspect_tree=[]):
        zf = zipfile.ZipFile(os.path.join(dest_root, "filesystem.zip"), "a", zipfile.ZIP_DEFLATED)
        logger.info("Enumerating guest filesystem for new entries")
        report = {"files": 0, "errors": 0, "yara": 0}
        filesdict = {}
        for f in self.find_new_files(starttime):
            file_in_guestfs = os.path.join('/', f["tsk_name"])
            os_path = "C:" + str(pathlib.PureWindowsPath(file_in_guestfs))
            filesdict[file_in_guestfs] = {
                "statns": {},
                "os_path": os_path,
                "saved": False,
                "avresult": "",
                "mimetype": "",
                "sha256": ""
            }
            
            try:
                if self.g.is_file(file_in_guestfs):
                    logger.debug("Found {}".format(file_in_guestfs))
                    filesdict[file_in_guestfs]["statns"] = self.g.statns(file_in_guestfs)
                    
                    # don't download the file if it is too large - 20MB is a good starting point
                    if filesdict[file_in_guestfs]["statns"]["st_size"] <= (20 * 1024 * 1024):
                        exclude, reason = self.to_exclude(file_in_guestfs)
                        if not exclude:
                            logger.debug("Writing {} to archive".format(file_in_guestfs))
                            destfile = os.path.join("/tmp", os.path.basename(file_in_guestfs))
                            self.g.download(file_in_guestfs, destfile)
                            zf.write(destfile, arcname=file_in_guestfs)
                            
                            yararesult = yarahandler.testyara(self.conf, destfile)
                            if yararesult:
                                filesdict[file_in_guestfs]["yara"] = yararesult
                                logger.info("Yara detections! {}".format(yararesult))
                                report["yara"] += len(yararesult)

                            # get file magic
                            filesdict[file_in_guestfs]["mimetype"] = magic.from_file(destfile, mime=True)

                            # get clam AV output
                            avresult = self.clamscan(destfile)
                            filesdict[file_in_guestfs]["avresult"] = avresult
                            
                            filesdict[file_in_guestfs]["sha256"] = self.getsha256(destfile).hexdigest()
                                                        
                            os.remove(destfile)
                            report["files"] += 1
                            
                            # if we've made it here without an exception, file has downloaded. Mark as such in dict
                            filesdict[file_in_guestfs]["saved"] = True
                            
                            from_suspect = False
                            for f in from_suspect_tree:
                                if os_path == f["path"]:
                                    from_suspect = True
                            filesdict[file_in_guestfs]["from_suspect"] = from_suspect
                            logger.debug("Stored {}".format(file_in_guestfs))
                        else:
                            logger.debug("Excluded because: {}".format(reason))
            except Exception:
                ex_type, ex, tb = sys.exc_info()
                fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
                lineno = tb.tb_lineno
                logger.error("Exception {0} {1} in {2}, line {3} while processing filesystem output".format(ex_type, ex, fname, lineno))
                report["errors"] += 1
        logger.debug("Filesystem report: {}".format(report))
        zf.close()
        return filesdict
    
    def getsha256(self, path):
        BUF_SIZE = 65536
        sha256 = hashlib.sha256()
        
        with open(path, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha256.update(data)
        
        return sha256

    def clamscan(self, path):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9999))
        s.send("SCAN {}".format(path).encode())
        data = s.recv(1024)
        s.close()

        m = re.match(r"^.*?: (?P<scanresult>.+)", data.decode())
        if m:
            return m.group("scanresult")
        else:
            return ""
        
    def download_modified_registries(self, starttime, dest_root, systemuser, collect_registries):
        zf = zipfile.ZipFile(os.path.join(dest_root, "filesystem.zip"), "a", zipfile.ZIP_DEFLATED)
        registries = [
            "/Windows/System32/config/SECURITY",
            "/Windows/System32/config/SOFTWARE",
            "/Windows/System32/config/SYSTEM",
            "/Users/{}/NTUSER.DAT".format(systemuser),
            "/Users/{}/AppData/Local/Microsoft/Windows/UsrClass.dat".format(systemuser)
            ]
        
        registriesdict = {}
        if collect_registries:
            for registry in registries:
                try:
                    statns = self.g.statns(registry)
                    os_path = "C:" + str(pathlib.PureWindowsPath(registry))
                    if arrow.get(statns["st_mtime_sec"]) > starttime:
                        logger.debug("Registry hive {} was modified".format(registry))
                        registriesdict[registry] = {
                            "statns": statns,
                            "os_path": os_path,
                            "saved": False,
                            "avresult": "",
                            "mimetype": "",
                            "sha256": ""
                        }
                                            
                        destfile = os.path.join("/tmp", os.path.basename(registry))
                        self.g.download(registry, destfile)
                        registriesdict[registry]["sha256"] = self.getsha256(destfile).hexdigest()
                        zf.write(destfile, arcname=registry)
                        os.remove(destfile)
                        
                        # if we've made it here without an exception, file has downloaded. Mark as ssuch in dict
                        registriesdict[registry]["saved"] = True
                        logger.debug("Stored registry hive {}".format(registry))
                except Exception:
                    ex_type, ex, tb = sys.exc_info()
                    fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
                    lineno = tb.tb_lineno
                    logger.error("Exception {0} {1} in {2}, line {3} while processing filesystem output for registry {4}".format(ex_type, ex, fname, lineno, registry))
                    
            zf.close()
                
        return registriesdict
    
    def download_specific_files(self, fileslist, dest_root):
        zf = zipfile.ZipFile(os.path.join(dest_root, "filesystem.zip"), "a", zipfile.ZIP_DEFLATED)
        
        fpd = {}
        
        for fpath in fileslist:
            try:
                if self.g.is_file(fpath):
                    statns = self.g.statns(fpath)
                    os_path = "C:" + str(pathlib.PureWindowsPath(fpath))
                    fpd[fpath] = {
                        "statns": statns,
                        "os_path": os_path,
                        "saved": False,
                        "avresult": "",
                        "mimetype": "",
                        "sha256": ""
                    }
                    
                    if fpd[fpath]["statns"]["st_size"] <= (20 * 1024 * 1024):
                        destfile = os.path.join("/tmp", os.path.basename(fpath))
                        self.g.download(fpath, destfile)
                        zf.write(destfile, arcname=fpath)
                        yararesult = yarahandler.testyara(self.conf, destfile)
                        if yararesult:
                            fpd[fpath]["yara"] = yararesult
                            logger.info("Yara detections! {}".format(yararesult))

                        fpd[fpath]["avresult"] = clamscan(destfile)
                        fpd[fpath]["mimetype"] = magic.from_file(destfile, mime=True)
                        fpd[fpath]["sha256"] = self.getsha256(destfile).hexdigest()
                        
                        os.remove(destfile)
                    
                        fpd[fpath]["saved"] = True
                else:
                    logger.error("File {} could not be found")
            except Exception:
                ex_type, ex, tb = sys.exc_info()
                fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
                lineno = tb.tb_lineno
                logger.error("Exception {0} {1} in {2}, line {3} while processing filesystem output for file {4}".format(ex_type, ex, fname, lineno, fpath))
                
        zf.close()
        
        return fpd
                
