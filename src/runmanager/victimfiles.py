#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import arrow, guestfs, logging, os, sys, db_calls, yarahandler, pathlib, zipfile

logger = logging.getLogger("antfarm.worker")
        
class VictimFiles:
    def __init__(self, conf, guest_image, partition):
        self.g = guestfs.GuestFS(python_return_dict=True)
        self.partition = partition
        self.conf = conf
        
        self.g.set_backend_setting("force_tcg", "1") # required to resolve error "Assertion `ret == cpu->kvm_msr_buf->nmsrs` failed"; caused by running within vmware
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
    
    def download_new_files(self, starttime, dest_root):
        zf = zipfile.ZipFile(dest_root + ".zip", "a", zipfile.ZIP_DEFLATED)
        logger.info("Enumerating guest filesystem for new entries")
        report = {"files": 0, "errors": 0, "yara": 0}
        filesdict = {}
        for f in self.find_new_files(starttime):
            file_in_guestfs = os.path.join('/', f["tsk_name"])
            os_path = "C:" + str(pathlib.PureWindowsPath(file_in_guestfs))
            filesdict[file_in_guestfs] = {
                "statns": {},
                "os_path": os_path,
                "saved": False
            }
            
            try:
                if self.g.is_file(file_in_guestfs):
                    logger.debug("Writing {} to archive".format(file_in_guestfs))
                
                    filesdict[file_in_guestfs]["statns"] = self.g.statns(file_in_guestfs)
                    destfile = os.path.join("/tmp", os.path.basename(file_in_guestfs))
                    self.g.download(file_in_guestfs, destfile)
                    zf.write(destfile, arcname=file_in_guestfs)
                    
                    yararesult = yarahandler.testyara(self.conf, destfile)
                    if yararesult:
                        filesdict[file_in_guestfs]["yara"] = yararesult
                        logger.info("Yara detections! {}".format(yararesult))
                        report["yara"] += len(yararesult)
                    
                    os.remove(destfile)
                    report["files"] += 1
                    
                    # if we've made it here without an exception, file has downloaded. Mark as such in dict
                    filesdict[file_in_guestfs]["saved"] = True
            except Exception:
                ex_type, ex, tb = sys.exc_info()
                fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
                lineno = tb.tb_lineno
                logger.error("Exception {0} {1} in {2}, line {3} while processing filesystem output".format(ex_type, ex, fname, lineno))
                report["errors"] += 1
        logger.debug("Filesystem report: {}".format(report))
        zf.close()
        return filesdict
        
    def download_modified_registries(self, starttime, dest_root, systemuser):
        zf = zipfile.ZipFile(dest_root + ".zip", "a", zipfile.ZIP_DEFLATED)
        registries = [
            "/Windows/System32/config/SECURITY",
            "/Windows/System32/config/SOFTWARE",
            "/Windows/System32/config/SYSTEM",
            "/Users/{}/NTUSER.DAT".format(systemuser),
            "/Users/{}/AppData/Local/Microsoft/Windows/UsrClass.dat".format(systemuser)
            ]
        
        registriesdict = {}
        
        for registry in registries:
            try:
                statns = self.g.statns(registry)
                os_path = "C:" + str(pathlib.PureWindowsPath(registry))
                if arrow.get(statns["st_mtime_sec"]) > starttime:
                    registriesdict[registry] = {
                        "statns": statns,
                        "os_path": os_path,
                        "saved": False
                    }
                                        
                    destfile = os.path.join("/tmp", os.path.basename(registry))
                    self.g.download(registry, destfile)
                    zf.write(destfile, arcname=registry)
                    os.remove(destfile)
                    
                    # if we've made it here without an exception, file has downloaded. Mark as ssuch in dict
                    registriesdict[registry]["saved"] = True
            except Exception:
                ex_type, ex, tb = sys.exc_info()
                fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
                lineno = tb.tb_lineno
                logger.error("Exception {0} {1} in {2}, line {3} while processing filesystem output for registry {4}".format(ex_type, ex, fname, lineno, registry))
                
        return registriesdict
