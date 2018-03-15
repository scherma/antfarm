#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import arrow, guestfs, logging, os, sys

logger = logging.getLogger(__name__)
        
class VictimFiles:
    def __init__(self, guest_image, partition):
        self.g = guestfs.GuestFS(python_return_dict=True)
        self.partition = partition
        
        self.g.set_backend_setting("force_tcg", "1") # required to resolve error "Assertion `ret == cpu->kvm_msr_buf->nmsrs` failed"; caused by running within vmware
        self.g.add_drive_opts(guest_image, readonly=True)
        logger.info("Launching guestfs...")
        self.g.launch()
        logger.info("Mounting guest filesystem...")
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
        logger.info("Enumerating guest filesystem for new entries")
        report = {"files": 0, "directories": 0, "errors": 0}
        for f in self.find_new_files(starttime):
            file_in_guestfs = os.path.join('/', f["tsk_name"])
            try:
                newpath = os.path.join(dest_root, f["tsk_name"])
                if self.g.is_dir(os.path.join('/', f["tsk_name"])):
                    if not os.path.exists(newpath):
                        os.makedirs(newpath)
                    report["directories"] += 1
                elif self.g.is_file(file_in_guestfs):
                    newdir = os.path.dirname(newpath)
                    os.makedirs(newdir, exist_ok=True)
                    logger.debug("Writing {}...".format(newpath))
                
                    self.g.download(file_in_guestfs, newpath)
                    report["files"] += 1
            
            except Exception:
                ex_type, ex, tb = sys.exc_info()
                fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
                lineno = tb.tb_lineno
                logger.error("Exception {0} {1} in {2}, line {3} while processing filesystem output".format(ex_type, ex, fname, lineno))
                report["errors"] += 1
        logger.info("Filesystem report: {}".format(report))
        
    def download_modified_registries(self, starttime, dest_root, systemuser):
        registries = [
            "/Windows/System32/config/SECURITY",
            "/Windows/System32/config/SOFTWARE",
            "/Windows/System32/config/SYSTEM",
            "/Users/{}/NTUSER.DAT".format(systemuser),
            "/Users/{}/AppData/Local/Microsoft/Windows/UsrClass.dat".format(systemuser)
            ]
        for registry in registries:
            try:
                if arrow.get(self.g.statns(registry)["st_mtime_sec"]) > starttime:
                    destdir = os.path.join(dest_root, os.path.dirname(registry).lstrip("/"))
                    os.makedirs(destdir, exist_ok=True)
                    destfile = os.path.join(destdir, os.path.basename(registry))
                    self.g.download(registry, destfile)
            except Exception:
                ex_type, ex, tb = sys.exc_info()
                fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
                lineno = tb.tb_lineno
                logger.error("Exception {0} {1} in {2}, line {3} while processing filesystem output for registry {4}".format(ex_type, ex, fname, lineno, registry))
