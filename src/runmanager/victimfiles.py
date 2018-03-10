#!/usr/bin/env python
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
        report = {"files": 0, "directories": 0, "errors": 0}
        for f in self.find_new_files(starttime):
            file_in_guestfs = os.path.join('/', f["tsk_name"])
            try:
                newpath = os.path.join(dest_root, f["tsk_name"])
                if self.g.is_dir(os.path.join('/', f["tsk_name"])):
                    os.makedirs(newpath)
                    report["directories"] += 1
                elif self.g.is_file(file_in_guestfs, newpath):
                    newdir = os.path.dirname(newpath)
                    os.makedirs(newdir, exist_ok=True)
                    logger.debug("Writing {}...".format(newpath))
                
                    self.g.download(file_in_guestfs, newpath)
                    report["files"] += 1
            
            except Exception:
                logger.debug("Unable to capture file {}".format(file_in_guestfs))
                report["errors"] += 1
        logger.info("Filesystem report: {}".format(report))
