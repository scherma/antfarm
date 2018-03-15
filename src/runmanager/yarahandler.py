#!/usr/bin/env python3
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import yara, glob, os, logging

logger = logging.getLogger(__name__)

def testyara(conf, suspectpath):
    rulesdir = os.path.join(conf.get("General", "basedir"), conf.get("General", "instancename"), "yara")
    paths = glob.glob(os.path.join(rulesdir, "*"))

    filepaths = {}
    
    logger.debug("Running {} yara files from {} against {}".format(len(paths), rulesdir, suspectpath))

    for path in paths:
        abspath = os.path.abspath(path)
        fname = os.path.basename(path)
        namespace = fname.split(".")[0]
        filepaths[namespace] = abspath

    rules = yara.compile(filepaths=filepaths)

    matches = rules.match(suspectpath)

    return matches
