#!/usr/bin/env python
# coding: utf-8
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

import sys, traceback, os, arrow, logging
from lxml import etree
from datetime import datetime
from dateutil import tz

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view

logger = logging.getLogger(__name__)

def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    logger.debug("Finding node {}".format(tag))
    return node.find("%s%s" % (ns, tag))

def to_lxml(record_xml):
    if sys.version_info[0] == 2 and sys.version_info[1] == 7:
        return etree.fromstring("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>%s" % record_xml.encode('utf-8'))
    elif sys.version_info[0] == 3 and sys.version_info[1] >= 5:
        try:
            logger.debug("Creating etree from record XML text")
            return etree.fromstring(record_xml)
        except Exception:
            ex_type, ex, tb = sys.exc_info()
            fname = os.path.split(tb.tb_frame.f_code.co_filename)[1]
            lineno = tb.tb_lineno
            logger.error("Exception {0} {1} in {2}, line {3} while processing job, Suricata data not written".format(ex_type, ex, fname, lineno))
            raise RuntimeError(ex)
    
def xml_records(filename):
    with Evtx(filename) as evtx:
#        try:
        for xml, record in evtx_file_xml_view(evtx.get_file_header()):
            try:
                logger.debug("Yielding XML")
                yield to_lxml(xml), None
            except etree.XMLSyntaxError as e:
                logger.error(e)
                yield xml, e

def parsed_date(dstr):
    ts = arrow.get(dstr)
    return ts

def event_in_daterange(d, start, end):
    is_in_range = True
    if d < start:
        is_in_range = False
    if d > end:
        is_in_range = False
    return is_in_range

def matching_records(evtfile, sdatetime, edatetime):
    for node, err in xml_records(evtfile):
        if err is not None:
            continue
        else:
            syst = get_child(node, "System")
            logger.debug("Found child node")
            t = parsed_date(get_child(syst, "TimeCreated").get("SystemTime"))
            if event_in_daterange(t, sdatetime, edatetime):
                logger.debug("Event with time {} matches date range".format(t.format('YYYY-MM-DD HH:mm:ss')))
                yield node
            else:
                logger.debug("Event with time {} not in date range".format(t.format('YYYY-MM-DD HH:mm:ss')))
                continue

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("evtfile", type=str)
    parser.add_argument("outfile", type=argparse.FileType('w'))
    parser.add_argument("start", type=parsed_date, help="Start date/time YYYY-mm-dd HH:MM:SS(.f)")
    parser.add_argument("-e", dest="end", type=parsed_date, help="End date/time YYYY-mm-dd HH:MM:SS(.f)",
                        default=arrow.utcnow())
    args = parser.parse_args()
    
    logging.basicConfig()
    
    for record in matching_records(args.evtfile, args.start, args.end):
        args.outfile.write(etree.tostring(record, pretty_print=True).decode())
    
        
if __name__ == "__main__":
    main()
