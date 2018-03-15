#!/bin/bash

# this could cause issues with jobs running missing some suricata output
# if process is hupped during a running job; need to come up with some way
# of ensuring processing is stopped while this happens

find /var/log/suricata/ -type f -mtime +7 -name 'eve-*.json' -execdir rm -- '{}' \;