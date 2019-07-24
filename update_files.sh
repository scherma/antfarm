#!/bin/bash
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

SCRIPTDIR=$(dirname "$(realpath "$0")")

rsync -r --update --info=progress2 "$SCRIPTDIR/src/runmanager/"* "/usr/local/unsafehex/antfarm/runmanager/"
chmod +x "/usr/local/unsafehex/antfarm/runmanager/runmanager"
rsync -r --update --info=progress2 "$SCRIPTDIR/src/node/"* "/usr/local/unsafehex/antfarm/www/"
rsync -r --update --info=progress2 "$SCRIPTDIR/src/api/"* "/usr/local/unsafehex/antfarm/api/"
rsync -r --update --info=progress2 "$SCRIPTDIR/src/utils/"* "/usr/local/unsafehex/antfarm/utils/"
rsync -r --update --info=progress2 "$SCRIPTDIR/src/novnc/"* "/usr/local/unsafehex/antfarm/novnc/"
chmod +x "/usr/local/unsafehex/antfarm/utils/suricata-clean.sh"
chmod +x "/usr/local/unsafehex/antfarm/utils/yara-update.sh"