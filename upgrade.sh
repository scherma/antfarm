#!/bin/bash
# MIT License © https://github.com/scherma
# contact http_error_418 @ unsafehex.com

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

SCRIPTDIR=$(dirname "$(realpath "$0")")

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

systemctl stop antfarm
systemctl stop antfarm-ui
systemctl stop antfarm-api

function configure_antfarm_db() {
	#test postgres install here
	echo -e "${GREEN}Configuring database...${NC}"
    su -c "psql -q antfarm < $SCRIPTDIR/res/filter_config.sql" postgres
    su -c "psql -q antfarm -c \"ALTER TABLE victims ADD COLUMN snapshot text;\"" postgres
    echo "${RED}You will need to manaully add the current snapshot name${NC}"
	su -c "psql -q antfarm -c \"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO antfarm;\"" postgres
}

function update_all_files() {
	echo -e "${GREEN}Unwrapping sandbox manager files and utilities...${NC}"
    /bin/bash $SCRIPTDIR/update_files.sh
}

configure_antfarm_db
update_all_files

systemctl start antfarm-api
systemctl start antfarm-ui
systemctl start antfarm