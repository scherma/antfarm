// © https://github.com/scherma
// contact http_error_418@unsafehex.com

var moment = require('moment');
var options = require('./options');
var Promise = require('bluebird');
var dbparams = {
	client: 'pg',
	connection: {
		user: options.conf.database.username,
		database: options.conf.site.name,
		password: options.conf.database.password,
		host:"localhost"}
	};
var pg = require('knex')(dbparams);

function new_suspect(sha256, sha1, md5, originalname, magic, avresult) {
	var formatted = moment().format('YYYY-MM-DD HH:mm:ss ZZ');
	return pg.raw('INSERT INTO suspects (sha256, sha1, md5, originalname, magic, avresult, uploadtime) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (sha256) DO NOTHING;',
				  [sha256, sha1, md5, originalname, magic, avresult, formatted]);
}

function new_case(uuid, unixtime, sha256, fname) {
	var formatted = moment.unix(unixtime).format('YYYY-MM-DD HH:mm:ss');
	return pg.insert({uuid: uuid, submittime: formatted, sha256: sha256, fname: fname, status: 'submitted'}).into('cases');
}

function list_cases(page=0, desc=true, where={}, limit=20) {
	var order = 'desc';
	if (!desc) {
		order = 'asc';
	}
	
	var offset = 0;
	if (page > 0) {
		offset = (limit - 1) * page;
	}
	
	if (where) {
		return pg('cases').select(pg.raw("to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS submittime, cases.sha256, cases.fname, cases.uuid AS uuid, cases.status, workerstate.position"))
		.leftJoin('workerstate', 'cases.uuid', 'workerstate.job_uuid')
		.where(where).orderBy('submittime', order).limit(limit).offset(offset);
	} else {
		return pg('cases').select(pg.raw("to_char(submittime, 'YYYY-MM-DD HH24:MI:SS'), sha256, fname, uuid, status")).orderBy('submittime', order).limit(limit).offset(offset);
	}
}

function list_workers() {
	return pg('victims').select('*').leftJoin('workerstate', 'victims.uuid', 'workerstate.uuid');
}

function list_files(page=0, where={}, limit=20) {
	var offset = 0;
	if (page > 0) {
		offset = (limit - 1) * page;
	}
		
	if (where) {
		parsedwhere = {};
		if (where.sha256) { parsedwhere["suspects.sha256"] = where.sha256; }
		if (where.sha1) { parsedwhere["suspects.sha1"] = where.sha1; }
		if (where.md5) { parsedwhere["suspects.md5"] = where.md5; }
		return pg('suspects').select('suspects.sha256', 'suspects.sha1', 'suspects.md5', 'suspects.originalname', 'suspects.magic').count('cases.sha256 AS runcount')
		.leftJoin('cases', 'suspects.sha256', '=', 'cases.sha256').groupBy('suspects.sha256').where(parsedwhere).orderBy('uploadtime', 'desc').limit(limit).offset(offset);
	} else {
		return pg('suspects').select('suspects.sha256', 'suspects.sha1', 'suspects.md5', 'suspects.originalname', 'suspects.magic').count('cases.sha256 AS runcount')
		.leftJoin('cases', 'suspects.sha256', '=', 'cases.sha256').groupBy('suspects.sha256').orderBy('uploadtime', 'desc').limit(limit).offset(offset);
	}
}

function sysmon_for_case(uuid) {
	return pg('sysmon_evts').select('recordid', 'eventid', 'timestamp', 'executionprocess', 'executionthread', 'computer', 'eventdata').where({uuid: uuid});
}

function show_case(uuid) {
	return pg('cases').leftJoin('suspects', 'cases.sha256', '=', 'suspects.sha256').where({'cases.uuid': uuid});
}

function suricata_for_case(uuid) {
	var dns = pg('suricata_dns').where({uuid: uuid});
	var http = pg('suricata_http').where({uuid: uuid});
	var alert = pg('suricata_alert').where({uuid: uuid});
	var tls = pg('suricata_tls').where({uuid: uuid});
	return Promise.all([dns, http, alert, tls]);
}

function delete_case(uuid) {
	return pg('cases').where('uuid', uuid).del();
}

module.exports = {
	list_cases: list_cases,
	new_case: new_case,
	new_suspect: new_suspect,
	show_case: show_case,
	list_files: list_files,
	list_workers: list_workers,
	delete_case: delete_case,
	sysmon_for_case: sysmon_for_case,
	suricata_for_case: suricata_for_case
	};