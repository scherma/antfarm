// MIT License © https://github.com/scherma
// contact http_error_418 @ unsafehex.com

var moment = require('moment');
var options = require('./options');
var Promise = require('bluebird');
var dbparams = {
	client: 'pg',
	connection: {
		user: options.conf.database.username,
		database: options.conf.database.name,
		password: options.conf.database.password,
		host:"localhost"}
	};
var pg = require('knex')(dbparams);
var format = require('string-template');

function new_suspect(sha256, sha1, md5, originalname, magic, avresult, exifdata, yararesult) {
	var formatted = moment().format('YYYY-MM-DD HH:mm:ss ZZ');
	return pg.raw(
		'INSERT INTO suspects (sha256, sha1, md5, originalname, magic, avresult, exifdata, yararesult, uploadtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (sha256) DO NOTHING;',
		[sha256, sha1, md5, originalname, magic, avresult, JSON.stringify(exifdata), JSON.stringify(yararesult), formatted]
	);
}

function new_case(uuid, unixtime, sha256, fname, reboots, banking, web, runtime, priority) {
	var formatted = moment.unix(unixtime).format('YYYY-MM-DD HH:mm:ss');
	
	var components = fname.split(".");
	var ext = components[components.length - 1];
	
	// default method to run a suspect
	// cmd /c start <file>
	var runstyle = 2;
	
	// direct CallProcessAsUser
	var type0 = ["exe", "com", "bat", "bin", "cpl", "ins", "inx", "isu", "job", "pif", "paf", "mst", "msi", "msc"];
	
	// explorer.exe <file>
	var type1 = ["jse", "wsf", "vbs", "js"];
	
	if (type0.indexOf(ext) >= 0) {
		runstyle = 0;
	} else if (type1.indexOf(ext) >= 0) {
		runstyle = 1;
	}
	
	return pg.insert({
		uuid: uuid,
		submittime: formatted,
		sha256: sha256,
		fname: fname,
		status: 'submitted',
		runstyle: runstyle,
		reboots: reboots,
		banking: banking,
		web: web,
		runtime: runtime,
		priority: priority})
	.into('cases');
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
	var pgr = "to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS submittime, cases.sha256, cases.fname, cases.uuid AS uuid, cases.status, workerstate.position, alerts.c AS alert_count, dns.c AS dns_count, http.c AS http_count, files.c as files_count FROM cases LEFT JOIN workerstate ON cases.uuid = workerstate.job_uuid LEFT JOIN (SELECT uuid, COUNT(*) AS c FROM suricata_alert GROUP BY uuid) AS alerts ON cases.uuid = alerts.uuid LEFT JOIN (SELECT uuid, COUNT(*) AS c FROM suricata_dns GROUP BY uuid) AS dns ON cases.uuid = dns.uuid LEFT JOIN (SELECT uuid, COUNT(*) AS c FROM suricata_http GROUP BY uuid) AS http ON cases.uuid = http.uuid LEFT JOIN (SELECT uuid, COUNT(*) AS c FROM victimfiles GROUP BY uuid) AS files ON cases.uuid = files.uuid";
	
	if (where) {
		return pg.select(pg.raw(pgr))
		.where(where).orderBy('submittime', order).limit(limit).offset(offset);
	} else {
		return pg.select(pg.raw(pgr))
		.orderBy('submittime', order).limit(limit).offset(offset);
	}
}

function list_workers() {
	return pg('victims').select('victims.*', 'workerstate.id', 'workerstate.pid', 'workerstate.position', 'workerstate.params', 'workerstate.job_uuid').leftJoin('workerstate', 'victims.uuid', 'workerstate.uuid');
}

function set_victim_status(uuid, status) {
	return pg('victims').update({status: status}).where({uuid: uuid});
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
		return pg('suspects').select('suspects.*').count('cases.sha256 AS runcount')
		.leftJoin('cases', 'suspects.sha256', '=', 'cases.sha256').groupBy('suspects.sha256').where(parsedwhere).orderBy('uploadtime', 'desc').limit(limit).offset(offset);
	} else {
		return pg('suspects').select('suspects.*').count('cases.sha256 AS runcount')
		.leftJoin('cases', 'suspects.sha256', '=', 'cases.sha256').groupBy('suspects.sha256').orderBy('uploadtime', 'desc').limit(limit).offset(offset);
	}
}

function sysmon_for_case(uuid) {
	return pg('sysmon_evts').select(pg.raw("recordid, eventid, to_char(timestamp, 'YYYY-MM-DD HH24:MI:SS') as timestamp, executionprocess, executionthread, computer, eventdata")).where({uuid: uuid});
}

function victimfiles(uuid) {
	return pg('victimfiles').select('*').where({uuid:uuid});
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

function pcap_summary_for_case(uuid) {
	return pg('pcap_summary').where('uuid', uuid);
}

function delete_case(uuid) {
	
	return pg.transaction(t => {
		
		var delete_dns = pg('suricata_dns').where('uuid', uuid).del().transacting(t);
		var delete_victimfiles = pg('victimfiles').where('uuid', uuid).del().transacting(t);
		var delete_http = pg('suricata_http').where('uuid', uuid).del().transacting(t);
		var delete_alert = pg('suricata_alert').where('uuid', uuid).del().transacting(t);
		var delete_tls = pg('suricata_tls').where('uuid', uuid).del().transacting(t);
		var delete_pcap = pg('pcap_summary').where('uuid', uuid).del().transacting(t);
		var delete_sysmon = pg('sysmon_evts').where('uuid', uuid).del().transacting(t);
		var del_case = pg('cases').where('uuid', uuid).del().transacting(t);
		
		return Promise.all([delete_dns, delete_http, delete_alert, delete_tls, delete_pcap, delete_sysmon, delete_victimfiles])
		.then(() => {
			return del_case;
		})
		.then(t.commit)
		.catch((err) => {
			console.log(err);
			t.rollback();
		});
	});
}

function update_clam(sha256, clamresult) {
	pg('suspects').where({sha256: sha256})
	.then((res) => {
		if (res.avresult != clamresult && clamresult !== '') {
			pg('suspects').update({avresult: clamresult}).where({sha256: sha256})
			.then(() => {
				console.log(format("Updated avresult for {sha256} from '{avr}' to '{clm}'", {sha256: sha256, avr: res.avresult, clm: clamresult}));
			});
		}
	});
}

function suspectProperties(sha256) {
	return pg('suspects').select('suspects.*', 'cases.uuid')
	.leftJoin('cases', 'suspects.sha256', '=', 'cases.sha256')
	.where({'cases.sha256': sha256});
}

module.exports = {
	list_cases: list_cases,
	new_case: new_case,
	new_suspect: new_suspect,
	show_case: show_case,
	list_files: list_files,
	list_workers: list_workers,
	set_victim_status: set_victim_status,
	delete_case: delete_case,
	sysmon_for_case: sysmon_for_case,
	suricata_for_case: suricata_for_case,
	pcap_summary_for_case: pcap_summary_for_case,
	victimfiles: victimfiles,
	update_clam: update_clam,
	suspectProperties: suspectProperties
};