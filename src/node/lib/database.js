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

module.exports = {
	new_suspect: function(sha256, sha1, md5, originalname, magic, avresult, exifdata, yararesult) {
		var formatted = moment().format('YYYY-MM-DD HH:mm:ss ZZ');
		return pg.raw(
			'INSERT INTO suspects (sha256, sha1, md5, originalname, magic, avresult, exifdata, yararesult, uploadtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (sha256) DO NOTHING;',
			[sha256, sha1, md5, originalname, magic, avresult, JSON.stringify(exifdata), JSON.stringify(yararesult), formatted]
		);
	},
	
	new_case: function(uuid, unixtime, sha256, fname, reboots, banking, web, registries, runtime, priority) {
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
			registries: registries,
			runtime: runtime,
			priority: priority})
		.into('cases');
	},
	
	list_cases: function(page=0, desc=true, where={}, limit=20) {
		var order = 'desc';
		if (!desc) {
			order = 'asc';
		}
		
		var offset = 0;
		if (page > 0) {
			offset = (limit - 1) * page;
		}
		var pgr = "to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS submittime, cases.sha256, cases.fname, cases.uuid AS uuid, cases.status AS status, " +
			"cases.summary AS summary, workerstate.position FROM cases LEFT JOIN workerstate ON cases.uuid = workerstate.job_uuid ";
		if (where) {
			return pg.select(pg.raw(pgr))
			.where(where).orderBy('cases.submittime', order).limit(limit).offset(offset);
		} else {
			return pg.select(pg.raw(pgr))
			.orderBy('cases.submittime', order).limit(limit).offset(offset);
		}
	},
	
	list_workers: function() {
		return pg('victims').select('victims.*', 'workerstate.id', 'workerstate.pid', 'workerstate.position', 'workerstate.params', 'workerstate.job_uuid').leftJoin('workerstate', 'victims.uuid', 'workerstate.uuid');
	},
	
	set_victim_status: function(uuid, status) {
		return pg('victims').update({status: status}).where({uuid: uuid});
	},
	
	list_files: function(page=0, where={}, limit=20) {
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
	},
	
	sysmon_for_case: function(req) {
		return pg('sysmon_evts').select(pg.raw("recordid, eventid, to_char(timestamp, 'YYYY-MM-DD HH24:MI:SS.MS') as timestamp, executionprocess, executionthread, computer, eventdata, is_artifact")).where({uuid: req.params.uuid});
	},
	
	victimfiles: function(uuid) {
		return pg('victimfiles').select('*').where({uuid:uuid});
	},
	
	show_case: function(uuid) {
		return pg('cases').leftJoin('suspects', 'cases.sha256', '=', 'suspects.sha256').where({'cases.uuid': uuid});
	},
	
	suricata_for_case: function(uuid) {
		var dns = pg('suricata_dns').where({uuid: uuid});
		var http = pg('suricata_http').where({uuid: uuid});
		var alert = pg('suricata_alert').where({uuid: uuid});
		var tls = pg('suricata_tls').where({uuid: uuid});
		return Promise.all([dns, http, alert, tls]);
	},
	
	pcap_summary_for_case: function(uuid) {
		return pg('pcap_summary').where('uuid', uuid);
	},
	
	delete_case: function(uuid) {
		
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
	},
	
	update_clam: function(sha256, clamresult) {
		pg('suspects').where({sha256: sha256})
		.then((res) => {
			if (res.avresult != clamresult && clamresult !== '') {
				pg('suspects').update({avresult: clamresult}).where({sha256: sha256})
				.then(() => {
					console.log(format("Updated avresult for {sha256} from '{avr}' to '{clm}'", {sha256: sha256, avr: res.avresult, clm: clamresult}));
				});
			}
		});
	},
	
	suspectProperties: function(sha256) {
		return pg('suspects').select('suspects.*', 'cases.uuid')
		.leftJoin('cases', 'suspects.sha256', '=', 'cases.sha256')
		.where({'cases.sha256': sha256});
	},
	
	search_on_term: function (searchterm, limit=100) {
		var suri_http = pg.raw("SELECT cases.uuid, cases.sha256, cases.fname, cases.status, cases.endtime, to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS casetime, word_similarity(?, suricata_http.alltext) AS sml, suricata_http.* FROM cases LEFT JOIN suricata_http ON cases.uuid = suricata_http.uuid WHERE suricata_http.is_artifact=false AND ? <% suricata_http.alltext ORDER BY sml LIMIT ?", [searchterm, searchterm, limit]);
		var suri_dns = pg.raw("SELECT cases.uuid, cases.sha256, cases.fname, cases.status, cases.endtime, to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS casetime, word_similarity(?, suricata_dns.alltext) AS sml, suricata_dns.* FROM cases LEFT JOIN suricata_dns ON cases.uuid = suricata_dns.uuid WHERE suricata_dns.is_artifact=false AND ? <% suricata_dns.alltext ORDER BY sml LIMIT ?", [searchterm, searchterm, limit]);
		var suri_tls = pg.raw("SELECT cases.uuid, cases.sha256, cases.fname, cases.status, cases.endtime, to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS casetime, word_similarity(?, suricata_tls.alltext) AS sml, suricata_tls.* FROM cases LEFT JOIN suricata_tls ON cases.uuid = suricata_tls.uuid WHERE suricata_tls.is_artifact=false AND ? <% suricata_tls.alltext ORDER BY sml LIMIT ?", [searchterm, searchterm, limit]);
		var suri_alert = pg.raw("SELECT cases.uuid, cases.sha256, cases.fname, cases.status, cases.endtime, to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS casetime, word_similarity(?, suricata_alert.alltext) AS sml, suricata_alert.* FROM cases LEFT JOIN suricata_alert ON cases.uuid = suricata_alert.uuid WHERE suricata_alert.is_artifact=false AND ? <% suricata_alert.alltext ORDER BY sml LIMIT ?", [searchterm, searchterm, limit]);
		var sysmon_evt = pg.raw("SELECT cases.uuid, cases.sha256, cases.fname, cases.status, cases.endtime, to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS casetime, word_similarity(?, sysmon_evts.alltext) AS sml, " +
			"sysmon_evts.recordid, sysmon_evts.eventid, sysmon_evts.timestamp, sysmon_evts.computer, sysmon_evts.eventdata FROM cases " +
			"LEFT JOIN sysmon_evts ON cases.uuid = sysmon_evts.uuid WHERE sysmon_evts.is_artifact=false AND ? <% sysmon_evts.alltext ORDER BY sml LIMIT ?", [searchterm, searchterm, limit]);
		var victimfiles = pg.raw("SELECT cases.uuid, cases.sha256, cases.fname, cases.status, cases.endtime, to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS casetime, word_similarity(?, victimfiles.alltext) AS sml, victimfiles.* FROM cases LEFT JOIN victimfiles ON cases.uuid = victimfiles.uuid WHERE victimfiles.is_artifact=false AND ? <% victimfiles.alltext ORDER BY sml LIMIT ?", [searchterm, searchterm, limit]);
		var suspects = pg.raw("SELECT *, to_char(uploadtime, 'YYYY-MM-DD HH24:MI:SS') AS uploadtime, word_similarity(?, suspects.alltext) AS sml FROM suspects WHERE ? <% alltext ORDER BY sml LIMIT ?", [searchterm, searchterm, limit]);
		return Promise.all([suri_http, suri_dns, suri_tls, suri_alert, sysmon_evt, victimfiles, suspects]);
	},
	
	search_on_ip: function(ipaddr) {
		var dns_ip = pg.raw("SELECT cases.uuid, cases.sha256, cases.fname, cases.status, cases.endtime, to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS casetime FROM cases LEFT JOIN suricata_dns ON cases.uuid = suricata_dns.uuid WHERE suricata_dns.is_artifact=false AND suricata_dns.dnsdata#>>'{rdata}' = ? ", [ipaddr]);
		var http_ip = pg.raw("SELECT cases.uuid, cases.sha256, cases.fname, cases.status, cases.endtime, to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS casetime FROM cases LEFT JOIN suricata_http ON cases.uuid = suricata_http.uuid WHERE suricata_http.is_artifact=false AND suricata_http.dest_ip = ? OR suricata_http.httpdata#>>'{hostname}' = ? ", [ipaddr, ipaddr]);
		var tls_ip = pg.raw("SELECT cases.uuid, cases.sha256, cases.fname, cases.status, cases.endtime, to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS casetime FROM cases LEFT JOIN suricata_tls ON cases.uuid = suricata_tls.uuid WHERE suricata_tls.is_artifact=false AND suricata_tls.dest_ip = ? ", [ipaddr]);
		var alert_ip = pg.raw("SELECT cases.uuid, cases.sha256, cases.fname, cases.status, cases.endtime, to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS casetime FROM cases LEFT JOIN suricata_alert ON cases.uuid = suricata_alert.uuid WHERE suricata_alert.is_artifact=false AND suricata_alert.dest_ip = ? OR suricata_alert.src_ip = ? ", [ipaddr, ipaddr]);
			
		return Promise.all([dns_ip, http_ip, tls_ip, alert_ip]);
	},
	
	search_on_hash32: function(hash32) {
		var suspects = pg("suspects").select("*").where({md5: hash32});
		var sysmon = pg.raw("SELECT cases.uuid, cases.sha256, cases.fname, cases.status, cases.endtime, to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS casetime, " +
			"sysmon_evts.recordid, sysmon_evts.eventid, sysmon_evts.timestamp, sysmon_evts.computer, sysmon_evts.eventdata FROM cases " +
			"LEFT JOIN sysmon_evts ON cases.uuid = sysmon_evts.uuid WHERE sysmon_evts.is_artifact=false AND sysmon_evts.eventdata#>>'{Hashes,MD5}' = ? OR sysmon_evts.eventdata#>>'{Hashes,IMPHASH}' = ?", [hash32, hash32]);
		return Promise.all([suspects, sysmon]);
	},
	
	search_on_sha1: function(sha1hash) {
		var suspects = pg("suspects").select("*").where({sha1: sha1hash});
		var sysmon = pg.raw("SELECT cases.uuid, cases.sha256, cases.fname, cases.status, cases.endtime, to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS casetime, " +
			"sysmon_evts.recordid, sysmon_evts.eventid, sysmon_evts.timestamp, sysmon_evts.computer, sysmon_evts.eventdata FROM cases " +
			"LEFT JOIN sysmon_evts ON cases.uuid = sysmon_evts.uuid WHERE sysmon_evts.is_artifact=false AND sysmon_evts.eventdata#>>'{Hashes,SHA1}' = ?", [sha1hash]);
		return Promise.all([suspects, sysmon]);
	},
	
	search_on_sha256: function(sha256hash) {
		var suspects = pg("suspects").select("*").where({sha256: sha256hash});
		var sysmon = pg.raw("SELECT cases.uuid, cases.sha256, cases.fname, cases.status, cases.endtime, to_char(cases.submittime, 'YYYY-MM-DD HH24:MI:SS') AS casetime, " +
			"sysmon_evts.recordid, sysmon_evts.eventid, sysmon_evts.timestamp, sysmon_evts.computer, sysmon_evts.eventdata FROM cases " +
			"LEFT JOIN sysmon_evts ON cases.uuid = sysmon_evts.uuid LEFT JOIN victimfiles ON cases.uuid = victimfiles.uuid WHERE (sysmon_evts.is_artifact=false AND sysmon_evts.eventdata#>>'{Hashes,SHA256}' = ?) OR (victimfiles.is_artifact=false AND victimfiles.sha256 = ?)", [sha256hash, sha256hash]);
		return Promise.all([suspects, sysmon]);
	},

	cases_since_datetime: function(dt) {
		return pg("cases").count("*").where("endtime", ">", dt);
	},

	suspects_since_datetime: function(dt) {
		return pg("suspects").count("*").where("uploadtime", ">", dt);
	},

	suspect_av_hits_since_datetime: function(dt) {
		return pg.select("avresult", "suspects.uploadtime AS time").from("suspects")
		.whereNot({avresult: "OK"}).andWhere("suspects.uploadtime", ">", dt);
	},

	suspect_yara_hits_since_datetime: function(dt) {
		return pg.select("yararesult", "suspects.uploadtime AS time").from("suspects")
		.whereNot({yararesult: '{}'}).andWhere("suspects.uploadtime", ">", dt);
	},

	case_av_hits_since_datetime: function(dt) {
		return pg.select("victimfiles.avresult", "cases.endtime AS time").from("victimfiles")
		.leftJoin("cases", "victimfiles.uuid", "cases.uuid")
		.whereRaw("victimfiles.avresult!='' AND victimfiles.avresult!='OK'").andWhere("cases.endtime", ">", dt);
	},

	case_yara_hits_since_datetime: function(dt) {
		return pg.select("victimfiles.yararesult", "cases.endtime AS time").from("victimfiles")
		.leftJoin("cases", "victimfiles.uuid", "cases.uuid")
		.whereNot({"victimfiles.yararesult": '{}'}).andWhere("cases.endtime", ">", dt);
	},

	extensions_since_datetime: function(dt) {
		return pg.raw("SELECT regexp_matches(lower(fname), '\\.(\\w+)$') AS extension, count(*) FROM cases WHERE cases.endtime > ? GROUP BY extension", [dt]);
	},

	filter_rules: function() {
		return pg("filter_config").select("filter_config.*", "filter_evttypes.*").leftJoin("filter_evttypes", "filter_config.evttype", "filter_evttypes.evttype").orderBy("filter_config.id");
	},
	
	filter_evttypes: function() {
		return pg("filter_evttypes").select("*");
	}
};
