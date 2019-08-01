// MIT License © https://github.com/scherma
// contact http_error_418 @ unsafehex.com

const uuidv4 = require('uuid/v4');
var amqp = require('amqplib/callback_api');
var fs = require('fs');
var options = require('./options');
var path = require('path');
var unixtime = require('unix-timestamp');
var crypto = require('crypto');
var Promise = require('bluebird');
var moment = require('moment');
var Addr = require('netaddr').Addr;
var db = require('./database');
var rootdir = path.join('/usr/local/unsafehex', options.conf.site.name);
var fdir = path.join(rootdir, 'suspects');
var casesdir = path.join(rootdir, 'output');
var mainmenu = require('../lib/mainmenu');
var Promise = require('bluebird');
var glob = require('glob');
var xml2js = require('xml2js');
var format = require('string-template');
var fs = require('fs');
var db = require('../lib/database');
var unzip = require('unzip');
const Telnet = require('telnet-client');

var Hashes = function(fpath) {
	return new Promise(function(fulfill, reject){
		var sha1sum = crypto.createHash('sha1');
		var sha256sum = crypto.createHash('sha256');
		var md5sum = crypto.createHash('md5');
		
		var s = fs.ReadStream(fpath);
		s.on('data', function(d) {
			sha1sum.update(d);
			sha256sum.update(d);
			md5sum.update(d);
			});
		s.on('end', function() {
			fulfill({md5: md5sum.digest('hex'), sha1: sha1sum.digest('hex'), sha256: sha256sum.digest('hex')});
			});
		s.on('err', function(err) {
			reject(err);
			});
	});
};

var Suspect = function(fname,
					   sha256,
					   fdir,
					   interactive=false,
					   banking=false,
					   web=false,
					   reboots=0,
					   runtime=120,
					   priority=0
					   ) {
	return new Promise(function(fulfill, reject){
		// validation
		if (!fname) { reject("FILENAME MISSING"); }
		if (!sha256) { reject("SHA256 MISSING"); }
		if (reboots > 2 || reboots < 0) { reject("INVALID REBOOTS VALUE " + reboots); }
		if (runtime > 600 || runtime < 120) { reject("INVALID RUNTIME VALUE " + runtime); }
		// force booleans
		interactive = !!interactive;
		banking = !!banking;
		web = !!web;
		
		var hd = sha256.substring(0,2);
		var fpdir = path.join(fdir, hd);
		var finalpath = path.join(fpdir, sha256);
		fs.stat(finalpath, function(err, stat){
			if (err === null) {
				var s = {};
				s.uuid = uuidv4();
				s.submittime = unixtime.now();
				s.fname = fname;
				s.interactive = interactive;
				s.banking = banking;
				s.reboots = reboots;
				s.runtime = runtime;
				s.ttl = runtime + 60; // allow 1 minute extra for victim prep
				s.web = web;
				s.priority = parseInt(priority);
				Hashes(finalpath).done(function(res){
					s.hashes = res;
					fs.stat(fpdir, function(err, stat){
						if (err === null) {

							db.new_case(s.uuid,
								s.submittime,
								s.hashes.sha256,
								s.fname,
								s.reboots,
								s.banking,
								s.web,
								s.runtime,
								s.priority)
							.then((c) => {
								fulfill(s);
							});
						} else {
							reject(err);
						}
					});
				});
			} else { reject(err); }
		});
	});
};

var GetCases = function(req) {
	return new Promise((fulfill, reject) => {
		var p = 0; // page = offset * length
		var w = {}; // where clause
		var d = true; // default order is descending
		var l = 20; // default length
		
		if (req.query.fname) { w.fname = req.query.fname; }
		if (req.query.sha256) { w.sha256 = req.query.sha256; }
		if (req.query.page) { p = parseInt(req.query.page); }
		if (req.query.desc == "false") { d = false; }
		if (req.query.limit) { l = parseInt(req.query.limit); }
		
		var extra = l + 1;
		
		db.list_cases(page=p, desc=d, where=w, limit=extra).then(function(dbres) {
			let buildQuery = function(w, p, l, d) {
				let params = Array();
				if (w.sha256) {	params.push("sha256=" + w.sha256); }
				if (w.fname) { params.push("fname=" + w.fname); }
				if (p) { params.push("page=" + p); }
				if (d === false) { params.push("desc=false"); }
				if (l) { params.push("limit=" + l); }
				
				return params.join("&");
			};
			
			let nxt = '';
			let prv = '';
			if (dbres.length > l) {
				nxt = '/cases' + req.path + '?' + buildQuery(w, p + 1, l, d);
				dbres.pop();
			}
			if (page > 0) {
				prv = '/cases' + req.path + '?' + buildQuery(w, p - 1, l, d);
			}
			
			dbres.forEach((row) => {
				row.labels = [];
				if (row.summary.alert > 0) {
					let alertlabel = {};
					alertlabel.labelstyle = "label-danger";
					alertlabel.labeltext = "alerts";
					alertlabel.labelcount = row.summary.alert;
					row.labels.push(alertlabel);
				}
				if (row.summary.dns > 0) {
					let dnslabel = {};
					dnslabel.labelstyle = "label-info";
					dnslabel.labeltext = "dns";
					dnslabel.labelcount = row.summary.dns;
					row.labels.push(dnslabel);
				}
				if (row.summary.http > 0) {
					let httplabel = {};
					httplabel.labelstyle = "label-warning";
					httplabel.labeltext = "http";
					httplabel.labelcount = row.summary.http;
					row.labels.push(httplabel);
				}
				if (row.summary.sysmon > 0) {
					let sysmonlabel = {};
					sysmonlabel.labelstyle = "label-primary";
					sysmonlabel.labeltext = "sysmon";
					sysmonlabel.labelcount = row.summary.sysmon;
					row.labels.push(sysmonlabel);
				}
				if (row.summary.files > 0) {
					let fileslabel = {};
					fileslabel.labelstyle = "label-default";
					fileslabel.labeltext = "files";
					fileslabel.labelcount = row.summary.files;
					row.labels.push(fileslabel);
				}
			});
			
			fulfill({cases: dbres, next: nxt, prev: prv, title: options.conf.site.displayName});
		});
	});
};

var ParseSysmon = (sm_evt) => {
	var reftable = {
		1: "Process created",
		2: "Process changed a file creation time",
		3: "Network connection",
		4: "Sysmon service state changed",
		5: "Process terminated",
		6: "Driver loded",
		7: "Image loaded",
		8: "CreateRemoteThread used",
		9: "RawAccessRead used",
		10: "ProcessAccess used",
		11: "File created or overwritten",
		12: "Registry object created/deleted",
		13: "Registry object value set",
		14: "Registry key or value renamed",
		15: "Alternate data stream created",
		255: "Sysmon error"
	};
	
	var e = {};
	
	e.System = {
		EventRecordID: sm_evt.recordid,
		Computer: sm_evt.computer,
		EventID: sm_evt.eventid,
		EventName: reftable[sm_evt.eventid],
		SystemTime: sm_evt.timestamp,
		ProcessID: sm_evt.executionprocess,
		ThreadID: sm_evt.executionthread
	};
	
	if (sm_evt.eventdata) {
		e.Data = sm_evt.eventdata;
	}
	
	if (e.Data.Hashes) {
		Object.keys(e.Data.Hashes).forEach((hashtype) => {
			e.Data[hashtype] = e.Data.Hashes[hashtype];
		});
		
		delete e.Data.Hashes;
	}
	
	if ([1].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.CommandLine;
	}
	
	if ([2].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.TargetFilename + ' (' + e.Data.PreviousCreationUtcTime + ' → ' + e.Data.CreationUtcTime + ')';
	}
	
	if ([3].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.Image + ' → ' + e.Data.DestinationIp + ':' + e.Data.DestinationPort;
		if (e.Data.DestinationHostname) {
			e.Highlight = e.Highlight + ' "' + e.Data.DestinationHostname + '"';
		}
	}
	
	if ([5].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.Image;
	}
	
	if ([7].indexOf(e.System.EventID) >= 0) {
		e.Highlight = format('"{img}" loaded "{imgld}"', {img: e.Data.Image, imgld: e.Data.ImageLoaded});
	}
	
	if ([8].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.SourceImage + ' → ' + e.Data.TargetImage;
	}
	
	if ([10].indexOf(e.System.EventID) >= 0) {
		e.Highlight = format('"{srcimg}" accessed "{tgtimg}"', {srcimg: e.Data.SourceImage, tgtimg: e.Data.TargetImage});
	}
	
	if ([11].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.TargetFilename;
	}
	
	if ([12, 13, 14].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.TargetObject;
	}
	
	if ([15].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.Image + ' → ' + e.Data.TargetFilename;
	}
	
	
	
	return e;
};

var DeleteFolderRecursive = function(path) {
  if( fs.existsSync(path) ) {
    fs.readdirSync(path).forEach(function(file,index){
      var curPath = path + "/" + file;
      if(fs.lstatSync(curPath).isDirectory()) { // recurse
        deleteFolderRecursive(curPath);
      } else { // delete file
        fs.unlinkSync(curPath);
		console.log('Delete: '+curPath);
      }
    });
	console.log('Delete: '+path);
    fs.rmdirSync(path);
  } else {
	console.log("Doesn't exist: "+path);
  }
};

var WorkerDisplayParams = function(rawparams) {
	var displayparams = {};
	if (Object.keys(rawparams).length !== 0) {
		var truefalse = {};
		var timeformat = 'YYYY-MM-DD HH:mm:ss';
		truefalse.Web = rawparams.web;
		truefalse.Banking = rawparams.banking;
		truefalse.Interactive = rawparams.interactive;
		truefalse.Reboots = rawparams.reboots;
		displayparams.Options = {content: JSON.stringify(truefalse), "class": ""};
		displayparams["Start time"] = {content: moment.unix(rawparams.starttime).format(timeformat), "class": ""};
		displayparams["Predicted finish"] = {content: moment.unix(rawparams.starttime + rawparams.ttl + 90).format(timeformat), "class": "clock"};
		displayparams["File name"] = {content: rawparams.fname, "class": ""};
	}
	return displayparams;
};

var PcapSummaryOfInterest = function(event) {
	var ofInterest = true;
	
	if ([137, 53].indexOf(event.src_port) >= 0 || [137, 53].indexOf(event.dest_port) >= 0) {
		ofInterest = false;
	}
	
	var s = Addr("224.0.0.0/10");
	if (s.contains(Addr(event.dest_ip))) {
		ofInterest = false;
	}
	
	if (event.src_ip == options.conf.network.gateway_ip) {
		ofInterest = false;
	}
	
	return ofInterest;
};

var SuricataEventsOfInterest = function(event) {
	var ofinterest = true;
	var subnets = options.conf.filters.subnets;
	var hostnames = options.conf.filters.hostnames;
	var tlsnames = options.conf.filters.tlsnames;
	
	subnets.forEach(function(subnet) {
		var s = Addr(subnet);
		if (s.contains(Addr(event.src_ip)) || s.contains(Addr(event.dest_ip))) {
			ofinterest = false;
		}
	});
	
	
	if (event.httpdata || event.dnsdata) {
		var namearr = [];
		if (event.httpdata && event.httpdata.hostname) {
			namearr = event.httpdata.hostname.split(".");	
		} else if (event.dnsdata && event.dnsdata.rrname) {
			namearr = event.dnsdata.rrname.split(".");
		}
		
		namearr.reverse();
		switch (namearr[0]) {
			case "uk":
				if (namearr[1] == "co" && hostnames["co.uk"].indexOf(namearr[2]) >= 0) {
					ofinterest = false;
				}
				break;
			default:
				if (namearr[0] in hostnames) {
					if (hostnames[namearr[0]].indexOf(namearr[1]) >= 0) {
						ofinterest = false;
					}	
				}
				break;
		}
	} else if (event.tlsdata) {
		var CNs = [];
		if (event.tlsdata.subject)
		{
			var attrs = event.tlsdata.subject.split(",");
			attrs.forEach((attr) => {
				var a = attr.trim().split("=");
				if (a[0] == "CN") {
					CNs.push(a[1]);
				}
			});
			CNs.forEach((CN) => {
				if (tlsnames.indexOf(CN) >= 0) {
					ofinterest = false;
				}
			});	
		}
	}
	
	return ofinterest;
};

function ExifParse(text) {
	var lines = text.split("\n");
	var exifdata = {};
	lines.forEach((line) => {
		var match = line.match("([^:]+): (.+)");
		if (match) {
			var name = match[1].trim();
			var value = match[2];
			var excludes = [
				"File Inode Change Date/Time",
				"File Modification Date/Time",
				"File Access Date/Time",
				"File Name",
				"Directory",
				"Create Date",
				"Modify Date",
				"File Permissions"
			];
			
			// if the data is NOT part of the  excludes, add to the result object
			if (excludes.indexOf(name) < 0 ) {
				exifdata[name] = value;		
			}
		}
		
	});
	return exifdata;
}

function ParseVictimFile(row) {
	var filedata = {};
	filedata.path = row.os_path;
	filedata.basename = path.win32.basename(row.os_path);
	filedata.sha256 = row.sha256;
	filedata.uuid = row.uuid;
	filedata.mimetype = row.mimetype;
	filedata.size = row.file_stat.st_size;
	filedata.ctime_sec = row.file_stat.st_ctime_sec;
	filedata.ctime_nsec = row.file_stat.st_ctime_nsec;
	filedata.humantime = {};
	if (filedata.ctime_sec) {
		filedata.humantime.created = moment.unix(filedata.ctime_sec).add(filedata.ctime_nsec / 1000000, 'ms').format("YYYY-MM-DD HH:mm:ss.SSS");
	}
	filedata.humantime.modified = moment.unix(row.file_stat.st_mtime_sec).add(row.file_stat.st_mtime_nsec / 1000000, 'ms').format("YYYY-MM-DD HH:mm:ss.SSS");
	filedata.humantime.accessed = moment.unix(row.file_stat.st_atime_sec).add(row.file_stat.st_atime_nsec / 1000000, 'ms').format("YYYY-MM-DD HH:mm:ss.SSS");
	if (filedata.size) {
		if (filedata.size > 1024*1024*1024) {
			filedata.humansize = Math.round(filedata.size / (1024*1024*1024)) + " GB";
		} else if (filedata.size > 1024*1024) {
			filedata.humansize = Math.round(filedata.size / (1024*1024)) + " MB";
		} else if (filedata.size > 1024) {
			filedata.humansize = Math.round(filedata.size / 1024) + " KB";
		} else {
			filedata.humansize = filedata.size + " B";
		}
	}
	filedata.saved = row.saved;
	if (filedata.saved) {
		filedata.download = row.file_path;
	}
	filedata.yararesult = row.yararesult;
	filedata.path_in_zip = row.file_path;
	if (row.avresult != 'OK') {
		filedata.avresult = row.avresult;
	}
	return filedata;
}

function RenderSuricata(events) {
	if (events.alert) {
		Object.keys(events.alert).forEach((key) => {
			if (events.alert[key].payload) {
				var binary = new Buffer.from(events.alert[key].payload, 'base64');
				var hextable = [];
				var asciitable = [];
				var linectr = 0;
				var hexline = [];
				var asciiline = "";
				for (i=0; i<binary.length; i++) {
					hexline.push(binary[i].toString(16).padStart(2, '0'));
					asciiline += String.fromCharCode(binary[i]).replace(/[^\x20-\x7f]/g, ".");
					linectr ++;
					if (linectr == 15) {
						hextable.push(hexline);
						asciitable.push(asciiline);
						hexline = [];
						asciiline = [];
						linectr = 0;
					}
				}
				
				// if it doesn't finish exactly on a boundary, push incomplete lines
				if (linectr < 15) {
					hextable.push(hexline);
					asciitable.push(asciiline);
				}
				events.alert[key].hextable = hextable;
				events.alert[key].asciitable = asciitable;
			}
		});
	}
	
	return events;
}

function GetCase(req) {
	var shortdir = req.params.sha256.substring(0,2);
	var casepath = path.join(casesdir, shortdir, req.params.sha256, req.params.uuid);
	var uuidshort = req.params.uuid.substr(0,2);
	var imagepath = path.join(rootdir, 'www', 'public', 'images', 'cases', uuidshort, req.params.uuid);
	var imagepublicpath = path.join('/images', 'cases', uuidshort, req.params.uuid);
	
	var sysmonP = new Promise((fulfill, reject) => {
		db.sysmon_for_case(req).then((rows) => {
			var ret = [];
			rows.forEach((row) => {
				if (row.is_artifact == 0 || parseInt(req.params.artifacts) == 1) {
					ret.push(row);
				}
			});
			
			fulfill(ret);
		});
	});
	
	var eventsP = new Promise((fulfill, reject) => {
		db.suricata_for_case(req.params.uuid).then((values) => {
			var d = {
				dns: [],
				http: [],
				alert: [],
				tls: []
			};
						
			values[0].forEach((dns_row) => {
				dns_row.timestamp = moment(dns_row.timestamp).toISOString();
				//dns_row.interesting = SuricataEventsOfInterest(dns_row);
				if (!dns_row.is_artifact || req.query.artifacts == "1") {
					d.dns.push(dns_row);
				}
			});
			values[1].forEach((http_row) => {
				http_row.timestamp = moment(http_row.timestamp).toISOString();
				//http_row.interesting = SuricataEventsOfInterest(http_row);
				if (!http_row.is_artifact || req.query.artifacts == "1") {
					d.http.push(http_row);
				}
			});
			values[2].forEach((alert_row) => {
				alert_row.timestamp = moment(alert_row.timestamp).toISOString();
				//alert_row.interesting = SuricataEventsOfInterest(alert_row);
				if (!alert_row.is_artifact || req.query.artifacts == "1") {
					d.alert.push(alert_row);
				}
			});
			values[3].forEach((tls_row) => {
				tls_row.timestamp = moment(tls_row.timestamp).toISOString();
				//tls_row.interesting = SuricataEventsOfInterest(tls_row);
				if (!tls_row.is_artifact || req.query.artifacts == "1") {
					d.tls.push(tls_row);
				}
			});
			fulfill(d);
		});
	});
	
	var pcapsummaryP = new Promise((fulfill, reject) => {
		db.pcap_summary_for_case(req.params.uuid).then((rows) => {
			var result = [];
			rows.forEach((row) => {
				if (!row.is_artifact || req.query.artifacts == "1") {
					result.push(row);
				}
			});
			
			fulfill(result);
		});
	});
	
	var runlogP = new Promise((fulfill, reject) => {
		fs.readFile(path.join(casepath, 'run.log'), 'utf8', (err, data) => {
			if (err === null) {
				fulfill(data);	
			} else {
				console.log(format("Unable to provide runlog: {err}", {err: err}));
				fulfill("");
			}
		});
	});
	
	var screenshots = new Promise((fulfill, reject) => {
		var images = Array();
		if (fs.existsSync(imagepath)) {
			var pattern = "+([0-9]).png";
			glob(pattern, {cwd: imagepath}, function(er, files) {
				var order = 0;
				files.forEach(file => {
					var thisimagepath = path.join(imagepublicpath, file);
					var testthumbpath = path.join(imagepath, file.replace(/\.png$/, "-thumb.png"));
					var publicthumbpath = path.join(imagepublicpath, file.replace(/\.png$/, "-thumb.png"));
					var thumbpath = thisimagepath;
					if (fs.existsSync(testthumbpath)) {
						thumbpath = publicthumbpath;
					}
					var active = "active";
					if (order > 0) { active = ""; }
					var image = {path: thisimagepath, alt: '', thumb: thumbpath, order: order, active: active};
					images.push(image);
					order++;
				});
				console.log(format("Found {num} images", {num: images.length}));
				fulfill(images);
			});
		} else {
			console.log("No images");
			fulfill([]);
		}

	});
	
	var thiscase = db.show_case(req.params.uuid);
	
	var victimfiles = new Promise((fulfill, reject) => {
		db.victimfiles(req.params.uuid)
		.then((values) => {
			vf = [];
			values.forEach((victimfile) => {
				victimfile.timestamp = moment(victimfile.timestamp).toISOString();
				if (!victimfile.is_artifact || req.query.artifacts == "1") {
					vf.push(victimfile);
				}
			});

			fulfill(vf);
		});
	});

	return Promise.all([eventsP, sysmonP, pcapsummaryP, runlogP, thiscase, screenshots, victimfiles])
	.then((values) => {
		if (values[4].length < 1) {
			throw "Case not found in DB";
		}
		var suspect = values[4][0];
		var events = values[0];
		var rawsysmon = values[1];
		var pcapsummary = values[2];
		var runlog = values[3];
		var images = values[5];
		var victimfiles = values[6];
		var properties = {};
		var showmagic = suspect.magic;
		if (suspect.magic.length > 50) {
			showmagic = suspect.magic.substr(0, 50) + "...";
		}
		properties.fname = {name: "File name", text: suspect.fname};
		properties.avresult = {name: "Clam AV result", text: suspect.avresult};
		properties.mimetype = {name: "File MIME type", text: showmagic, "class": "mime", htmltitle: suspect.magic};
		properties.submittime = {name: "Submit time", text: moment(suspect.submittime).toISOString()};
		properties.starttime = {name: "Run start time", text: moment(suspect.starttime).toISOString()};
		properties.endtime = {name: "Run end time", text: moment(suspect.endtime).toISOString()};
		properties.status = {name: "Status", text: suspect.status};
		properties.sha256 = {name: "SHA256", text: suspect.sha256};
		properties.sha1 = {name: "SHA1", text: suspect.sha1};
		properties.os = {name: "VM OS", text: suspect.vm_os};
		properties.uuid = {name: "Run UUID", text: suspect.uuid};
		properties.params = {name: "Parameters", text: "Reboots: " + suspect.reboots + ", Banking interaction: " + suspect.banking + ", Web interaction: " + suspect.web};
				
		var caseid = properties.sha256.text + "/" + properties.uuid.text;
		
		var sysmon = [];
		
		rawsysmon.forEach((row) => {
			var parsed = ParseSysmon(row);
			sysmon.push(parsed);
		});
		
		sysmon.sort(function(a,b){
			if (parseInt(a.System.EventRecordID) < parseInt(b.System.EventRecordID)) {
				return -1;
			}
			if (parseInt(a.System.EventRecordID) > parseInt(b.System.EventRecordID)) {
				return 1;
			}
			
			return 0;
		});
		
		var pcaplink = '/cases/' + properties.sha256.text + '/' + properties.uuid.text + '/pcap';
		var suspectlink = '/files/' + properties.sha256.text;
		var sockid = 0;
		var intsockid = 0;
		if (suspect.victim_params && suspect.victim_params.vnc) { intsockid = (parseInt(suspect.victim_params.vnc.port) - 5900); }
		if (intsockid < 10) { sockid = format("0{sockid}", { sockid: sockid }); } else { sockid = intsockid; }
		var vnclink = format('/novnc/vnc.html?host={host}&port={port}&path=vncsockets/{sockid}', {host: req.hostname, port: 443, sockid: sockid});
		
		var fileslist = [];
		var badfileslist = [];
		
		var fid = 0;
		victimfiles.forEach((row) => {
			var parsed = ParseVictimFile(row);
			parsed.id = fid;
			parsed.casesha256 = properties.sha256;
			if (parsed.ctime_sec) {
				fileslist.push(parsed);	
			} else {
				badfileslist.push(parsed);
			}
			
			fid++;
		});
		
		var badges = {};
		badges.sysmon = sysmon.length;
		badges.ids = events.alert.length;
		badges.dns = events.dns.length;
		badges.http = events.http.length;
		badges.tls = events.tls.length;
		badges.files = fileslist.length;
		badges.pcap = pcapsummary.length;
		
		fileslist.sort(function(a,b) {
			if (a.ctime_sec < b.ctime_sec) {
				return -1;
			}
			if (a.ctime_sec == b.ctime_sec && a.ctime_nsec < b.ctime_nsec) {
				return -1;
			}
			if (a.ctime_sec > b.ctime_sec) {
				return 1;
			}
			if (a.ctime_sec == b.ctime_sec && a.ctime_nsec > b.ctime_nsec) {
				return 1;
			}
			
			return 0;
		});
		
		
		var suricata_evts = RenderSuricata(events);
		return OverviewItems(suricata_evts.alert, suricata_evts.dns, suricata_evts.http, suricata_evts.tls, sysmon, fileslist, pcapsummary)
		.then((overview) => {
			var caseobj = {
				properties: properties,
				screenshots: images,
				overview: overview,
				suricata: suricata_evts,
				sysmon: sysmon,
				pcaplink: pcaplink,
				suspectlink: suspectlink,
				vnclink: vnclink,
				pcapsummary: pcapsummary,
				runlog: runlog,
				caseid: caseid,
				exifdata: suspect.exifdata,
				badges: badges,
				title: options.conf.site.displayName,
				files: fileslist
			};
			
			return caseobj;	
		});
		
	});
}

function OverviewItems(ids, dns, http, tls, sysmon, files, pcap) {
	return new Promise((fulfill, reject) => {
		var items = [];
		var tsfmt = 'YYYY-MM-DD HH:mm:ss.SSS';
		ids.forEach((i) => {
			var item = {};
			item.timestamp = moment(i.timestamp).format(tsfmt);
			item.timestampraw = moment(i.timestamp);
			item.type = 'alert';
			item.title = 'IDS alert';
			item.info = format('{signature} ({srcip}:{srcport} → {dstip}:{dstport})', {signature: i.alert.signature, srcip: i.src_ip, srcport: i.src_port, dstip: i.dest_ip, dstport: i.dest_port});
			item.source = 'Suricata';
			items.push(item);
		});
		dns.forEach((d) => {
			var item = {};
			item.timestampraw = moment(d.timestamp);
			item.timestamp = item.timestampraw.format(tsfmt);
			item.type = 'netconn';
			item.title = 'DNS query';
			item.info = format('{type} {rrtype} {rrname}', {type: d.dnsdata.type, rrtype: d.dnsdata.rrtype, rrname: d.dnsdata.rrname});
			item.source = 'Suricata';
			items.push(item);
		});
		http.forEach((h) => {
			var item = {};
			item.timestampraw = moment(h.timestamp);
			item.timestamp = item.timestampraw.format(tsfmt);
			item.type = 'netconn';
			item.title = 'HTTP request';
			item.info = format('({hostname}) {method} {url}', {hostname: h.httpdata.hostname, method: h.httpdata.http_method, url: h.httpdata.url});
			item.source = 'Suricata';
			items.push(item);
		});
		tls.forEach((t) => {
			var item = {};
			item.timestampraw = moment(t.timestamp);
			item.timestamp = item.timestampraw.format(tsfmt);
			item.type = 'netconn';
			item.title = 'TLS connection';
			item.info = t.tlsdata.sni;
			item.source = 'Suricata';
			items.push(item);
		});
		sysmon.forEach((s) => {
			var item = {};
			item.timestampraw = moment(s.System.SystemTime, 'YYYY-MM-DD hh:mm:ss.SSS');
			item.timestamp = item.timestampraw.format(tsfmt);
			item.type = 'misc';
			if ([1, 5].indexOf(s.System.EventID) >= 0) {
				item.type = 'process';
			} else if (s.System.EventID == 11) {
				item.type = 'file';
			} else if (s.System.EventID == 3) {
				item.type = 'netconn';
			}
			item.title = s.System.EventName;
			item.info = s.Highlight;
			item.source = 'Sysmon';
			items.push(item);
		});
		files.forEach((f) => {
			var item = {};
			item.timestampraw = moment(f.humantime.modified, 'YYYY-MM-DD hh:mm:ss.SSS');
			item.timestamp = item.timestampraw.format(tsfmt);
			if (f.avresult || Object.keys(f.yararesult).length > 0) {
				item.type = 'alert';	
			} else {
				item.type = 'file';	
			}
			item.title = 'Last modified';
			item.info = f.basename;
			item.source = 'Filesystem';
			items.push(item);
		});
		pcap.forEach((p) => {
			var item = {};
			item.timestampraw = moment(p.timestamp, 'YYYY-MM-DD hh:mm:ss.SSS');
			item.timestamp = item.timestampraw.format(tsfmt);
			item.title = "Traffic flow";
			item.info = format("{dest_ip}:{dest_port}", {dest_ip: p.dest_ip, dest_port: p.dest_port})
			item.source = 'pcap';
			items.push(item);
		});
		
		items.sort(function(a,b) {
			var m1 = moment(a.timestampraw);
			var m2 = moment(b.timestampraw);
			if (m1 < m2) {
				return -1;
			}
			if (m1 > m2) {
				return 1;
			}
			
			return 0;
		});
		
		fulfill(items);
	});
}

function Runlog(req) {
	var shortdir = req.params.sha256.substring(0,2);
	var casepath = path.join(casesdir, shortdir, req.params.sha256, req.params.uuid);
	return new Promise((fulfill, reject) => {
		fs.readFile(path.join(casepath, 'run.log'), 'utf8', (err, data) => {
			if (err === null) {
				fulfill(data);	
			} else {
				console.log(format("Unable to provide pcap summary: {err}", {err: err}));
				fulfill("");
			}
		});
	});
}

function ClamScan(suspectPath) {
	var params = {
		host: '127.0.0.1',
		port: options.conf.clamav.port,
		negotiationMandatory: false,
		timeout: 1000
	};
	var connection = new Telnet();
	var cmd = 'SCAN ' + suspectPath;
	var scan = connection.connect(params)
	.then(function(){
		return connection.send(cmd);
	}, function(err) {
		console.log(err);
		return '';
	});
	
	return scan;
}

function ClamUpdate(sha256) {
	var sd = sha256.substring(0,2);
	var fpath = path.join(fdir, sd, sha256);
	ClamScan(fpath).then((clamresult) => {
		clamresult = clamresult.replace(new RegExp("^[^:]+: ", ""), "").replace("\n", "");
		db.update_clam(sha256, clamresult);
	});
}

function ExtractSavedFile(casesha256, uuid, filesha256, fpath) {
	return new Promise((fulfill, reject) => {
		var sd = casesha256.substring(0,2);
		var zippath = path.join(casesdir, sd, casesha256, uuid, 'filesystem.zip');
		var details = {};
		fs.createReadStream(zippath)
		.pipe(unzip.Parse())
		.on('entry', function(entry) {
			var fileName = entry.path;
			if ("/" + fileName === fpath) {
				var outpath = path.join('/tmp', filesha256);
				entry.pipe(fs.createWriteStream(outpath));
				entry.on('end', function() {
					details.path = outpath;
					details.name = format("{bn}.{sha256}.bin" , { bn: path.basename(fpath), sha256: filesha256});
					fulfill(details);
				});
			} else {
				entry.autodrain();
			}
		})
		.on('end', function() {
			reject("File not found");
		});
	});
}

function SuspectProperties(sha256) {
	let properties = {};
	return new Promise((fulfill, reject) => {
		db.suspectProperties(sha256)
		.then((res) => {
			if (res.length > 0) {
				properties = res[0];
				properties.caseUUIDs = [];
				res.forEach((row) => {
					properties.caseUUIDs.push(row.uuid);
				});
				delete properties.uuid;
				fulfill(properties);
			} else {
				fulfill();
			}
		});
	});
}


function SearchRawTerm(searchterm) {
	var hits = {
		cases: {},
		suspects: {}
	};
	switch(FindStringType(searchterm)) {
		case "ipv4":
			return db.search_on_ip(searchterm).then((values) => {
				values.forEach((val) => {
					val.rows.forEach((row) => {
						if (row.uuid in hits.cases) {
							hits.cases[row.uuid].count += 1;
						} else {
							hits.cases[row.uuid] = row;
							hits.cases[row.uuid].count = 1;
						}
						hits.cases[row.uuid].sml = 1;
					});
				});
				
				return hits;
			});
			break;
		case "sha256":
			return db.search_on_sha256(searchterm).then((values) => {
				return ConstructHits(values);
			});
			break;
		case "sha1":
			return db.search_on_sha1(searchterm).then((values) => {
				return ConstructHits(values);
			});
			break;
		case "hash32":
			return db.search_on_hash32(searchterm).then((values) => {
				return ConstructHits(values);
			});
			break;
		default:
			return db.search_on_term(searchterm).then(([suri_http, suri_dns, suri_tls, suri_alert, sysmon_evt, victimfiles, suspects]) => {
				let values = {
					"suricata http": suri_http, 
					"suricata dns": suri_dns, 
					"suricata tls": suri_tls, 
					"suricata alert": suri_alert, 
					"sysmon": sysmon_evt, 
					"filesystem": victimfiles
				};

				Object.keys(values).forEach((key) => {
					values[key].rows.forEach((row) => {
						row.source = key;
						let uuid = row.uuid;
						if (uuid in hits.cases) {
							hits.cases[uuid].count += 1;
							if (hits.cases[uuid].sml < row.sml) {
								hits.cases[uuid].sml = row.sml;
							}
						} else {
							hits.cases[uuid] = {};
							hits.cases[uuid].count = 1;
							hits.cases[uuid].fname = row.fname;
							hits.cases[uuid].casetime = row.casetime;
							hits.cases[uuid].uuid = uuid;
							hits.cases[uuid].sml = row.sml;
							hits.cases[uuid].sha256 = row.sha256;
							hits.cases[uuid].rawobject = {
								uuid: uuid,
								sha256: row.sha256,
								satatus: row.status,
								endtime: row.endtime,
								casetime: row.casetime,
								fname: row.fname,
								events: []
							};
						}

						delete row.alltext;
						delete row.is_artifact;
						delete row.count;

						let event = row;
						delete event.sha256;
						delete event.status;
						delete event.casetime;
						delete event.endtime;
						delete event.fname;
						delete event.sml;

						hits.cases[uuid].rawobject.events.push(event);
					});
				});

				Object.keys(hits.cases).forEach((uuid) => {
					hits.cases[uuid].object = JSON.stringify(hits.cases[uuid].rawobject, null, 2);
				});

				suspects.rows.forEach((suspect) => {
					if (suspect.sha256 in hits.suspects) {
						hits.suspects[suspect.sha256].runcount += 1;
					} else {
						hits.suspects[suspect.sha256] = suspect;
						hits.suspects[suspect.sha256].runcount = 1;
					}
				});
				
				return hits;
			});
	}
}

function ConstructHits(values) {
	let hits = {
		cases: {},
		suspects: {}
	};
	values[0].forEach((suspect) => {
		hits.suspects[suspect.sha256] = suspect;
		hits.suspects[suspect.sha256].sml = 1;
		hits.suspects[suspect.sha256].runcount = 1;
		if (suspect.avresult != "OK") {
			hits.suspects[suspect.sha256].avbadge = suspect.avresult;
		}
		hits.suspects[suspect.sha256].yarabadges = [];
		if (suspect.yararesult) {
			hits.suspects[suspect.sha256].yarabadges = Object.keys(suspect.yararesult);
		}
	});
	values[1].rows.forEach((sysmon) => {
		let uuid = sysmon.uuid;
		if (uuid in hits.cases) {
			hits.cases[uuid].count += 1;
		} else {
			hits.cases[uuid] = {};
			hits.cases[uuid].count = 1;
			hits.cases[uuid].fname = sysmon.fname;
			hits.cases[uuid].casetime = sysmon.casetime;
			hits.cases[uuid].uuid = uuid;
			hits.cases[uuid].sha256 = sysmon.sha256;
			hits.cases[uuid].rawobject = {
				uuid: uuid,
				sha256: sysmon.sha256,
				satatus: sysmon.status,
				endtime: sysmon.endtime,
				casetime: sysmon.casetime,
				fname: sysmon.fname,
				events: []
			};
		}
		hits.cases[uuid].sml = 1;

		delete sysmon.uuid;
		delete sysmon.sh256;
		delete sysmon.status;
		delete sysmon.endtime;
		delete sysmon.status;
		delete sysmon.fname;

		hits.cases[uuid].rawobject.events.push(sysmon);
	});

	Object.keys(hits.cases).forEach((uuid) => {
		hits.cases[uuid].object = JSON.stringify(hits.cases[uuid].rawobject, null, 2);
	});

	return hits;
}

function FindStringType(thestring) {
	if (thestring.match(/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/)) return "ipv4";
	if (thestring.match(/^[A-Fa-f0-9]{64}$/)) return "sha256";
	if (thestring.match(/^[A-Fa-f0-9]{40}$/)) return "sha1";
	if (thestring.match(/^[A-Fa-f0-9]{32}$/)) return "hash32"; // md5 or imphash
	
	// if no match treat as a generic full text search string
	return "string";
}

function SortHits(hits) {
	var finalhits = {
		cases: [],
		suspects: []
	}

	Object.keys(hits.cases).forEach((uuid) => {
		finalhits.cases.push(hits.cases[uuid]);
	});
	Object.keys(hits.suspects).forEach((sha256) => {
		finalhits.suspects.push(hits.suspects[sha256]);
	});

	finalhits.cases.sort(function(a,b){
		if (a.sml < b.sml){
			return 1;
		} else if (a.sml > b.sml){
			return -1;
		} else {
			if (moment(a.submittime) < moment(b.submittime)) {
				return 1;
			} else if (moment(a.submittime) > moment(b.submittime)) {
				return -1;
			}

			return 0;
		}
	});

	return finalhits;
}

function SandboxStats(dt) {
	return Promise.all([
		db.cases_since_datetime(moment("1970-01-01")),
		db.cases_since_datetime(dt), 
		db.suspect_av_hits_since_datetime(dt),
		db.suspect_yara_hits_since_datetime(dt),
		db.case_av_hits_since_datetime(dt),
		db.case_yara_hits_since_datetime(dt),
		db.extensions_since_datetime(dt)
	]).then(([
		cases_all_time,
		cases,
		suspect_av_hits, 
		suspect_yara_hits, 
		case_av_hits, 
		case_yara_hits,
		extensions
	]) => {
		var output = {};

		output.startdate = dt.format("YYYY-MM-DD");
		output.cases_all_time = cases_all_time[0].count;
		output.cases = cases[0].count;
		output.datelist = get_date_list(dt);
		output.extensions = {
			datasets: [{
				data: []
			}],
			labels: []
		};
		
		let display_exts = extensions_to_display(extensions);
		output.extensions.datasets[0].data = display_exts.counts;
		output.extensions.labels = display_exts.labels;

		let suspectavlinedata = [];
		let suspectyaralinedata = [];
		let fileavlinedata = [];
		let fileyaralinedata = [];
		let avhits = {};
		let yarahits = {};
		output.datelist.forEach((date) => {
			let savtotal = 0;
			let suspectavhits = av_hit_builder(suspect_av_hits);
			for (let detection in suspectavhits.dates[date]) {
				savtotal += suspectavhits.dates[date][detection];
				if (avhits[detection]) {
					avhits[detection] += suspectavhits.dates[date][detection];
				} else {
					avhits[detection] = suspectavhits.dates[date][detection];
				}
			}
			suspectavlinedata.push(savtotal);
			let syaratotal = 0;
			let suspectyarahits = yara_hit_builder(suspect_yara_hits);
			for (let detection in suspectyarahits.dates[date]) {
				syaratotal += suspectyarahits.dates[date][detection];
				if (yarahits[detection]) {
					yarahits[detection] += suspectyarahits.dates[date][detection];
				} else {
					yarahits[detection] = suspectyarahits.dates[date][detection];
				}
			}
			suspectyaralinedata.push(syaratotal);
			let favtotal = 0;
			let fileavhits = av_hit_builder(case_av_hits);
			for (let detection in fileavhits.dates[date]) {
				favtotal += fileavhits.dates[date][detection];
				if (avhits[detection]) {
					avhits[detection] += fileavhits.dates[date][detection];
				} else {
					avhits[detection] = fileavhits.dates[date][detection];
				}
			}
			fileavlinedata.push(favtotal);
			let fyaratotal = 0;
			let fileyarahits = yara_hit_builder(case_yara_hits);
			for (let detection in fileyarahits.dates[date]) {
				fyaratotal += fileyarahits.dates[date][detection];
				if (yarahits[detection]) {
					yarahits[detection] += fileyarahits.dates[date][detection];
				} else {
					yarahits[detection] = fileyarahits.dates[date][detection];
				}
			}
			fileyaralinedata.push(fyaratotal);
		});
		output.suspectavlinedata = suspectavlinedata;
		output.suspectyaralinedata = suspectyaralinedata;
		output.fileavlinedata = fileavlinedata;
		output.fileyaralinedata = fileyaralinedata;
		output.avhits = avhits;
		output.yarahits = yarahits;

		return output;
	});
}

function extensions_to_display(extensions) {
	extensions.rows.sort(function(a,b){
		if (parseInt(a.count) > parseInt(b.count)) {
			return -1;
		}
		if (parseInt(a.count) < parseInt(b.count)) {
			return 1;
		}
		
		return 0;
	});
	
	// pallette.js breaks if asked for more than 12 colours
	// aggregate smallest values into 'other'
	let other = 0;
	while (extensions.rows.length >= 12) {
		let r = extensions.rows.pop();
		other += parseInt(r.count);	
	}

	let ext = {
		extension: ["other"],
		count: other
	}
	extensions.rows.push(ext);

	var ret = {
		labels: [],
		counts: []
	}
	extensions.rows.forEach((dbrow) => {
		ret.labels.push(dbrow.extension[0]);
		ret.counts.push(dbrow.count);
	});
	return ret;
}

function get_date_list(dt) {
	var date_list = [];
	var theday = moment(dt).utc();
	var today = moment().utc().endOf('day');
	while (theday.add(1, 'days') <= today) {
		var currentday = theday.format("YYYY-MM-DD");
		date_list.push(currentday);
	}

	return date_list;
}

function av_hit_builder(avhit_array) {
	let hit_obj = {
		dates: {},
		names: {}
	};
	avhit_array.forEach((av_hit) => {
		var day = moment(av_hit.time).format("YYYY-MM-DD");
		var avresult = av_hit.avresult;
		if (hit_obj.dates[day]) {
			if (hit_obj.dates[day][avresult]) {
				hit_obj.dates[day][avresult] += 1;
			} else {
				hit_obj.dates[day][avresult] = 1;
			}
		} else {
			hit_obj.dates[day] = {};
			hit_obj.dates[day][avresult] = 1;
		}

		if (hit_obj.names[avresult]) {
			hit_obj.names[avresult] += 1;
		} else {
			hit_obj.names[avresult] = 1;
		}
	});
	return hit_obj;
}

function yara_hit_builder(yarahit_array) {
	let hit_obj = {
		dates: {},
		names: {}
	};
	yarahit_array.forEach((result) => {
		var day = moment(result.time).format("YYYY-MM-DD");
		Object.keys(result.yararesult).forEach((key) => {
			if (hit_obj.dates[day]) {
				if (hit_obj.dates[day][key]) {
					hit_obj.dates[day][key] += 1;
				} else {
					hit_obj.dates[day][key] = 1;
				}
			} else {
				hit_obj.dates[day] = {};
				hit_obj.dates[day][key] = 1;
			}

			
			if (hit_obj.names[key]) {
				hit_obj.names[key] += 1;
			} else {
				hit_obj.names[key] = 1;
			}
		});
	});	

	return hit_obj;
}

function FilterConfig() {
	let config = {};
	return Promise.all([db.filter_rules(), db.filter_evttypes()])
	.then(([rules, evttypes]) => {
		rules.forEach((rule) => {
			let evttypelist = [];
			evttypes.forEach((evttype) => {
				let evttypecopy = Object.assign({}, evttype);
				evttypecopy.selected = false;
				if (rule.evttype == evttypecopy.evttype) {
					evttypecopy.selected = true;
				}
				evttypelist.push(evttypecopy);
			});
			rule.evttypelist = evttypelist;
			rule.conditions.forEach((condition) => {
				condition.methodlist = [{name: "rex", selected: false, label: "regex"}, {name: "eq", selected: false, label: "equal to"}];
				if (condition.method == "regex") {
					condition.methodlist[0].selected = true;
				} else if (condition.method == "eq") {
					condition.methodlist[1].selected = true;
				}
			});
		});
		config.rules = rules;
		return config;
	});
}

module.exports = {
	Hashes: Hashes,
	Suspect: Suspect,
	ParseSysmon: ParseSysmon,
	ParseVictimFile: ParseVictimFile,
	DeleteFolderRecursive: DeleteFolderRecursive,
	WorkerDisplayParams: WorkerDisplayParams,
	SuricataEventsOfInterest: SuricataEventsOfInterest,
	PcapSummaryOfInterest: PcapSummaryOfInterest,
	ExifParse: ExifParse,
	RenderSuricata: RenderSuricata,
	GetCases: GetCases,
	GetCase: GetCase,
	Runlog: Runlog,
	ClamScan: ClamScan,
	ClamUpdate: ClamUpdate,
	ExtractSavedFile: ExtractSavedFile,
	SuspectProperties: SuspectProperties,
	SearchRawTerm: SearchRawTerm,
	SortHits: SortHits,
	SandboxStats: SandboxStats,
	FilterConfig: FilterConfig
};
