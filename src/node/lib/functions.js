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
				s.priority = priority;
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
								s.runtime)
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
		var p = 0;
		var w = {};
		var d = true;
		var l = 20;
		
		if (req.query.fname) { w.fname = req.query.fname; }
		if (req.query.sha256) { w.sha256 = req.query.sha256; }
		if (req.query.page) { p = parseInt(req.query.page); }
		if (req.query.desc == "false") { d = false; }
		if (req.query.limit) { l = parseInt(req.query.limit); }
		
		var extra = l + 1;
		
		db.list_cases(page=p, desc=d, where=w, limit=extra).then(function(dbres) {
			var buildQuery = function(w, p, l, d) {
				var params = Array();
				if (w.sha256) {	params.push("sha256=" + w.sha256); }
				if (w.fname) { params.push("fname=" + w.fname); }
				if (p) { params.push("page=" + p); }
				if (d === false) { params.push("desc=false"); }
				if (l) { params.push("limit=" + l); }
				
				return params.join("&");
			};
			
			var nxt = '';
			var prv = '';
			if (dbres.length > l) {
				nxt = '/cases?' + buildQuery(w, p + 1, l, d);
				dbres.pop();
			}
			if (page > 0) {
				prv = '/cases?' + buildQuery(w, p - 1, l, d);
			}
			
			dbres.forEach((row) => {
				row.labels = [];
				if (row.alert_count > 0) {
					var alertlabel = {};
					alertlabel.labelstyle = "label-danger";
					alertlabel.labeltext = "alerts";
					alertlabel.labelcount = row.alert_count;
					row.labels.push(alertlabel);
				}
				if (row.dns_count > 0) {
					var dnslabel = {};
					dnslabel.labelstyle = "label-info";
					dnslabel.labeltext = "dns";
					dnslabel.labelcount = row.dns_count;
					row.labels.push(dnslabel);
				}
				if (row.http_count > 0) {
					var httplabel = {};
					httplabel.labelstyle = "label-warning";
					httplabel.labeltext = "http";
					httplabel.labelcount = row.http_count;
					row.labels.push(httplabel);
				}
				if (row.files_count > 0) {
					var fileslabel = {};
					fileslabel.labelstyle = "label-default";
					fileslabel.labeltext = "files";
					fileslabel.labelcount = row.files_count;
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
			console.log("subnet");
		}
	});
	
	
	if (event.httpdata || event.dnsdata) {
		var namearr = [];
		if (event.httpdata) {
			namearr = event.httpdata.hostname.split(".");	
		} else {
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
		filedata.humantime.created = moment.unix(filedata.ctime_sec).format("YYYY-MM-DD HH:mm:ss Z");
	}
	filedata.humantime.modified = moment.unix(row.file_stat.st_mtime_sec).format("YYYY-MM-DD HH:mm:ss Z");
	filedata.humantime.accessed = moment.unix(row.file_stat.st_atime_sec).format("YYYY-MM-DD HH:mm:ss Z");
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
	
	var sysmonP = db.sysmon_for_case(req.params.uuid);
	
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
				dns_row.interesting = SuricataEventsOfInterest(dns_row);
				if (dns_row.interesting) {
					d.dns.push(dns_row);
				}
			});
			values[1].forEach((http_row) => {
				http_row.timestamp = moment(http_row.timestamp).toISOString();
				http_row.interesting = SuricataEventsOfInterest(http_row);
				if (http_row.interesting) {
					d.http.push(http_row);
				}
			});
			values[2].forEach((alert_row) => {
				alert_row.timestamp = moment(alert_row.timestamp).toISOString();
				alert_row.interesting = SuricataEventsOfInterest(alert_row);
				if (alert_row.interesting) {
					d.alert.push(alert_row);
				}
			});
			values[3].forEach((tls_row) => {
				tls_row.timestamp = moment(tls_row.timestamp).toISOString();
				tls_row.interesting = SuricataEventsOfInterest(tls_row);
				if (tls_row.interesting) {
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
				if (PcapSummaryOfInterest(row)) {
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
	
	var victimfiles = db.victimfiles(req.params.uuid);
	
	return Promise.all([eventsP, sysmonP, pcapsummaryP, runlogP, thiscase, screenshots, victimfiles])
	.then((values) => {
		if (values[4].length < 1) {
			res.status = 404;
			res.send("Case not found in DB");
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
		return OverviewItems(suricata_evts.alert, suricata_evts.dns, suricata_evts.http, suricata_evts.tls, sysmon, fileslist)
		.then((overview) => {
			var caseobj = {
				properties: properties,
				screenshots: images,
				overview: overview,
				suricata: suricata_evts,
				sysmon: sysmon,
				pcaplink: pcaplink,
				suspectlink: suspectlink,
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

function OverviewItems(ids, dns, http, tls, sysmon, files) {
	return new Promise((fulfill, reject) => {
		var items = [];
		ids.forEach((i) => {
			var item = {};
			item.timestamp = moment(i.timestamp).format();
			item.type = 'ids';
			item.title = 'IDS alert';
			item.info = format('{signature} ({srcip}:{srcport} → {dstip}:{dstport})', {signature: i.alert.signature, srcip: i.src_ip, srcport: i.src_port, dstip: i.dest_ip, dstport: i.dest_port});
			items.push(item);
		});
		dns.forEach((d) => {
			var item = {};
			item.timestamp = moment(d.timestamp).format();
			item.type = 'netconn';
			item.title = 'DNS query';
			item.info = format('{type} {rrtype} {rrname}', {type: d.dnsdata.type, rrtype: d.dnsdata.rrtype, rrname: d.dnsdata.rrname});
			items.push(item);
		});
		http.forEach((h) => {
			var item = {};
			item.timestamp = moment(h.timestamp).format();
			item.type = 'netconn';
			item.title = 'HTTP request';
			item.info = format('({hostname}) {method} {url}', {hostname: h.httpdata.hostname, method: h.httpdata.http_method, url: h.httpdata.url});
			items.push(item);
		});
		tls.forEach((t) => {
			var item = {};
			item.timestamp = moment(t.timestamp).format();
			item.type = 'netconn';
			item.title = 'TLS connection';
			item.info = t.tlsdata.sni;
			items.push(item);
		});
		sysmon.forEach((s) => {
			var item = {};
			item.timestamp = moment(s.System.SystemTime, 'YYYY-MM-DD hh:mm:ss').format();
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
			items.push(item);
		});
		files.forEach((f) => {
			var item = {};
			item.timestamp = moment(f.humantime.modified, 'YYYY-MM-DD hh:mm:ss').format();
			item.type = 'file';
			item.title = 'File modified';
			item.info = f.basename;
			items.push(item);
		});
		
		items.sort(function(a,b) {
			var m1 = moment(a.timestamp);
			var m2 = moment(b.timestamp);
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
	ExtractSavedFile: ExtractSavedFile
};
