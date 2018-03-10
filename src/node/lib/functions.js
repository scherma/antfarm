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
					   runtime=120
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
				Hashes(finalpath).done(function(res){
					s.hashes = res;
					fs.stat(fpdir, function(err, stat){
						if (err === null) {
							fulfill(s);
						} else {
							reject(err);
						}
					});
				});
			} else { reject(err); }
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
	
	if ([5].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.Image;
	}
	
	if ([1].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.CommandLine;
	}
	
	if ([11].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.TargetFilename;
	}
	
	if ([12, 13, 14].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.TargetObject;
	}
	
	if ([8].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.SourceImage + ' -> ' + e.Data.TargetImage;
	}
	
	if ([3].indexOf(e.System.EventID) >= 0) {
		e.Highlight = e.Data.Image + ' -> ' + e.Data.DestinationIp + ':' + e.Data.DestinationPort;
		if (e.Data.DestinationHostname) {
			e.Highlight = e.Highlight + ' "' + e.Data.DestinationHostname + '"';
		}
	}
	
	return e;
};

var deleteFolderRecursive = function(path) {
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

var workerDisplayParams = function(rawparams) {
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

var pcapSummaryOfInterest = function(event) {
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

var ofInterest = function(event) {
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
	
	
	if (event.httpdata) {
		var namearr = event.httpdata.hostname.split(".");
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
	
	return ofinterest;
};

module.exports = {
	Hashes: Hashes,
	Suspect: Suspect,
	ParseSysmon: ParseSysmon,
	deleteFolderRecursive: deleteFolderRecursive,
	workerDisplayParams: workerDisplayParams,
	ofInterest: ofInterest,
	pcapSummaryOfInterest: pcapSummaryOfInterest
};
