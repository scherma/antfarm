// MIT License © https://github.com/scherma
// contact http_error_418 @ unsafehex.com

var express = require('express');
var router = express.Router();
var options = require('../lib/options');
var db = require('../lib/database');
var fs = require('fs');
var moment = require('moment');
var xml2js = require('xml2js');
require('string.format');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.send("Cool");
});

router.post('/register', function(req, res, next) {
  /*if (db.isServiceRegistered(req.body.GUID)) {
    res.status(204).send("Already registered");  
  } else */
  if (db.vmExists(req.body.VMName)) {
    db.registerVictimService(
      req.body.GUID,
      req.body.VMName,
      req.ip, 
      req.body.OSName,
      req.body.OfficeVersionString,
      req.body.OfficeVersionNum,
      req.body.username,
      req.body.password,
      req.body.DisplayHeight,
      req.body.DisplayWidth,
			req.body.MalwareX,
			req.body.MalwareY
    )
    .then(() => {
      res.status(200).send("Registered");
    });
  } else {
    res.status(403).send("Specified VM doesn't exist");
  }
});

router.get('/case/:guid', function(req, res, next) {
  db.findCaseForVM(req.params.guid)
  .then((rows) => {
    if (rows.length > 0) {
      var options = {};
      var ts = moment.utc();
      options.Year = ts.year();
      options.Month = ts.month() + 1; // months are zero indexed because moment js is clearly smoking crack
      options.Day = ts.date();
      options.Hour = ts.hours();
      options.Minute = ts.minutes();
      options.Second = ts.seconds();
      options.GetPath = `/files/${rows[0].sha256}`;
      options.FileName = rows[0].fname;
      options.RunUser = rows[0].username;
      options.RunTimeMs = rows[0].runtime * 1000;
			options.RunStyle = 1;
      //options.RunStyle = rows[0].runstyle;
      			
			db.markCaseObtained(rows[0].uuid)
			.then(() =>{
				return res.send(options);
			});
    } else {
      return res.status(404).send();
    }
  });
});

router.post('/case/:guid/data', function(req, res, next) {
	db.findCaseForVM(req.params.guid)
  .then((rows) => {
    if (rows.length > 0) {
			insertRows = [];
			req.body.Events.Sysmon.forEach((xml) => {	
				xml2js.parseString(xml, function (err, result) {
					if (!err) {
						eventdata = {};
						eventdata.Hashes = {};
						result.Event.EventData[0].Data.forEach((data) => {
							if (data.$.Name == "Hashes") {
								var eachHash = data._.split(",");
								eachHash.forEach((hashtype) => {
									var components = hashtype.split("=");
									eventdata.Hashes[components[0]] = components[1];
								});
							} else {
								eventdata[data.$.Name] = data._;	
							}
						});
						
						insertRow = {
							uuid: rows[0].uuid,
							recordid: result.Event.System[0].EventRecordID[0],
							eventid: result.Event.System[0].EventID[0],
							timestamp: result.Event.System[0].TimeCreated[0].$.SystemTime,
							executionprocess: result.Event.System[0].Execution[0].$.ProcessID,
							executionthread: result.Event.System[0].Execution[0].$.ThreadID,
							computer: result.Event.System[0].Computer[0],
							eventdata: JSON.stringify(eventdata),
							evt_xml: xml
						};
						
						insertRows.push(insertRow);
					}
				});
			});
			
			if (insertRows.length > 0) {
				db.sysmonInsert(insertRows)
				.then((result) => {
					console.log("Inserted {num} rows to sysmon_evts".format({num: result.rowCount}));	
				});
			}
			res.sendStatus(200);
		} else {
			res.sendStatus(404);
		}
  });
});

router.get('/files/:sha256', function(req, res, next) {
  var sd = req.params.sha256.substring(0,2);
  var fpath = `/usr/local/unsafehex/${options.conf.site.name}/suspects/${sd}/${req.params.sha256}`;
	console.log(fpath);
  if (fs.existsSync(fpath)) {
    res.download(fpath);  
  } else {
    res.status(404).send();
  }
});

module.exports = router;
