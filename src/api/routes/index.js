// MIT License © https://github.com/scherma
// contact http_error_418 @ unsafehex.com

var express = require('express');
var router = express.Router();
var options = require('../lib/options');
var db = require('../lib/database');
var fs = require('fs');
var moment = require('moment');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.send("Cool");
});

router.post('/register', function(req, res, next) {
  if (db.isServiceRegistered(req.body.GUID)) {
    res.status(204).send("Already registered");  
  } else if (db.vmExists(req.body.VMName)) {
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
      req.body.DisplayWidth
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
      options.RunStyle = rows[0].runstyle;
      			
			db.markCaseObtained(rows[0].uuid)
			.then(() =>{
				return res.send(options);
			});
    } else {
      return res.status(404).send();
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
