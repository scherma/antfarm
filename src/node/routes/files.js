// MIT License © https://github.com/scherma
// contact http_error_418 @ unsafehex.com

var express = require('express');
var router = express.Router();
var db = require('../lib/database');
var options = require('../lib/options');
var functions = require('../lib/functions');
var mainmenu = require('../lib/mainmenu');
var fs = require('fs');
const path = require('path');
var rootdir = path.join('/usr/local/unsafehex', options.conf.site.name);
var filespath = path.join(rootdir, 'suspects');
var multer = require('multer');
var upload = multer({dest: filespath});
var type = upload.single('suspect');
var Magic = require('mmmagic').Magic;
var Promise = require('bluebird');
const Telnet = require('telnet-client');
var format = require("string-template");
var exec = require("child_process").exec;

router.get('/', function(req, res, next) {
	var p = 0;
	var w = {};
	var l = 20;
	
	if (req.query.sha256) { w.sha256 = req.query.sha256; }
	if (req.query.sha1) { w.sha1 = req.query.sha1; }
	if (req.query.md5) { w.md5 = req.query.md5; }
	if (req.query.fname) { w.fname = req.query.fname; }
	if (req.query.page) { p = parseInt(req.query.page); }
	if (req.query.limit) { l = parseInt(req.query.limit); }
	
	var extra = l + 1;
	
	db.list_files(page=p, where=w, limit=extra).then(function(dbres) {
		var buildQuery = function(w, p, l) {
			var params = Array();
			if (w.sha256) {	params.push("sha256=" + w.sha256); }
			if (w.sha1) { params.push("sha1=" + w.sha1); }
			if (w.md5) { params.push("md5=" + w.md5); }
			if (w.fname) { params.push("fname=" + w.fname); }
			if (p) { params.push("page=" + p); }
			if (l) { params.push("limit=" + l); }
			
			return params.join("&");
		};
		
		var nxt = '';
		var prv = '';
		if (dbres.length > l) {
			nxt = '/files?' + buildQuery(w, parseInt(p) + 1, l);
			dbres.pop();
		}
		if (page > 0) {
			prv = '/files?' + buildQuery(w, parseInt(p) - 1, l);
		}
		
		dbres.forEach((dbr) => {
			var rxp = /^([\w\s]+\w)/g;
			var rxpm = dbr.magic.match(rxp);
			if (rxpm) {
				console.log(rxpm);
				dbr.magicShort = rxpm[0];
			} else {
				dbr.magicShort = dbr.magic;
			}
			
			if (dbr.avresult != "OK") {
				dbr.avbadge = dbr.avresult;
			}
			
			dbr.yarabadges = [];
			if (dbr.yararesult) {
				dbr.yarabadges = Object.keys(dbr.yararesult);
			}
		});
		
		res.render('files', {
			files: dbres,
			mainmenu: mainmenu,
			prev: prv,
			next: nxt,
			title: options.conf.site.displayName
		});
	});
});

router.get('/:sha256', function(req,res,next) {
	var sd = req.params.sha256.substring(0,2);
	var fpath = path.join(filespath, sd, req.params.sha256);
	var fname = req.params.sha256 + ".bin";
	res.download(fpath, fname);
});

router.post('/new-suspect', type, function(req, res, next) {
	var suspect = functions.Hashes(req.file.path);
	var filemagic = new Promise((resolve, reject) => {
		var magic = new Magic();
		magic.detectFile(req.file.path, function(err, result) {
			if(err) {
				reject(err);
			}
			resolve(result);
		});		
	});
	var params = {
		host: '127.0.0.1',
		port: options.conf.clamav.port,
		negotiationMandatory: false,
		timeout: 1000
		};
	var connection = new Telnet();
	var cmd = 'SCAN ' + req.file.path;
	var scan = connection.connect(params)
	.then(function(){
		return connection.send(cmd);
	}, function(err) {
		console.log(err);
		return '';
	});
	var exif = new Promise((resolve, reject) => {
		exec(format("exiftool {path}", {path: req.file.path}), function(error, stdout, stderr) {
			if (error) {
				resolve({});
			} else {
				resolve(functions.exifParse(stdout));
			}
		});
	});
	
	Promise.all([suspect, filemagic, scan, exif])
	.then((values) => {
		var s = values[0];
		var m = values[1];
		var sc = values[2];
		var ex = values[3];
		
		sc = sc.replace(new RegExp("^[^:]+: ", ""), "").replace("\n", "");
		
		return db.new_suspect(s.sha256, s.sha1, s.md5, req.file.originalname, m, sc, ex)
		.then(function() {
			return s;
		});
	})
	.then(function(s) {
		var hd = s.sha256.substring(0,2);
		var fpdir = path.join(rootdir, 'suspects', hd);
		var finalpath = path.join(fpdir, s.sha256);
		if (!fs.existsSync(fpdir)) {
			fs.mkdirSync(fpdir);
		}
		if (fs.existsSync(finalpath)) {
			// no need to copy if it's already present - remove the original
			fs.unlinkSync(req.file.path);
			return s;
		} else {
			fs.renameSync(req.file.path, finalpath);
			return s;
		}
	})
	.then(function(s){
		res.redirect('/files?sha256=' + s.sha256 + '&upload=true&name=' + req.file.originalname);
	})
	.catch(function(err) {
		console.log(err);
		res.redirect('/files?upload=false');
	});
});

module.exports = router;