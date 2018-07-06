// MIT License © https://github.com/scherma
// contact http_error_418 @ unsafehex.com

var express = require('express');
var router = express.Router();
var options = require('../lib/options');
var functions = require('../lib/functions');
var mainmenu = require('../lib/mainmenu');
const path = require('path');


router.get('/', function(req, res, next) {
	functions.GetCases(req).then((cases) => {
		cases.mainmenu = mainmenu;
		res.render('cases', cases);
	});
});

router.post('/start', function(req, res, next) {
	functions.Suspect(req.body.filename, req.body.sha256, fdir, req.body.interactive, req.body.banking, req.body.web, parseInt(req.body.reboots), parseInt(req.body.runtime))
	.then(function(suspect) {
		var s = db.new_case(suspect.uuid,
							suspect.submittime,
							suspect.hashes.sha256,
							suspect.fname,
							suspect.reboots,
							suspect.banking,
							suspect.web,
							suspect.runtime)
		.then(function() {
			return suspect;
		});
		return s;
	})
	.then(function(suspect) {
		res.redirect(format('/cases/view/{sha256}/{uuid}', {sha256: req.body.sha256, uuid: suspect.uuid}));
	})
	.catch(function(err) {
		console.log(err);
		res.redirect('/cases?error=true');
	});
	
});

router.get('/view/:sha256/:uuid', function(req,res,next) {
	functions.GetCase(req)
	.then((caseobj) => {
		caseobj.mainmenu = mainmenu;
		res.render("case", caseobj);
	});
});

router.get('/json/:sha256/:uuid', function(req, res, next) {
	functions.GetCase(req)
	.then((caseobj) => {
		res.send(caseobj);
	});
});

router.get('/:sha256/:uuid/pcap', function(req,res,next) {
	var sd = req.params.sha256.substring(0,2);
	var fpath = path.join(casesdir, sd, req.params.sha256, req.params.uuid, 'capture.pcap');
	var sha256 = req.params.sha256;
	var fname = sha256 + '-capture.pcap';
	res.download(fpath, fname);
});

router.get('/:sha256/delete/:uuid', function(req,res,next) {
	var cancel = "/cases";
	var c = {sha256: req.params.sha256, uuid: req.params.uuid};
	res.render('deletecase', {mainmenu: mainmenu, c: c, cancel: cancel, title: options.conf.site.displayName});
});

router.post('/:sha256/delete/:uuid', function(req,res,next) {
	var re = new RegExp('\\w{8}-\\w{4}-\\w{4}-\\w{4}-\\w{12}');
	if (!re.test(req.params.uuid)) {
		res.status(400);
		res.send('Invalid UUID');
	} else {
		if (req.body.purge) {
			var sd = req.params.sha256.substring(0,2);
			var casedir = path.join(casesdir, sd, req.params.sha256, req.params.uuid);
			var imagedir = path.join(rootdir, 'www', options.conf.site.name, 'public', 'images', 'cases', sd, req.params.uuid);
			functions.DeleteFolderRecursive(casedir);
			functions.DeleteFolderRecursive(imagedir);
		}
		db.delete_case(req.params.uuid)
		.then(res.redirect('/cases?sha256=' + req.params.sha256));
	}
});

router.get('/properties/:sha256/:uuid', function(req, res, next) {
	db.show_case(req.params.uuid)
	.then((result) => {
		res.status(200);
		res.send(result[0]);
	});
});

router.get('/runlog/:sha256/:uuid', function(req, res, next){
	functions.Runlog(req).then((result) => {
		res.status(200);
		res.send(result);
	});
});

module.exports = router;
