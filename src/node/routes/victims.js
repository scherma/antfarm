// MIT License © https://github.com/scherma
// contact http_error_418 @ unsafehex.com

var express = require('express');
var router = express.Router();
var db = require('../lib/database');
var mainmenu = require('../lib/mainmenu');
var functions = require('../lib/functions');
var options = require('../lib/options');

router.get('/', function(req, res, next) {
	db.list_workers()
	.then(function(workers){
		if (workers) {
			for (w = 0; w < workers.length; w++) {
				if (!workers[w].position) {
					workers[w].position = "offline";
				}
				if (workers[w].params) {
					workers[w].parsedparams = functions.workerDisplayParams(JSON.parse(workers[w].params));
				}
				var workerStateOpts = ["pre-prod", "production", "maintenance"];
				var optslist = '';
				workerStateOpts.forEach((opt) => {
					if (workers[w].status == opt) {
						optslist = optslist + `<option value="${opt}" selected>${opt}</option>\n`;
					} else {
						optslist = optslist + `<option value="${opt}">${opt}</option>\n`;
					}
				});
				workers[w].selectopts = optslist;
			}
		}
		res.render('victims', {workers: workers, mainmenu: mainmenu, title: options.conf.site.displayName});
	});
});

router.post('/:uuid/status', function(req, res, next) {
	db.set_victim_status(req.params.uuid, req.body.status)
	.then((result) => {
		res.sendStatus(200);
	});
});

module.exports = router;