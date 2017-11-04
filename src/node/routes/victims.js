// MIT License © https://github.com/scherma
// contact http_error_418 @ unsafehex.com

var express = require('express');
var router = express.Router();
var db = require('../lib/database');
var mainmenu = require('../lib/mainmenu');
var functions = require('../lib/functions');

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
			}
		}
		res.render('victims', {workers: workers, mainmenu: mainmenu});
	});
});

module.exports = router;