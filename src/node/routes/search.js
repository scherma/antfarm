// MIT License © https://github.com/scherma
// contact http_error_418 @ unsafehex.com

var express = require('express');
var router = express.Router();
var db = require('../lib/database');
var options = require('../lib/options');
var functions = require('../lib/functions');
var mainmenu = require('../lib/mainmenu');

router.get('/', function(req, res, next) {
	res.render('search', {
		mainmenu: mainmenu
	});
});

router.post('/', function(req, res, next) {
	if (req.body.searchterm) {
		functions.SearchRawTerm(req.body.searchterm)
		.then((hits) => {
			console.log(hits.cases);
			res.render('searchresults', {
				mainmenu: mainmenu,
				results: hits
			});
		});
	}
});

module.exports = router;
