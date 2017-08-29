// © https://github.com/scherma
// contact http_error_418@unsafehex.com

var express = require('express');
var router = express.Router();
var mainmenu = require('../lib/mainmenu');
var options = require('../lib/options');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: options.conf.site.displayName, bodycontent: '', mainmenu: mainmenu});
});

module.exports = router;
