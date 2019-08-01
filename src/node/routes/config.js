// MIT License © https://github.com/scherma
// contact http_error_418 @ unsafehex.com

var express = require('express');
var router = express.Router();
var db = require('../lib/database');
var options = require('../lib/options');
var functions = require('../lib/functions');
var mainmenu = require('../lib/mainmenu');

router.get('/', function(req, res, next) {
    functions.FilterConfig()
    .then((cf) => {
        res.render('config', {
            mainmenu: mainmenu,
            title: options.conf.site.displayName,
            config: cf
        });
    });
});

module.exports = router;