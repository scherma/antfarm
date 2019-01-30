// MIT License © https://github.com/scherma
// contact http_error_418 @ unsafehex.com

var express = require('express');
var router = express.Router();
var mainmenu = require('../lib/mainmenu');
var options = require('../lib/options');
var functions = require('../lib/functions');
var moment = require('moment');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: options.conf.site.displayName, bodycontent: '', mainmenu: mainmenu});
});

router.get('/json/stats', function(req, res, next) {
  var since = moment().utc().subtract('7', 'days');
  if (req.query.since) {
    try {
      since = moment(req.query.since).startOf('day');
    } catch (err) {
      console.log(err);
    }
  }

  functions.SandboxStats(since)
  .then((stats) => {
    res.send(stats);
  });
});

module.exports = router;
