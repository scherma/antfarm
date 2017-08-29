// © https://github.com/scherma
// contact http_error_418@unsafehex.com

var fs = require('fs');
var path = require('path');
var jsonpath = path.join(__dirname, 'mainmenu.json');

var mainmenu = JSON.parse(fs.readFileSync(jsonpath));

module.exports = mainmenu;