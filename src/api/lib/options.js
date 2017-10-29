// © https://github.com/scherma
// contact http_error_418@unsafehex.com

var fs = require('fs');
var path = require('path');
var configPath = path.join(__dirname, 'config.json');

var parsed = JSON.parse(fs.readFileSync(configPath, 'UTF-8'));

exports.conf = parsed;