if (process.platform === 'win32') {
  console.error('Must be run on a Unix OS');
  exit(1);
}

var library = require('../package.json');
var fs = require('fs');
var telemetry = require('../src/version');
var execSync = require('child_process').execSync;
telemetry.version = library.version;
fs.writeFileSync('src/version.js', `// Generated file by ${process.env['USER']} on ${new Date()};\nmodule.exports = ${JSON.stringify(telemetry, null, 2)};`);
execSync('git add src/version.js');