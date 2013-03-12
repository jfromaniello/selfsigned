// openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -subj "/CN=contoso.auth0.com" -keyout contoso.key  -out contoso.cer

var async = require('async');
var tmp = require('tmp');
var exec = require('child_process').exec;
var fs = require('fs');

function generateTempFiles (callback) {
  async.parallel([
    tmp.file.bind(tmp),
    tmp.file.bind(tmp)
  ], function (err, results) {
    if(err) return callback(err);
    return callback(null, {
      tmpKeyFile: results[0][0],
      tmpPubFile: results[1][0]
    });    
  });
}

function executeCommand (options, tmpFiles, callback) {
  var command = 'openssl req -new -newkey rsa:2048';
  command += ' -days ' + options.days.toString();
  command += ' -nodes -x509';
  command += ' -subj "' + options.subj + '"';
  command += ' -keyout ' + tmpFiles.tmpKeyFile; 
  command += ' -out ' + tmpFiles.tmpPubFile;
  exec(command, callback);
}

function createResponse (tmpFiles, callback) {
  async.parallel([
    function (cb) { fs.readFile(tmpFiles.tmpKeyFile, cb); },
    function (cb) { fs.readFile(tmpFiles.tmpPubFile, cb); }
  ], function (err, files) {
    if (err) return callback(err);
    callback(null, {
      privateKey: files[0].toString(),
      publicKey:  files[1].toString()
    });
  });
}

exports.generate = function (options, callback) {
  if(!options.subj){
    return callback(new Error('subj is required'));
  }
  options.days = options.days || 30;
  
  generateTempFiles(function (err, files) {
    if (err) return callback(err);
    executeCommand(options, files, function (err) {
      if (err) return callback(err);
      createResponse(files, callback);
    });
  });
};