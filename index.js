// openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -subj "/CN=contoso.auth0.com" -keyout contoso.key  -out contoso.cer

var async = require('async');
var tmp = require('tmp');
var exec = require('child_process').exec;
var fs = require('fs');
var path = require('path');

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

  if (process.platform === 'win32') {
    command = '"' + path.join(__dirname, '/external/', process.arch, 'bin', 'openssl.exe') + '"' + command.replace(/^openssl/, '') +
              ' -config "' + path.join(__dirname, '/external/', process.arch, 'openssl.cnf') + '"';
    console.log(command);
  }

  exec(command, callback);
}

//openssl crl2pkcs7 -nocrl -certfile contoso1.crt -out contoso1.p7b
function createResponse (options, tmpFiles, callback) {
  async.parallel([
    function (cb) { fs.readFile(tmpFiles.tmpKeyFile, cb); },
    function (cb) { fs.readFile(tmpFiles.tmpPubFile, cb); },
    function (cb) {
      if (!options.pkcs7) return cb();
      var command;
      if (process.platform === 'win32') {
        command = '"' + path.join(__dirname, '/external/', process.arch, 'bin', 'openssl.exe') + '" crl2pkcs7 -nocrl -certfile ' + tmpFiles.tmpPubFile;
      } else {
        command = 'openssl crl2pkcs7 -nocrl -certfile ' + tmpFiles.tmpPubFile;
      }
      exec(command, function (err, stdout) {
        cb(err, stdout);
      });
    }
  ], function (err, files) {
    if (err) return callback(err);
    var result = {
      privateKey: files[0].toString(),
      publicKey:  files[1].toString()
    };
    if(options.pkcs7) {
      result.publicPkcs7Key = files[2];
    }
    callback(null, result);
  });
}

function removeTmpFiles (tmpFiles, callback) {
  async.parallel([
    function (cb) { fs.unlink(tmpFiles.tmpKeyFile, cb); },
    function (cb) { fs.unlink(tmpFiles.tmpPubFile, cb); }
  ], function (err) {
    if (err) return callback(err);
    callback(null);
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

      createResponse(options, files, function (err, result) {
        if(err) return callback(err);
        
        removeTmpFiles(files, function (err) {
          if(err) return callback(err);
          
          callback(null, result);
        });
      });
    });
  });
};