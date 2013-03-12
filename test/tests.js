var expect = require('chai').expect;
var selfsigned = require('../');
var fs = require('fs');
var path = require('path');
var exec = require('child_process').exec;
var rimraf = require('rimraf');

describe('selfsigned', function () {
  
  beforeEach(function (done) {
    fs.mkdir(path.join(__dirname, 'tmp'), function () {
      fs.unlink(path.join(__dirname, 'tmp', 'test.pem'), function () {
        fs.unlink(path.join(__dirname, 'tmp', 'test.key'), function () {
          done();
        });
      });
    });
  });

  afterEach(function () {
    rimraf.sync(path.join(__dirname, 'tmp'));
  });

  it('should fail it doesnt provide the subject', function (done) {
    selfsigned.generate({}, function (err) {
      expect(err.message).to.equal('subj is required');
      done();
    });    
  });
  
  var cmd = "(openssl x509 -noout -modulus -in test.pem | openssl md5 ;\\ " +
            "openssl rsa -noout -modulus -in test.key | openssl md5) | uniq";

  it('should generate valid private public keys', function (done) {
    selfsigned.generate({subj: '/CN=contoso.com' }, function (err, result) {
      if(err) return done(err);
      fs.writeFileSync(path.join(__dirname, 'tmp', 'test.key'), result.privateKey);
      fs.writeFileSync(path.join(__dirname, 'tmp', 'test.pem'), result.publicKey);
      exec(cmd, function (err, stdout) {
        if(err) return done(err);
        expect(stdout.trim().split('\n').length).to.equal(1);
        done();
      });
    });
  });
});