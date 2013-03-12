var expect = require('chai').expect;
var selfsigned = require('../');
var fs = require('fs');
var path = require('path');
var exec = require('child_process').exec;
var rimraf = require('rimraf');

describe('selfsigned', function () {
  
  beforeEach(function () {
    rimraf.sync(path.join(__dirname, 'tmp'));
    fs.mkdirSync(path.join(__dirname, 'tmp'));
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
  

  it('should generate valid private public keys', function (done) {
    var cmd = "(openssl x509 -noout -modulus -in test.pem | openssl md5 ;\\ " +
              "openssl rsa -noout -modulus -in test.key | openssl md5) | uniq";
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


  it('should generate a valid pkcs7', function (done) {
    var cmd = "(openssl pkcs7 -noout -modulus -in test.pb7 | openssl md5 ;\\ " +
              "openssl rsa -noout -modulus -in test.key | openssl md5) | uniq";

    selfsigned.generate({subj: '/CN=contoso.com', pkcs7: true }, 
      function (err, result) {
        if(err) return done(err);
        fs.writeFileSync(path.join(__dirname, 'tmp', 'test.key'), result.privateKey);
        fs.writeFileSync(path.join(__dirname, 'tmp', 'test.pb7'), result.publicPkcs7Key);
        exec(cmd, function (err, stdout) {
          if(err) return done(err);
          expect(stdout.trim().split('\n').length).to.equal(1);
          done();
        });
      });
  });
});