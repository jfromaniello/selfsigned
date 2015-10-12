var assert = require('assert')
var forge = require('node-forge')
var generate = require('../index').generate
var fs = require('fs');
var exec = require('child_process').exec;

var pems = generate()

assert.ok(!!pems.private, 'has a private key')
assert.ok(!!pems.public, 'has a public key')
assert.ok(!!pems.cert, 'has a certificate')
assert.ok(!pems.pkcs7, 'should not include a pkcs7 by default')


var caStore = forge.pki.createCaStore()
caStore.addCertificate(pems.cert)

//test pkcs7 generation
pems = generate(null, {pkcs7: true})

assert.ok(!!pems.pkcs7, 'has a pkcs7')

try{
  fs.unlinkSync('/tmp/tmp.crt')
}catch(er){}

fs.writeFileSync('/tmp/tmp.crt', pems.cert)
exec('openssl crl2pkcs7 -nocrl -certfile /tmp/tmp.crt', function (err, stdout, stderr) {
  var expected = stdout.toString()
                      .replace(/\n/g, '\r\n'); //node-forge uses \r\n
  assert.equal(pems.pkcs7, expected)
});

var pems_sha1 = generate(null, { algorithm: 'sha1' });
assert.ok(forge.pki.certificateFromPem(pems_sha1.cert).siginfo.algorithmOid == forge.pki.oids['sha1WithRSAEncryption'], 'can generate sha1 certs')

var pems_sha256 = generate(null, { algorithm: 'sha256' });
assert.ok(forge.pki.certificateFromPem(pems_sha256.cert).siginfo.algorithmOid == forge.pki.oids['sha256WithRSAEncryption'], 'can generate sha256 certs')

var pems_sha512 = generate(null, { algorithm: 'sha512' });
assert.ok(forge.pki.certificateFromPem(pems_sha512.cert).siginfo.algorithmOid == forge.pki.oids['sha512WithRSAEncryption'], 'can generate sha512 certs')
