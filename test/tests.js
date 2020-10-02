const assert = require('assert');
const forge = require('node-forge');
const fs = require('fs');
const exec = require('child_process').exec;

describe('generate', function () {

  const generate = require('../index').generate;

  it('should work without attrs/options', function (done) {
    const pems = generate();
    assert.ok(!!pems.private, 'has a private key');
    assert.ok(!!pems.fingerprint, 'has fingerprint');
    assert.ok(!!pems.public, 'has a public key');
    assert.ok(!!pems.cert, 'has a certificate');
    assert.ok(!pems.pkcs7, 'should not include a pkcs7 by default');
    assert.ok(!pems.clientcert, 'should not include a client cert by default');
    assert.ok(!pems.clientprivate, 'should not include a client private key by default');
    assert.ok(!pems.clientpublic, 'should not include a client public key by default');

    const caStore = forge.pki.createCaStore();
    caStore.addCertificate(pems.cert);
    done();
  });

  it('should generate client cert', function (done) {
    const pems = generate(null, { clientCertificate: true });

    assert.ok(!!pems.clientcert, 'should include a client cert when requested');
    assert.ok(!!pems.clientprivate, 'should include a client private key when requested');
    assert.ok(!!pems.clientpublic, 'should include a client public key when requested');
    done();
  });

  it('should include pkcs7', function (done) {
    const pems = generate([{ name: 'commonName', value: 'contoso.com' }], { pkcs7: true });

    assert.ok(!!pems.pkcs7, 'has a pkcs7');

    try {
      fs.unlinkSync('/tmp/tmp.pkcs7');
    } catch (er) { }

    fs.writeFileSync('/tmp/tmp.pkcs7', pems.pkcs7);
    exec('openssl pkcs7 -print_certs -in /tmp/tmp.pkcs7', function (err, stdout, stderr) {
      if (err) {
        return done(err);
      }

      const errorMessage = stderr.toString();
      if (errorMessage.length) {
        return done(new Error(errorMessage));
      }

      const expected = stdout.toString().replace(/\n/g, '\r\n'); //node-forge uses \r\n
      assert.strictEqual(
        `subject=/CN=contoso.com\r\nissuer=/CN=contoso.com\r\n` +
        pems.cert +
        '\r\n',
        expected
      );

      done();
    });
  });

  it('should support sha1 algorithm', function (done) {
    const pems_sha1 = generate(null, { algorithm: 'sha1' });
    assert.ok(forge.pki.certificateFromPem(pems_sha1.cert).siginfo.algorithmOid === forge.pki.oids['sha1WithRSAEncryption'], 'can generate sha1 certs');
    done();
  });

  it('should support sha256 algorithm', function (done) {
    const pems_sha256 = generate(null, { algorithm: 'sha256' });
    assert.ok(forge.pki.certificateFromPem(pems_sha256.cert).siginfo.algorithmOid === forge.pki.oids['sha256WithRSAEncryption'], 'can generate sha256 certs');
    done();
  });

  describe('with callback', function () {
    it('should work without attrs/options', function (done) {
      generate(function (err, pems) {
        if (err) done(err);
        assert.ok(!!pems.private, 'has a private key');
        assert.ok(!!pems.public, 'has a public key');
        assert.ok(!!pems.cert, 'has a certificate');
        assert.ok(!pems.pkcs7, 'should not include a pkcs7 by default');
        assert.ok(!pems.clientcert, 'should not include a client cert by default');
        assert.ok(!pems.clientprivate, 'should not include a client private key by default');
        assert.ok(!pems.clientpublic, 'should not include a client public key by default');
        done();
      });
    });

    it('should generate client cert', function (done) {
      generate(null, { clientCertificate: true }, function (err, pems) {
        if (err) done(err);
        assert.ok(!!pems.clientcert, 'should include a client cert when requested');
        assert.ok(!!pems.clientprivate, 'should include a client private key when requested');
        assert.ok(!!pems.clientpublic, 'should include a client public key when requested');
        done();
      });
    });

    it('should include pkcs7', function (done) {
      generate([{ name: 'commonName', value: 'contoso.com' }], { pkcs7: true }, function (err, pems) {
        if (err) done(err);
        assert.ok(!!pems.pkcs7, 'has a pkcs7');

        try {
          fs.unlinkSync('/tmp/tmp.pkcs7');
        } catch (er) { }

        fs.writeFileSync('/tmp/tmp.pkcs7', pems.pkcs7);
        exec('openssl pkcs7 -print_certs -in /tmp/tmp.pkcs7', function (err, stdout, stderr) {
          if (err) {
            return done(err);
          }

          const errorMessage = stderr.toString();
          if (errorMessage.length) {
            return done(new Error(errorMessage));
          }

          const expected = stdout.toString().replace(/\n/g, '\r\n'); //node-forge uses \r\n
          assert.strictEqual(
            `subject=/CN=contoso.com\r\nissuer=/CN=contoso.com\r\n` +
            pems.cert +
            '\r\n',
            expected
          );

          done();
        });
      });
    });

    it('should support sha1 algorithm', function (done) {
      generate(null, { algorithm: 'sha1' }, function (err, pems_sha1) {
        if (err) done(err);
        assert.ok(forge.pki.certificateFromPem(pems_sha1.cert).siginfo.algorithmOid === forge.pki.oids['sha1WithRSAEncryption'], 'can generate sha1 certs');
        done();
      });
    });

    it('should support sha256 algorithm', function (done) {
      generate(null, { algorithm: 'sha256' }, function (err, pems_sha256) {
        if (err) done(err);
        assert.ok(forge.pki.certificateFromPem(pems_sha256.cert).siginfo.algorithmOid === forge.pki.oids['sha256WithRSAEncryption'], 'can generate sha256 certs');
        done();
      });
    });
  });
});
