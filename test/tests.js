var { assert } = require('chai');
var fs         = require('fs');
var { promisify } = require('util');
var exec       = promisify(require('child_process').exec);
var crypto     = require('crypto');

describe('generate', function () {

  var generate = require('../index').generate;
  var { createPkcs7 } = require('../pkcs7');

  it('should work without attrs/options', async function () {
    var pems = await generate();
    assert.ok(!!pems.private, 'has a private key');
    assert.ok(!!pems.fingerprint, 'has fingerprint');
    assert.ok(!!pems.public, 'has a public key');
    assert.ok(!!pems.cert, 'has a certificate');
    assert.ok(!pems.pkcs7, 'should not include a pkcs7 by default');
    assert.ok(!pems.clientcert, 'should not include a client cert by default');
    assert.ok(!pems.clientprivate, 'should not include a client private key by default');
    assert.ok(!pems.clientpublic, 'should not include a client public key by default');

    // Verify cert can be read by Node.js crypto
    const cert = new crypto.X509Certificate(pems.cert);
    assert.ok(cert.subject, 'cert has a subject');
  });

  it('should generate client cert', async function () {
    var pems = await generate(null, {clientCertificate: true});

    assert.ok(!!pems.clientcert, 'should include a client cert when requested');
    assert.ok(!!pems.clientprivate, 'should include a client private key when requested');
    assert.ok(!!pems.clientpublic, 'should include a client public key when requested');
  });

  it('should include pkcs7', async function () {
    var pems = await generate([{ name: 'commonName', value: 'contoso.com' }]);
    var pkcs7 = createPkcs7(pems.cert);

    assert.ok(!!pkcs7, 'has a pkcs7');

    try {
      fs.unlinkSync('/tmp/tmp.pkcs7');
    } catch (er) {}

    fs.writeFileSync('/tmp/tmp.pkcs7', pkcs7);

    const { stdout, stderr } = await exec('openssl pkcs7 -print_certs -in /tmp/tmp.pkcs7');

    if (stderr && stderr.length) {
      throw new Error(stderr);
    }

    const expected = stdout.toString();
    let [ subjectLine,issuerLine, ...cert ] = expected.split(/\r?\n/).filter(c => c);
    cert = cert.filter(c => c);
    assert.match(subjectLine, /subject=\/?CN\s?=\s?contoso.com/i);
    assert.match(issuerLine, /issuer=\/?CN\s?=\s?contoso.com/i);
    // Normalize line endings for comparison
    const normalizedPemCert = pems.cert.replace(/\r\n/g, '\n').trim();
    const normalizedExpected = cert.join('\n').trim();
    assert.strictEqual(
      normalizedPemCert,
      normalizedExpected
    );
  });

  it('should support sha1 algorithm', async function () {
    var pems_sha1 = await generate(null, { algorithm: 'sha1' });
    const cert = new crypto.X509Certificate(pems_sha1.cert);
    // SHA-1 with RSA signature
    assert.ok(cert.publicKey, 'can generate sha1 certs');
  });

  it('should support sha256 algorithm', async function () {
    var pems_sha256 = await generate(null, { algorithm: 'sha256' });
    const cert = new crypto.X509Certificate(pems_sha256.cert);
    // SHA-256 with RSA signature
    assert.ok(cert.publicKey, 'can generate sha256 certs');
  });

  it('should default to 2048 bit keysize', async function () {
    var pems = await generate();
    const privateKey = crypto.createPrivateKey(pems.private);
    const keyDetails = privateKey.asymmetricKeyDetails;
    assert.strictEqual(keyDetails.modulusLength, 2048, 'default key size should be 2048 bits');
  });

  it('should default to 2048 bit keysize for client certificate', async function () {
    var pems = await generate(null, {clientCertificate: true});
    const clientPrivateKey = crypto.createPrivateKey(pems.clientprivate);
    const keyDetails = clientPrivateKey.asymmetricKeyDetails;
    assert.strictEqual(keyDetails.modulusLength, 2048, 'default client key size should be 2048 bits');
  });

  it('should support custom keySize', async function () {
    var pems = await generate(null, { keySize: 4096 });
    const privateKey = crypto.createPrivateKey(pems.private);
    const keyDetails = privateKey.asymmetricKeyDetails;
    assert.strictEqual(keyDetails.modulusLength, 4096, 'should support custom key size');
  });

  it('should support custom clientCertificateKeySize', async function () {
    var pems = await generate(null, {
      clientCertificate: true,
      clientCertificateKeySize: 4096
    });
    const clientPrivateKey = crypto.createPrivateKey(pems.clientprivate);
    const keyDetails = clientPrivateKey.asymmetricKeyDetails;
    assert.strictEqual(keyDetails.modulusLength, 4096, 'should support custom client key size');
  });

  it('should support sha384 algorithm', async function () {
    var pems = await generate(null, { algorithm: 'sha384' });
    const cert = new crypto.X509Certificate(pems.cert);
    assert.ok(cert.publicKey, 'can generate sha384 certs');
  });

  it('should support sha512 algorithm', async function () {
    var pems = await generate(null, { algorithm: 'sha512' });
    const cert = new crypto.X509Certificate(pems.cert);
    assert.ok(cert.publicKey, 'can generate sha512 certs');
  });

  it('should default to 365 days validity', async function () {
    var pems = await generate();
    const cert = new crypto.X509Certificate(pems.cert);

    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);
    const diffTime = Math.abs(validTo - validFrom);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    assert.approximately(diffDays, 365, 1, 'certificate should default to 365 days validity');
  });

  it('should respect notBeforeDate option', async function () {
    const customDate = new Date('2025-01-01T00:00:00Z');
    var pems = await generate(null, { notBeforeDate: customDate });
    const cert = new crypto.X509Certificate(pems.cert);

    const validFrom = new Date(cert.validFrom);
    // Allow small difference for processing time
    assert.approximately(validFrom.getTime(), customDate.getTime(), 5000, 'should use custom notBeforeDate');
  });

  it('should respect notAfterDate option', async function () {
    const notBefore = new Date('2025-01-01T00:00:00Z');
    const notAfter = new Date('2025-02-15T00:00:00Z');
    var pems = await generate(null, { notBeforeDate: notBefore, notAfterDate: notAfter });
    const cert = new crypto.X509Certificate(pems.cert);

    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);

    assert.approximately(validFrom.getTime(), notBefore.getTime(), 5000, 'should use custom notBeforeDate');
    assert.approximately(validTo.getTime(), notAfter.getTime(), 5000, 'should use custom notAfterDate');
  });

  it('should generate valid fingerprint format', async function () {
    var pems = await generate();
    assert.match(pems.fingerprint, /^[0-9a-f]{2}(:[0-9a-f]{2}){19}$/i, 'fingerprint should be valid SHA-1 format');
  });

  it('should support custom attributes', async function () {
    const attrs = [
      { name: 'commonName', value: 'test.example.com' },
      { name: 'countryName', value: 'GB' },
      { shortName: 'ST', value: 'London' },
      { name: 'localityName', value: 'Westminster' },
      { name: 'organizationName', value: 'Test Corp' },
      { shortName: 'OU', value: 'Engineering' }
    ];

    var pems = await generate(attrs);
    const cert = new crypto.X509Certificate(pems.cert);

    assert.include(cert.subject, 'CN=test.example.com', 'should include custom CN');
    assert.include(cert.subject, 'C=GB', 'should include custom country');
    assert.include(cert.subject, 'O=Test Corp', 'should include custom organization');
  });

  it('should support custom clientCertificateCN (deprecated)', async function () {
    var pems = await generate(null, {
      clientCertificate: true,
      clientCertificateCN: 'Custom User CN'
    });

    const clientCert = new crypto.X509Certificate(pems.clientcert);
    assert.include(clientCert.subject, 'CN=Custom User CN', 'should use custom client CN');
  });

  it('should support clientCertificate as options object with cn', async function () {
    var pems = await generate(null, {
      clientCertificate: {
        cn: 'Client Options CN'
      }
    });

    const clientCert = new crypto.X509Certificate(pems.clientcert);
    assert.include(clientCert.subject, 'CN=Client Options CN', 'should use cn from clientCertificate options');
  });

  it('should support clientCertificate.keySize', async function () {
    var pems = await generate(null, {
      clientCertificate: {
        keySize: 4096
      }
    });

    const clientPrivateKey = crypto.createPrivateKey(pems.clientprivate);
    const keyDetails = clientPrivateKey.asymmetricKeyDetails;
    assert.strictEqual(keyDetails.modulusLength, 4096, 'should use keySize from clientCertificate options');
  });

  it('should support clientCertificate.notBeforeDate and notAfterDate', async function () {
    const notBefore = new Date('2025-06-01T00:00:00Z');
    const notAfter = new Date('2025-06-30T00:00:00Z');

    var pems = await generate(null, {
      clientCertificate: {
        notBeforeDate: notBefore,
        notAfterDate: notAfter
      }
    });

    const clientCert = new crypto.X509Certificate(pems.clientcert);
    const validFrom = new Date(clientCert.validFrom);
    const validTo = new Date(clientCert.validTo);

    assert.approximately(validFrom.getTime(), notBefore.getTime(), 5000, 'should use notBeforeDate from clientCertificate options');
    assert.approximately(validTo.getTime(), notAfter.getTime(), 5000, 'should use notAfterDate from clientCertificate options');
  });

  it('should support clientCertificate.algorithm', async function () {
    var pems = await generate(null, {
      algorithm: 'sha1',  // main cert uses sha1
      clientCertificate: {
        algorithm: 'sha256'  // client cert uses sha256
      }
    });

    // Both certs should be valid
    const serverCert = new crypto.X509Certificate(pems.cert);
    const clientCert = new crypto.X509Certificate(pems.clientcert);
    assert.ok(serverCert.publicKey, 'server cert should be valid');
    assert.ok(clientCert.publicKey, 'client cert should be valid');
  });

  it('clientCertificate options should take precedence over deprecated options', async function () {
    var pems = await generate(null, {
      clientCertificateCN: 'Deprecated CN',
      clientCertificateKeySize: 2048,
      clientCertificate: {
        cn: 'New Options CN',
        keySize: 4096
      }
    });

    const clientCert = new crypto.X509Certificate(pems.clientcert);
    assert.include(clientCert.subject, 'CN=New Options CN', 'clientCertificate.cn should take precedence');

    const clientPrivateKey = crypto.createPrivateKey(pems.clientprivate);
    const keyDetails = clientPrivateKey.asymmetricKeyDetails;
    assert.strictEqual(keyDetails.modulusLength, 4096, 'clientCertificate.keySize should take precedence');
  });

  it('should generate valid key pair that work together', async function () {
    var pems = await generate();

    // Test data
    const testData = 'Hello, World!';

    // Create sign and verify objects
    const privateKey = crypto.createPrivateKey(pems.private);
    const publicKey = crypto.createPublicKey(pems.public);

    // Sign with private key
    const sign = crypto.createSign('SHA256');
    sign.update(testData);
    sign.end();
    const signature = sign.sign(privateKey);

    // Verify with public key
    const verify = crypto.createVerify('SHA256');
    verify.update(testData);
    verify.end();
    const isValid = verify.verify(publicKey, signature);

    assert.isTrue(isValid, 'public key should verify signature from private key');
  });

  it('should create client cert signed by server cert', async function () {
    var pems = await generate(null, { clientCertificate: true });

    const serverCert = new crypto.X509Certificate(pems.cert);
    const clientCert = new crypto.X509Certificate(pems.clientcert);

    // Client cert should have different subject than server
    assert.notEqual(clientCert.subject, serverCert.subject, 'client and server should have different subjects');

    // Both certs should be valid
    assert.ok(serverCert.publicKey, 'server cert should be valid');
    assert.ok(clientCert.publicKey, 'client cert should be valid');
  });

  it('should support using existing keyPair', async function () {
    // First generate a key pair
    const firstPems = await generate();

    // Reuse the key pair
    const secondPems = await generate(null, {
      keyPair: {
        privateKey: firstPems.private,
        publicKey: firstPems.public
      }
    });

    // Keys should be identical
    assert.strictEqual(firstPems.private, secondPems.private, 'should use provided private key');
    assert.strictEqual(firstPems.public, secondPems.public, 'should use provided public key');

    // Certificates will be different (different serial, dates) but keys are same
    const firstCert = new crypto.X509Certificate(firstPems.cert);
    const secondCert = new crypto.X509Certificate(secondPems.cert);
    assert.strictEqual(firstCert.publicKey.export({ format: 'pem', type: 'spki' }),
                       secondCert.publicKey.export({ format: 'pem', type: 'spki' }),
                       'certificates should contain the same public key');
  });

  it('should create PKCS#7 for client certificate', async function () {
    var pems = await generate([{ name: 'commonName', value: 'server.example.com' }], {
      clientCertificate: true
    });

    var clientPkcs7 = createPkcs7(pems.clientcert);
    assert.ok(!!clientPkcs7, 'should create PKCS#7 for client cert');
    assert.include(clientPkcs7, 'BEGIN PKCS7', 'should be valid PKCS#7 format');

    // Verify with openssl
    try {
      fs.unlinkSync('/tmp/tmp-client.pkcs7');
    } catch (er) {}

    fs.writeFileSync('/tmp/tmp-client.pkcs7', clientPkcs7);
    const { stdout, stderr } = await exec('openssl pkcs7 -print_certs -in /tmp/tmp-client.pkcs7');

    if (stderr && stderr.length) {
      throw new Error(stderr);
    }

    assert.ok(stdout.toString().length > 0, 'openssl should be able to read client PKCS#7');
  });

  it('should generate unique serial numbers', async function () {
    const pems1 = await generate();
    const pems2 = await generate();

    const cert1 = new crypto.X509Certificate(pems1.cert);
    const cert2 = new crypto.X509Certificate(pems2.cert);

    assert.notEqual(cert1.serialNumber, cert2.serialNumber, 'serial numbers should be unique');
  });

  it('should handle minimal attributes', async function () {
    const attrs = [{ name: 'commonName', value: 'minimal.test' }];
    var pems = await generate(attrs);

    const cert = new crypto.X509Certificate(pems.cert);
    assert.include(cert.subject, 'CN=minimal.test', 'should work with minimal attributes');
  });

  it('should support passphrase for private key encryption', async function () {
    const passphrase = 'my-secret-passphrase';
    var pems = await generate(null, { passphrase: passphrase });

    assert.ok(!!pems.private, 'has a private key');
    assert.include(pems.private, 'ENCRYPTED', 'private key should be encrypted');

    // Verify the key can be decrypted with the correct passphrase
    const privateKey = crypto.createPrivateKey({
      key: pems.private,
      passphrase: passphrase
    });
    assert.ok(privateKey, 'should be able to decrypt private key with passphrase');

    // Verify signing works with decrypted key
    const testData = 'Hello, World!';
    const sign = crypto.createSign('SHA256');
    sign.update(testData);
    sign.end();
    const signature = sign.sign({ key: pems.private, passphrase: passphrase });

    const verify = crypto.createVerify('SHA256');
    verify.update(testData);
    verify.end();
    const isValid = verify.verify(pems.public, signature);
    assert.isTrue(isValid, 'encrypted key should work for signing');
  });

  it('should fail to decrypt private key with wrong passphrase', async function () {
    const passphrase = 'correct-passphrase';
    var pems = await generate(null, { passphrase: passphrase });

    assert.throws(() => {
      crypto.createPrivateKey({
        key: pems.private,
        passphrase: 'wrong-passphrase'
      });
    });
  });
});
