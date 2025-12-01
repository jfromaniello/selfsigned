# selfsigned

Generate self-signed X.509 certificates using Node.js native crypto.

## Install

```bash
npm install selfsigned
```

## Requirements

- **Node.js >= 15.6.0** (for native WebCrypto support)

## Usage

**Version 5.0 is async-only.** The `generate()` function now returns a Promise.

```js
const selfsigned = require('selfsigned');

const attrs = [{ name: 'commonName', value: 'contoso.com' }];
const pems = await selfsigned.generate(attrs);
console.log(pems);
```

### Output

```js
{
  private: '-----BEGIN PRIVATE KEY-----\n...',
  public: '-----BEGIN PUBLIC KEY-----\n...',
  cert: '-----BEGIN CERTIFICATE-----\n...',
  fingerprint: 'XX:XX:XX:...'
}
```

## Options

```js
const pems = await selfsigned.generate(null, {
  keySize: 2048, // the size for the private key in bits (default: 2048)
  notBeforeDate: new Date(), // start of certificate validity (default: now)
  notAfterDate: new Date('2026-01-01'), // end of certificate validity (default: notBeforeDate + 365 days)
  algorithm: 'sha256', // sign the certificate with specified algorithm (default: 'sha1')
  extensions: [{ name: 'basicConstraints', cA: true }], // certificate extensions array
  clientCertificate: true, // generate client cert (default: false) - can also be an options object
  ca: { key: '...', cert: '...' }, // CA key and cert for signing (default: self-signed)
  passphrase: 'secret' // encrypt the private key with a passphrase (default: none)
});
```

### Setting Custom Validity Period

Use `notBeforeDate` and `notAfterDate` to control certificate validity:

```js
// Using date-fns
const { addDays, addYears } = require('date-fns');

const pems = await selfsigned.generate(null, {
  notBeforeDate: new Date(),
  notAfterDate: addDays(new Date(), 30) // Valid for 30 days
});

// Or with vanilla JS
const notBefore = new Date();
const notAfter = new Date(notBefore);
notAfter.setFullYear(notAfter.getFullYear() + 2); // Valid for 2 years

const pems = await selfsigned.generate(null, {
  notBeforeDate: notBefore,
  notAfterDate: notAfter
});
```

### Supported Algorithms

- `sha1` (default)
- `sha256`
- `sha384`
- `sha512`

### Using Your Own Keys

You can avoid key pair generation by specifying your own keys:

```js
const pems = await selfsigned.generate(null, {
  keyPair: {
    publicKey: '-----BEGIN PUBLIC KEY-----...',
    privateKey: '-----BEGIN PRIVATE KEY-----...'
  }
});
```

### Encrypting the Private Key

You can encrypt the private key with a passphrase using AES-256-CBC:

```js
const pems = await selfsigned.generate(null, {
  passphrase: 'my-secret-passphrase'
});

// The private key will be in encrypted PKCS#8 format:
// -----BEGIN ENCRYPTED PRIVATE KEY-----
// ...
// -----END ENCRYPTED PRIVATE KEY-----
```

To use the encrypted key, provide the passphrase:

```js
const crypto = require('crypto');

// Decrypt the key
const privateKey = crypto.createPrivateKey({
  key: pems.private,
  passphrase: 'my-secret-passphrase'
});

// Or use directly with HTTPS server
const https = require('https');
https.createServer({
  key: pems.private,
  passphrase: 'my-secret-passphrase',
  cert: pems.cert
}, app).listen(443);
```

### Signing with a CA

You can generate certificates signed by an existing Certificate Authority instead of self-signed certificates. This is useful for development environments where you want browsers to trust your certificates.

```js
const fs = require('fs');
const selfsigned = require('selfsigned');

const pems = await selfsigned.generate([
  { name: 'commonName', value: 'localhost' }
], {
  algorithm: 'sha256',
  ca: {
    key: fs.readFileSync('/path/to/ca.key', 'utf8'),
    cert: fs.readFileSync('/path/to/ca.crt', 'utf8')
  }
});
```

The generated certificate will be signed by the provided CA and will include:
- Subject Alternative Name (SAN) extension with DNS name matching the commonName
- For `localhost`, an additional IP SAN for `127.0.0.1`
- Key Usage: digitalSignature, keyEncipherment
- Extended Key Usage: serverAuth, clientAuth

#### Using with mkcert

[mkcert](https://github.com/FiloSottile/mkcert) is a simple tool for making locally-trusted development certificates. Combining it with `selfsigned` provides an excellent developer experience:

- **No certificate files to manage** - generate trusted certificates on-the-fly at server startup
- **No git-ignored cert files** - nothing to store, share, or accidentally commit
- **Browsers trust the certificates automatically** - no security warnings during development

```js
const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const selfsigned = require('selfsigned');

// Get mkcert's CA (requires: brew install mkcert && mkcert -install)
const caroot = execSync('mkcert -CAROOT', { encoding: 'utf8' }).trim();

const pems = await selfsigned.generate([
  { name: 'commonName', value: 'localhost' }
], {
  algorithm: 'sha256',
  ca: {
    key: fs.readFileSync(path.join(caroot, 'rootCA-key.pem'), 'utf8'),
    cert: fs.readFileSync(path.join(caroot, 'rootCA.pem'), 'utf8')
  }
});

// Start server with browser-trusted certificate - no files written to disk
https.createServer({ key: pems.private, cert: pems.cert }, app).listen(443);
```

See [examples/https-server-mkcert.js](examples/https-server-mkcert.js) for a complete working example.

## Attributes

Attributes follow the X.509 standard:

```js
const attrs = [
  { name: 'commonName', value: 'example.org' },
  { name: 'countryName', value: 'US' },
  { shortName: 'ST', value: 'Virginia' },
  { name: 'localityName', value: 'Blacksburg' },
  { name: 'organizationName', value: 'Test' },
  { shortName: 'OU', value: 'Test' }
];
```

## Generate Client Certificates

For environments where servers require client certificates, you can generate client keys signed by the original (server) key:

```js
const pems = await selfsigned.generate(null, { clientCertificate: true });
console.log(pems);
```

Output includes additional client certificate fields:

```js
{
  private: '-----BEGIN PRIVATE KEY-----\n...',
  public: '-----BEGIN PUBLIC KEY-----\n...',
  cert: '-----BEGIN CERTIFICATE-----\n...',
  fingerprint: 'XX:XX:XX:...',
  clientprivate: '-----BEGIN PRIVATE KEY-----\n...',
  clientpublic: '-----BEGIN PUBLIC KEY-----\n...',
  clientcert: '-----BEGIN CERTIFICATE-----\n...'
}
```

### Client Certificate Options

The `clientCertificate` option can be `true` for defaults, or an options object for full control:

```js
const pems = await selfsigned.generate(null, {
  clientCertificate: {
    cn: 'jdoe',                              // common name (default: 'John Doe jdoe123')
    keySize: 4096,                           // key size in bits (default: 2048)
    algorithm: 'sha256',                     // signature algorithm (default: inherits from parent or 'sha1')
    notBeforeDate: new Date(),               // validity start (default: now)
    notAfterDate: new Date('2026-01-01')     // validity end (default: notBeforeDate + 1 year)
  }
});
```

Simple example with just a custom CN:

```js
const pems = await selfsigned.generate(null, {
  clientCertificate: { cn: 'FooBar' }
});
```

## PKCS#7 Support

PKCS#7 formatting is available through a separate module for better tree-shaking:

```js
const selfsigned = require('selfsigned');
const { createPkcs7 } = require('selfsigned/pkcs7');

const pems = await selfsigned.generate(attrs);
const pkcs7 = createPkcs7(pems.cert);
console.log(pkcs7); // PKCS#7 formatted certificate
```

You can also create PKCS#7 for client certificates:

```js
const pems = await selfsigned.generate(null, { clientCertificate: true });
const clientPkcs7 = createPkcs7(pems.clientcert);
```

## Migration from v4.x

Version 5.0 introduces breaking changes:

### Breaking Changes

1. **Async-only API**: The `generate()` function is now async and returns a Promise. Synchronous generation is no longer supported.
2. **No callback support**: Callbacks have been removed. Use `async`/`await` or `.then()`.
3. **Minimum Node.js version**: Now requires Node.js >= 15.6.0 (was >= 10).
4. **Dependencies**: Replaced `node-forge` with `@peculiar/x509` and `pkijs` (66% smaller bundle size).
5. **`days` option removed**: Use `notAfterDate` instead. Default validity is 365 days from `notBeforeDate`.

### Migration Examples

**Old (v4.x):**
```js
// Sync
const pems = selfsigned.generate(attrs, { days: 365 });

// Callback
selfsigned.generate(attrs, { days: 365 }, function(err, pems) {
  if (err) throw err;
  console.log(pems);
});
```

**New (v5.x):**
```js
// Async/await (default 365 days validity)
const pems = await selfsigned.generate(attrs);

// Custom validity with notAfterDate
const notAfter = new Date();
notAfter.setDate(notAfter.getDate() + 30); // 30 days
const pems = await selfsigned.generate(attrs, { notAfterDate: notAfter });

// Or with .then()
selfsigned.generate(attrs)
  .then(pems => console.log(pems))
  .catch(err => console.error(err));
```

## License

MIT
