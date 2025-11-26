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
const pems = await selfsigned.generate(attrs, { days: 365 });
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
  days: 30, // how long till expiry of the signed certificate (default: 365)
  notBeforeDate: new Date(), // The date before which the certificate should not be valid (default: now)
  algorithm: 'sha256', // sign the certificate with specified algorithm (default: 'sha1')
  extensions: [{ name: 'basicConstraints', cA: true }], // certificate extensions array
  clientCertificate: true, // generate client cert signed by the original key (default: false)
  clientCertificateCN: 'jdoe', // client certificate's common name (default: 'John Doe jdoe123')
  clientCertificateKeySize: 2048 // the size for the client private key in bits (default: 2048)
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

To override the default client CN of `John Doe jdoe123`:

```js
const pems = await selfsigned.generate(null, {
  clientCertificate: true,
  clientCertificateCN: 'FooBar'
});
```

## PKCS#7 Support

PKCS#7 formatting is available through a separate module for better tree-shaking:

```js
const selfsigned = require('selfsigned');
const { createPkcs7 } = require('selfsigned/pkcs7');

const pems = await selfsigned.generate(attrs, { days: 365 });
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
// Async/await
const pems = await selfsigned.generate(attrs, { days: 365 });

// Or with .then()
selfsigned.generate(attrs, { days: 365 })
  .then(pems => console.log(pems))
  .catch(err => console.error(err));
```

## License

MIT
