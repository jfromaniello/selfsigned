const { X509CertificateGenerator, X509Certificate, X509ChainBuilder, BasicConstraintsExtension, KeyUsagesExtension, KeyUsageFlags, ExtendedKeyUsageExtension, ExtendedKeyUsage, SubjectAlternativeNameExtension, GeneralName } = require("@peculiar/x509");
const nodeCrypto = require("crypto");

// Use Node.js native webcrypto
const crypto = nodeCrypto.webcrypto;

// a hexString is considered negative if it's most significant bit is 1
// because serial numbers use ones' complement notation
// this RFC in section 4.1.2.2 requires serial numbers to be positive
// http://www.ietf.org/rfc/rfc5280.txt
function toPositiveHex(hexString) {
  var mostSiginficativeHexAsInt = parseInt(hexString[0], 16);
  if (mostSiginficativeHexAsInt < 8) {
    return hexString;
  }

  mostSiginficativeHexAsInt -= 8;
  return mostSiginficativeHexAsInt.toString() + hexString.substring(1);
}

function getAlgorithmName(key) {
  switch (key) {
    case "sha256":
      return "SHA-256";
    case 'sha384':
      return "SHA-384";
    case 'sha512':
      return "SHA-512";
    default:
      return "SHA-1";
  }
}

function getSigningAlgorithm(key) {
  const hashAlg = getAlgorithmName(key);
  return {
    name: "RSASSA-PKCS1-v1_5",
    hash: hashAlg
  };
}

// Convert attributes from node-forge format to X509 name format
function convertAttributes(attrs) {
  const nameMap = {
    'commonName': 'CN',
    'countryName': 'C',
    'ST': 'ST',
    'localityName': 'L',
    'organizationName': 'O',
    'OU': 'OU'
  };

  return attrs.map(attr => {
    const key = attr.name || attr.shortName;
    const oid = nameMap[key] || key;
    return `${oid}=${attr.value}`;
  }).join(', ');
}

// Convert PEM key to CryptoKey
async function importPrivateKey(pemKey, algorithm) {
  // Support both PKCS#8 and PKCS#1 (RSA) formats
  const pkcs8Match = pemKey.match(/-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/);
  const rsaMatch = pemKey.match(/-----BEGIN RSA PRIVATE KEY-----([\s\S]*?)-----END RSA PRIVATE KEY-----/);

  if (pkcs8Match) {
    const pemContents = pkcs8Match[1].replace(/\s/g, '');
    const binaryDer = Buffer.from(pemContents, 'base64');
    return await crypto.subtle.importKey(
      'pkcs8',
      binaryDer,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: getAlgorithmName(algorithm),
      },
      true,
      ['sign']
    );
  } else if (rsaMatch) {
    // PKCS#1 RSA key - need to convert using Node.js crypto
    const keyObject = nodeCrypto.createPrivateKey(pemKey);
    const pkcs8Pem = keyObject.export({ type: 'pkcs8', format: 'pem' });
    const pemContents = pkcs8Pem
      .replace(/-----BEGIN PRIVATE KEY-----/, '')
      .replace(/-----END PRIVATE KEY-----/, '')
      .replace(/\s/g, '');
    const binaryDer = Buffer.from(pemContents, 'base64');
    return await crypto.subtle.importKey(
      'pkcs8',
      binaryDer,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: getAlgorithmName(algorithm),
      },
      true,
      ['sign']
    );
  } else {
    throw new Error('Unsupported private key format. Expected PKCS#8 or PKCS#1 RSA key.');
  }
}

async function importPublicKey(pemKey, algorithm) {
  const pemContents = pemKey
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s/g, '');

  const binaryDer = Buffer.from(pemContents, 'base64');

  return await crypto.subtle.importKey(
    'spki',
    binaryDer,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: getAlgorithmName(algorithm),
    },
    true,
    ['verify']
  );
}

async function generatePemAsync(keyPair, attrs, options, ca) {
  const { privateKey, publicKey } = keyPair;

  // Generate serial number
  const serialBytes = crypto.getRandomValues(new Uint8Array(9));
  const serialHex = toPositiveHex(Buffer.from(serialBytes).toString('hex'));

  // Set up dates
  const notBefore = options.notBeforeDate || new Date();
  let notAfter;
  if (options.notAfterDate) {
    notAfter = options.notAfterDate;
  } else {
    notAfter = new Date(notBefore);
    notAfter.setDate(notAfter.getDate() + 365);
  }

  // Default attributes
  attrs = attrs || [
    {
      name: "commonName",
      value: "example.org",
    },
    {
      name: "countryName",
      value: "US",
    },
    {
      shortName: "ST",
      value: "Virginia",
    },
    {
      name: "localityName",
      value: "Blacksburg",
    },
    {
      name: "organizationName",
      value: "Test",
    },
    {
      shortName: "OU",
      value: "Test",
    },
  ];

  const subjectName = convertAttributes(attrs);
  const signingAlg = getSigningAlgorithm(options.algorithm);

  // Extract common name for SAN extension
  const commonNameAttr = attrs.find(attr => attr.name === 'commonName' || attr.shortName === 'CN');
  const commonName = commonNameAttr ? commonNameAttr.value : 'localhost';

  // Build extensions array
  const extensions = [
    new BasicConstraintsExtension(false, undefined, true),
    new KeyUsagesExtension(KeyUsageFlags.digitalSignature | KeyUsageFlags.keyEncipherment, true),
    new ExtendedKeyUsageExtension([ExtendedKeyUsage.serverAuth, ExtendedKeyUsage.clientAuth], false),
    new SubjectAlternativeNameExtension([
      { type: 'dns', value: commonName },
      ...(commonName === 'localhost' ? [{ type: 'ip', value: '127.0.0.1' }] : [])
    ], false)
  ];

  let cert;

  if (ca) {
    // Generate certificate signed by CA
    const caCert = new X509Certificate(ca.cert);
    const caPrivateKey = await importPrivateKey(ca.key, options.algorithm || "sha256");

    cert = await X509CertificateGenerator.create({
      serialNumber: serialHex,
      subject: subjectName,
      issuer: caCert.subject,
      notBefore: notBefore,
      notAfter: notAfter,
      signingAlgorithm: signingAlg,
      publicKey: publicKey,
      signingKey: caPrivateKey,
      extensions: extensions
    });
  } else {
    // Generate self-signed certificate
    cert = await X509CertificateGenerator.createSelfSigned({
      serialNumber: serialHex,
      name: subjectName,
      notBefore: notBefore,
      notAfter: notAfter,
      signingAlgorithm: signingAlg,
      keys: {
        privateKey: privateKey,
        publicKey: publicKey
      },
      extensions: extensions
    });
  }

  // Calculate fingerprint (SHA-1 hash of the certificate)
  const certRaw = cert.rawData;
  const fingerprintBuffer = await crypto.subtle.digest('SHA-1', certRaw);
  const fingerprint = Buffer.from(fingerprintBuffer)
    .toString('hex')
    .match(/.{2}/g)
    .join(':');

  // Export keys to PEM
  const privateKeyDer = await crypto.subtle.exportKey('pkcs8', privateKey);
  const publicKeyDer = await crypto.subtle.exportKey('spki', publicKey);

  let privatePem;
  if (options.passphrase) {
    // Encrypt the private key with the passphrase using Node.js crypto
    const keyObject = nodeCrypto.createPrivateKey({
      key: Buffer.from(privateKeyDer),
      format: 'der',
      type: 'pkcs8'
    });
    privatePem = keyObject.export({
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: options.passphrase
    });
  } else {
    privatePem =
      '-----BEGIN PRIVATE KEY-----\n' +
      Buffer.from(privateKeyDer).toString('base64').match(/.{1,64}/g).join('\n') +
      '\n-----END PRIVATE KEY-----\n';
  }

  const publicPem =
    '-----BEGIN PUBLIC KEY-----\n' +
    Buffer.from(publicKeyDer).toString('base64').match(/.{1,64}/g).join('\n') +
    '\n-----END PUBLIC KEY-----\n';

  const certPem = cert.toString('pem');

  const pem = {
    private: privatePem,
    public: publicPem,
    cert: certPem,
    fingerprint: fingerprint,
  };

  // Client certificate support
  if (options && options.clientCertificate) {
    // Parse clientCertificate options - can be boolean or object
    const clientOpts = typeof options.clientCertificate === 'object' ? options.clientCertificate : {};

    // Resolve client certificate options with fallbacks to deprecated options
    const clientKeySize = clientOpts.keySize || options.clientCertificateKeySize || 2048;
    const clientAlgorithm = clientOpts.algorithm || options.algorithm || "sha1";
    const clientCN = clientOpts.cn || options.clientCertificateCN || "John Doe jdoe123";

    const clientKeyPair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: clientKeySize,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: getAlgorithmName(clientAlgorithm),
      },
      true,
      ["sign", "verify"]
    );

    const clientSerialBytes = crypto.getRandomValues(new Uint8Array(9));
    const clientSerialHex = toPositiveHex(Buffer.from(clientSerialBytes).toString('hex'));

    // Resolve client certificate validity dates
    const clientNotBefore = clientOpts.notBeforeDate || new Date();
    let clientNotAfter;
    if (clientOpts.notAfterDate) {
      clientNotAfter = clientOpts.notAfterDate;
    } else {
      clientNotAfter = new Date(clientNotBefore);
      clientNotAfter.setFullYear(clientNotBefore.getFullYear() + 1);
    }

    const clientAttrs = JSON.parse(JSON.stringify(attrs));
    for (let i = 0; i < clientAttrs.length; i++) {
      if (clientAttrs[i].name === "commonName") {
        clientAttrs[i] = {
          name: "commonName",
          value: clientCN
        };
      }
    }

    const clientSubjectName = convertAttributes(clientAttrs);
    const issuerName = convertAttributes(attrs);

    // Signing algorithm for client cert (can differ from main cert)
    const clientSigningAlg = getSigningAlgorithm(clientAlgorithm);

    // Create client cert signed by root key
    const clientCertRaw = await X509CertificateGenerator.create({
      serialNumber: clientSerialHex,
      subject: clientSubjectName,
      issuer: issuerName,
      notBefore: clientNotBefore,
      notAfter: clientNotAfter,
      signingAlgorithm: clientSigningAlg,
      publicKey: clientKeyPair.publicKey,
      signingKey: privateKey // Sign with root private key
    });

    // Export client keys
    const clientPrivateKeyDer = await crypto.subtle.exportKey('pkcs8', clientKeyPair.privateKey);
    const clientPublicKeyDer = await crypto.subtle.exportKey('spki', clientKeyPair.publicKey);

    pem.clientprivate =
      '-----BEGIN PRIVATE KEY-----\n' +
      Buffer.from(clientPrivateKeyDer).toString('base64').match(/.{1,64}/g).join('\n') +
      '\n-----END PRIVATE KEY-----\n';

    pem.clientpublic =
      '-----BEGIN PUBLIC KEY-----\n' +
      Buffer.from(clientPublicKeyDer).toString('base64').match(/.{1,64}/g).join('\n') +
      '\n-----END PUBLIC KEY-----\n';

    pem.clientcert = clientCertRaw.toString('pem');
  }

  // Verify certificate chain
  const x509Cert = new X509Certificate(cert.rawData);
  const certificates = [x509Cert];

  // If CA-signed, include CA cert in the chain for verification
  if (ca) {
    const caCert = new X509Certificate(ca.cert);
    certificates.push(caCert);
  }

  const chainBuilder = new X509ChainBuilder({
    certificates: certificates
  });

  const chain = await chainBuilder.build(x509Cert);
  if (chain.length === 0) {
    throw new Error("Certificate could not be verified.");
  }

  return pem;
}

/**
 * Generate a certificate (async)
 *
 * @param {CertificateField[]} attrs Attributes used for subject.
 * @param {object} options
 * @param {number} [options.keySize=2048] the size for the private key in bits
 * @param {object} [options.extensions] additional extensions for the certificate
 * @param {string} [options.algorithm="sha1"] The signature algorithm sha256, sha384, sha512 or sha1
 * @param {Date} [options.notBeforeDate=new Date()] The date before which the certificate should not be valid
 * @param {Date} [options.notAfterDate] The date after which the certificate should not be valid (default: notBeforeDate + 365 days)
 * @param {boolean|object} [options.clientCertificate=false] Generate client cert signed by the original key. Can be `true` for defaults or an options object.
 * @param {number} [options.clientCertificate.keySize=2048] Key size for the client certificate in bits
 * @param {string} [options.clientCertificate.algorithm] Signature algorithm for client cert (defaults to options.algorithm or "sha1")
 * @param {string} [options.clientCertificate.cn="John Doe jdoe123"] Client certificate's common name
 * @param {Date} [options.clientCertificate.notBeforeDate=new Date()] The date before which the client certificate should not be valid
 * @param {Date} [options.clientCertificate.notAfterDate] The date after which the client certificate should not be valid (default: notBeforeDate + 1 year)
 * @param {string} [options.clientCertificateCN="John Doe jdoe123"] @deprecated Use options.clientCertificate.cn instead
 * @param {number} [options.clientCertificateKeySize] @deprecated Use options.clientCertificate.keySize instead
 * @param {object} [options.ca] CA certificate and key for signing (if not provided, generates self-signed)
 * @param {string} [options.ca.key] CA private key in PEM format
 * @param {string} [options.ca.cert] CA certificate in PEM format
 * @param {string} [options.passphrase] Passphrase to encrypt the private key (uses AES-256-CBC)
 * @returns {Promise<object>} Promise that resolves with certificate data
 */
exports.generate = async function generate(attrs, options) {
  attrs = attrs || undefined;
  options = options || {};

  const keySize = options.keySize || 2048;

  let keyPair;

  if (options.keyPair) {
    // Import existing key pair
    keyPair = {
      privateKey: await importPrivateKey(options.keyPair.privateKey, options.algorithm || "sha1"),
      publicKey: await importPublicKey(options.keyPair.publicKey, options.algorithm || "sha1")
    };
  } else {
    // Generate new key pair
    keyPair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: keySize,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: getAlgorithmName(options.algorithm || "sha1"),
      },
      true,
      ["sign", "verify"]
    );
  }

  return await generatePemAsync(keyPair, attrs, options, options.ca);
};
