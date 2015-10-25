Generate a self signed x509 certificate from node.js.

[![Build Status](https://travis-ci.org/jfromaniello/selfsigned.png)](https://travis-ci.org/jfromaniello/selfsigned)

## Install

```bash
  npm install selfsigned
```

## Usage

```js
var selfsigned = require('selfsigned');
var pems = selfsigned.generate({ subj: '/CN=contoso.com', days: 365 });
console.log(pems)
```

Will return the following like this:

```js
{ 
  private: '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQCBFMXMYS/+RZz6+qzv+xeqXPdjw4YKZC4y3dPhSwgEwkecrCTX\r\nsR6boue+1MjIqPqWggXZnotIGldfEN0kn0Jbh2vMTrTx6YwqQ8tceBPoyuuqcYBO\r\nOONAcKOB3MLnZbyOgVtbyT3j68JE5V/lx6LhpIKAgY0m5WIuaKrW6mvLXQIDAQAB\r\nAoGAU6ODGxAqSecPdayyG/ml9vSwNAuAMgGB0eHcpZG5i2PbhRAh+0TAIXaoFQXJ\r\naAPeA2ISqlTJyRmQXYAO2uj61FzeyDzYCf0z3+yZEVz3cO7jB5Pl6iBvzbxWuuuA\r\ncbJtWLhWtW5/jioc8F0EAzZ+lkC/XuVJdwKHDmwt2qvJO+ECQQD+dvo1g3Sz9xGw\r\n21n+fDG5i4128+Qh+JPgh5AeLuXSofc1HMHaOXcC6Wu/Cloh7QAD934b7W0A7VoD\r\ndLd/JLyFAkEAgdwjryyvdhy69e516IrPB3b+m4rggtntBlZREMrk9tOzeIucVO3W\r\ntKI3FHm6JebN2gVcG+rZ+FaDPo+ifJkW+QJBAPojrMwEACmUevB2f9246gxx0UsY\r\nbq6yM3No71OsWEEY8/Bi53CEQqg7Gq5+F6H33qcHmBEN8LQTngN9rY+vZh0CQBg0\r\nqJImii5B/LeK03+dICoMDDmCEYdSh9P+ku3GZBd+Lp3xqBpMmxDgi9PNPN2DwCs7\r\nhIfPpwGbXqtyqp7/CkECQB4OdY+2FbCciI473eQkTu310RMf8jElU63iwnx4R/XN\r\n/mgqN589OfF4SS0U/MoRzYk9jF9IAJN1Mi/571T+nw4=\r\n-----END RSA PRIVATE KEY-----\r\n',
  public: '-----BEGIN PUBLIC KEY-----\r\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCBFMXMYS/+RZz6+qzv+xeqXPdj\r\nw4YKZC4y3dPhSwgEwkecrCTXsR6boue+1MjIqPqWggXZnotIGldfEN0kn0Jbh2vM\r\nTrTx6YwqQ8tceBPoyuuqcYBOOONAcKOB3MLnZbyOgVtbyT3j68JE5V/lx6LhpIKA\r\ngY0m5WIuaKrW6mvLXQIDAQAB\r\n-----END PUBLIC KEY-----\r\n',
  cert: '-----BEGIN CERTIFICATE-----\r\nMIICjTCCAfagAwIBAgIBATANBgkqhkiG9w0BAQUFADBpMRQwEgYDVQQDEwtleGFt\r\ncGxlLm9yZzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQH\r\nEwpCbGFja3NidXJnMQ0wCwYDVQQKEwRUZXN0MQ0wCwYDVQQLEwRUZXN0MB4XDTEz\r\nMDgxMzA1NDAyN1oXDTE0MDgxMzA1NDAyN1owaTEUMBIGA1UEAxMLZXhhbXBsZS5v\r\ncmcxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxh\r\nY2tzYnVyZzENMAsGA1UEChMEVGVzdDENMAsGA1UECxMEVGVzdDCBnzANBgkqhkiG\r\n9w0BAQEFAAOBjQAwgYkCgYEAgRTFzGEv/kWc+vqs7/sXqlz3Y8OGCmQuMt3T4UsI\r\nBMJHnKwk17Eem6LnvtTIyKj6loIF2Z6LSBpXXxDdJJ9CW4drzE608emMKkPLXHgT\r\n6MrrqnGATjjjQHCjgdzC52W8joFbW8k94+vCROVf5cei4aSCgIGNJuViLmiq1upr\r\ny10CAwEAAaNFMEMwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAvQwJgYDVR0RBB8w\r\nHYYbaHR0cDovL2V4YW1wbGUub3JnL3dlYmlkI21lMA0GCSqGSIb3DQEBBQUAA4GB\r\nAC9hGQlDh8anNo1YDJdG2mYqOQ5uybJV++kixblGaOkoDROPsWepUpL6kMDUtbAM\r\n4uXTyFkvlUQSaQkhNgOY5w/BRIAkCIu6u4D4XcjlCdwFq6vcKMEuWTHMAlBWFla3\r\nXJZAPO10PHuDen7JeMOUf1Re7lRFtwfRGAvVYmrvYFKv\r\n-----END CERTIFICATE-----\r\n'
}
```

### Generate Client Certificates

If you are in an environment where servers require client certificates, you can generate client keys signed by the original (server) key.

```js
var selfsigned = require('selfsigned');
var pems = selfsigned.generate(null, { clientCertificate: true });
console.log(pems)
```

Which will generate the following:

```js
{ private: '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXQIBAAKBgQCgd/lGfk+0Yfgprcm0pJUiP6Hl3i4GDsGmstW3JBRsUNgE+RpT\r\nhLrDoxr0hvovXvdKLTUfRMkqLNVevv0EP6QP+2yG97FJ9IZb+DX3wHrTvMj3ngcf\r\nE5LpN632c8jK2TF9syozAuBnDiBmU27ys5mP4mf1OPmmZGfNADib85vWYQIDAQAB\r\nAoGASeESnlb3IUhdteqyS/3eP4dmZWuWaumOVM5PQONWl8vcuOVrLnqUdg/5EA24\r\nz+h8F+WaaIwFxeogTl/GI5edU5RrcMsX7yAJahGcV7NG8A1ajCCdlUXUJKKiahAI\r\nU3S9ej+8VCj93NwBtTgcTWDr24lyhZF7MCFpQ6qIoTFP58UCQQD0vx4etezlC5ba\r\nOWK7fLux8JhRsqOhhU7pMtnSc7kStCcXnkMMFgnCQOui5jh6CA9g1VeMGFppQ+00\r\ndh8NTEYrAkEAp9jUuOeXzobgV+f84V6eQ2FU+tB1EfsNSgSHIZRMsMUkVe+HOKed\r\nEyQzduuo8t/RUUmXKvGFtC6DU3t1cT37owJBAJnIOIm9b/NfO9M0uZfqwRkGfv7e\r\nizhjRfj7TaiRtBlPfzy04ZYHhuw61JSPqa7rv5Xtl0vcxXpdBv+utMYrRe8CQCnr\r\njbVgohmCtiU+W3ouF3jcpky+I38KJJeH6fgJAd5kXl7YI/2SXziYogHheaCvJagX\r\nqRmgmLQXqdT/0KUnxeECQQDR4c1sq8imgm82OpGElAZHxaSHQMwOWzo4E8E+XZCo\r\nV4tLzLjGKPwwdNTwGK+oxD3P7Qy1klnAowqj/URGkHE3\r\n-----END RSA PRIVATE KEY-----\r\n',
  public: '-----BEGIN PUBLIC KEY-----\r\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgd/lGfk+0Yfgprcm0pJUiP6Hl\r\n3i4GDsGmstW3JBRsUNgE+RpThLrDoxr0hvovXvdKLTUfRMkqLNVevv0EP6QP+2yG\r\n97FJ9IZb+DX3wHrTvMj3ngcfE5LpN632c8jK2TF9syozAuBnDiBmU27ys5mP4mf1\r\nOPmmZGfNADib85vWYQIDAQAB\r\n-----END PUBLIC KEY-----\r\n',
    cert: '-----BEGIN CERTIFICATE-----\r\nMIICjTCCAfagAwIBAgIBATANBgkqhkiG9w0BAQUFADBpMRQwEgYDVQQDEwtleGFt\r\ncGxlLm9yZzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQH\r\nEwpCbGFja3NidXJnMQ0wCwYDVQQKEwRUZXN0MQ0wCwYDVQQLEwRUZXN0MB4XDTE1\r\nMTAyNTEzNTIwNFoXDTE2MTAyNTEzNTIwNFowaTEUMBIGA1UEAxMLZXhhbXBsZS5v\r\ncmcxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxh\r\nY2tzYnVyZzENMAsGA1UEChMEVGVzdDENMAsGA1UECxMEVGVzdDCBnzANBgkqhkiG\r\n9w0BAQEFAAOBjQAwgYkCgYEAoHf5Rn5PtGH4Ka3JtKSVIj+h5d4uBg7BprLVtyQU\r\nbFDYBPkaU4S6w6Ma9Ib6L173Si01H0TJKizVXr79BD+kD/tshvexSfSGW/g198B6\r\n07zI954HHxOS6Tet9nPIytkxfbMqMwLgZw4gZlNu8rOZj+Jn9Tj5pmRnzQA4m/Ob\r\n1mECAwEAAaNFMEMwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAvQwJgYDVR0RBB8w\r\nHYYbaHR0cDovL2V4YW1wbGUub3JnL3dlYmlkI21lMA0GCSqGSIb3DQEBBQUAA4GB\r\nAA508xX8hPhSMcOvgPznM80On0IXBTB6NlnAGd2I89mYnNX2b7/vBt83xCvwcxwo\r\nVaksTm6JbrlPWQ9hQESSkjsXGOJuGQePndKA7z4NwlVTdNyXupAm+zfrYRguajij\r\n3xXyY1ulsjTHhRaFP8fh49rrbAo7RB9D6fydNzHaqLz3\r\n-----END CERTIFICATE-----\r\n',
      clientprivate: '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQC1EiQnN9GgPPOP5vm5XtJT1pQ7xeTI8/gTaGrCIV49HFWfVQ0h\r\nNVDbuhcKxTFlmnQLWolIxrSwRT5+T+UMiyrvMrErgQE2Tz/qbK7K+5Yl1yu2P39D\r\njdKwmIfBfacWisLxCE53/0WkMD+3uFu+h36Be0FWb+xmQuPHScQ0R1UbBQIDAQAB\r\nAoGAMUjEyl/pEMJGUQ6/PfNPMD6hjjto8EFnbnDnTfujGOMTcxDFSBqo7YWTK/1M\r\nWqlVmJmF8GcVWz0dq2e3olhm0MsOb+AWUsPhPTryXDnZLoJmZpyHYakLP2k7B3I7\r\nMmV2T7QNZY2d0THoAZ8tkO337LGuzZiuALa7Ix/fJGyJiykCQQDjH5+UZwcko/7T\r\nyQ/c2fHV0O1Sk3txyaVUPLB3QHcFBZRQaTIPzyjD6YITpy4+oE8iukZrlkrl+Hua\r\nCQp8d8+fAkEAzBealXUz7Z2ZC6DT1ISv1cVQpcRXYzveve3jOdsPrvJcBjWs4LCf\r\nTj0wACn8L14dirxnFHHBoKjogP/JjoDC2wJAeTcqcwidjlecLCnVtnf3ErdjwbuG\r\nmY8WFqQhRjP4kYyNwHC0UC2uwwh/7L8/9hqWwaEK7maS6LO6O9Zxa0aCXwJAabG/\r\nqK8t2VzIqbD8gw7EUR0CixaHeyjCTfIovwmnsZ5p8f1SLnrJxacCeNNFevJusi6n\r\n43qWIDHZVxUguOAOCQJBAIU/FDEVIc8h/mp2I5vufsMpYGsAMdMh03Wdg3dhxUaT\r\nlOXVzQehotFxyDayyyIr/S8V/SlG0nM7g4UJhKVQzbM=\r\n-----END RSA PRIVATE KEY-----\r\n',
        clientpublic: '-----BEGIN PUBLIC KEY-----\r\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1EiQnN9GgPPOP5vm5XtJT1pQ7\r\nxeTI8/gTaGrCIV49HFWfVQ0hNVDbuhcKxTFlmnQLWolIxrSwRT5+T+UMiyrvMrEr\r\ngQE2Tz/qbK7K+5Yl1yu2P39DjdKwmIfBfacWisLxCE53/0WkMD+3uFu+h36Be0FW\r\nb+xmQuPHScQ0R1UbBQIDAQAB\r\n-----END PUBLIC KEY-----\r\n',
          clientcert: '-----BEGIN CERTIFICATE-----\r\nMIICSzCCAbSgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBpMRQwEgYDVQQDEwtleGFt\r\ncGxlLm9yZzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQH\r\nEwpCbGFja3NidXJnMQ0wCwYDVQQKEwRUZXN0MQ0wCwYDVQQLEwRUZXN0MB4XDTE1\r\nMTAyNTEzNTIwNFoXDTE2MTAyNTEzNTIwNFowbjEZMBcGA1UEAxMQSm9obiBEb2Ug\r\namRvZTEyMzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQH\r\nEwpCbGFja3NidXJnMQ0wCwYDVQQKEwRUZXN0MQ0wCwYDVQQLEwRUZXN0MIGfMA0G\r\nCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1EiQnN9GgPPOP5vm5XtJT1pQ7xeTI8/gT\r\naGrCIV49HFWfVQ0hNVDbuhcKxTFlmnQLWolIxrSwRT5+T+UMiyrvMrErgQE2Tz/q\r\nbK7K+5Yl1yu2P39DjdKwmIfBfacWisLxCE53/0WkMD+3uFu+h36Be0FWb+xmQuPH\r\nScQ0R1UbBQIDAQABMA0GCSqGSIb3DQEBBQUAA4GBABvI/e+wpprXPTGp72SnoVPB\r\nKJ0AjZt2kYl69xl4KWw/PqN292l6Km/kkTbaPcG9QTjEyfYGCU73bgIp1htBPFcz\r\nssaYLXHtWxkTF6fYSgdR2uJFTWL0BVvr0x4ZS+7kyB7w82igqfL4NTP1XexcsqUx\r\n286cvNgatOWUjJ/Zr3jj\r\n-----END CERTIFICATE-----\r\n' }
```

To override the default client CN of `john doe jdoe123`, add another option for clientCertificateCN:

```js
var selfsigned = require('selfsigned');
var pems = selfsigned.generate(null, { clientCertificate: true, clientCertificateCN: "FooBar" });
console.log(pems)
```

## License

MIT
