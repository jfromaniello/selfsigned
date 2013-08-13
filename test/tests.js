var assert = require('assert')
var forge = require('node-forge')
var generate = require('../index').generate

var pems = generate()

assert.ok(!!pems.private, 'has a private key')
assert.ok(!!pems.public, 'has a public key')
assert.ok(!!pems.cert, 'has a certificate')

var caStore = forge.pki.createCaStore()
caStore.addCertificate(pems.cert)
