#!/usr/bin/env node

var selfsigned = require('./');
var pems = selfsigned.generate();
Object.keys(pems).forEach(function(type) {
  console.log(pems[type]);
});
