import crypto from 'node:crypto';
crypto.DEFAULT_ENCODING = 'hex';
var salt = ''
crypto.scrypt('password', salt, 64, { N: 1024 }, (err, derivedKey) => {
  if (err) throw err;
  console.log(derivedKey.toString('hex'));  // '3745e48...aa39b34'
});