var crypto = require('crypto');
crypto.DEFAULT_ENCODING = 'hex';
crypto.scrypt('password', '', 64, { N: 1024 }, (err, derivedKey) => {
  if (err) throw err;
  console.log(derivedKey.toString('hex'));  // '3745e48...aa39b34'
});