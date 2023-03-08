import crypto from 'node:crypto';
crypto.DEFAULT_ENCODING = 'hex';
var salt = 'salt'
crypto.pbkdf2('secret', salt, 100000, 512, 'sha512', (err, derivedKey) => {
  if (err) throw err;
  console.log(derivedKey);  // '3745e48...aa39b34'
});
