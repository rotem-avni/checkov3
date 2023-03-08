var crypto = require('crypto');
var salt = ''
crypto.DEFAULT_ENCODING = 'hex';
const key = crypto.scryptSync('password', salt, 64, { N: 1024 });
console.log(key);  // '3745e48...aa39b34'