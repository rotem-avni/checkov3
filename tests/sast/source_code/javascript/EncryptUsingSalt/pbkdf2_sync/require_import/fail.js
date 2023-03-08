var crypto = require('crypto');
crypto.DEFAULT_ENCODING = 'hex';
const key = crypto.pbkdf2Sync('secret', '', 100000, 512, 'sha512');
console.log(key);  // '3745e48...aa39b34'
