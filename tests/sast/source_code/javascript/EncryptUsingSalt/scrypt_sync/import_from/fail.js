// 3
import crypto from 'node:crypto';
crypto.DEFAULT_ENCODING = 'hex';
const key = crypto.scryptSync('password', '', 64, { N: 1024 });
console.log(key);  // '3745e48...aa39b34'