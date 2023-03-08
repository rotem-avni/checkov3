
const {
  pbkdf2Sync,
} = await import('node:crypto');

const key = pbkdf2Sync('secret', '', 100000, 64, 'sha512');
console.log(key.toString('hex'));  // '3745e48...08d59ae'