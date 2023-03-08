
const {
  scryptSync,
} = await import('node:crypto');

const key = scryptSync('password', 'salt', 64, { N: 1024 });
console.log(key.toString('hex'));  // '3745e48...08d59ae'
