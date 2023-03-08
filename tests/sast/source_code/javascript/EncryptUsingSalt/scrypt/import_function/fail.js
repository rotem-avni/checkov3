// // 1
const {
  scrypt,
} = await import('node:crypto');

scrypt('password', '', 64, { N: 1024 }, (err, derivedKey) => {
  if (err) throw err;
  console.log(derivedKey.toString('hex'));  // '3745e48...aa39b34'
});
