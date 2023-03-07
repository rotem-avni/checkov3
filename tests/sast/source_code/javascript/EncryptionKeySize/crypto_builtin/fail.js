const {
  randomBytes,
} = await import('node:crypto');

randomBytes(12, (err, buf) => {
  if (err) throw err;
  console.log(`${buf.length} bytes of random data: ${buf.toString('hex')}`);
});