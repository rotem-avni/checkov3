// Node.js program to demonstrate the
// crypto.hkdf() function

// Importing crypto module
const {
  hkdf,
} = await import('node:crypto');

// getting derived key
// by using hkdf() method
var salt = 'salt'
const val = hkdf('sha512', 'key', salt,
						'info', 64, (err, derivedKey) => {

	// checking if any error is found
	if (err) throw err;

	// display the result
	console.log(Buffer.from(derivedKey).toString('hex'));
});
