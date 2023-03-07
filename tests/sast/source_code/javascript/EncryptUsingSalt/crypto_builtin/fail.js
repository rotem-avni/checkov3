// Node.js program to demonstrate the
// crypto.hkdf() function

// Importing crypto module
const crypto = require('crypto')

// getting derived key
// by using hkdf() method
const val = crypto.hkdf('sha512', 'key', '',
						'info', 64, (err, derivedKey) => {

	// checking if any error is found
	if (err) throw err;

	// display the result
	console.log(Buffer.from(derivedKey).toString('hex'));
});
