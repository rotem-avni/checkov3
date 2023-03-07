// Node.js program to demonstrate the
// crypto.publicEncrypt() method

// Including crypto and fs module
const crypto = require('crypto');
const fs = require("fs");

// Using a function generateKeyFiles
function generateKeyFiles() {

	const keyPair = crypto.generateKeyPairSync('rsa', {
		modulusLength: 520,
		publicKeyEncoding: {
			type: 'spki',
			format: 'pem'
		},
		privateKeyEncoding: {
		type: 'pkcs8',
		format: 'pem',
		cipher: 'aes-256-cbc',
		passphrase: ''
		}
	});

	// Creating public key file
	fs.writeFileSync("public_key", keyPair.publicKey);
}

// Generate keys
generateKeyFiles();

// Creating a function to encrypt string
function encryptString (plaintext, publicKeyFile) {
    var publicKey = fs.readFileSync(publicKeyFile, "utf8");

    // publicEncrypt() method with its parameters
        publicKey = {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    }

    const encrypted = crypto.publicEncrypt(
        publicKey, Buffer.from(plaintext));
    return encrypted.toString("base64");
}

// Defining a text to be encrypted
const plainText = "GfG";

// Defining encrypted text
const encrypted = encryptString(plainText, "./public_key");

// Prints plain text
console.log("Plaintext:", plainText);

// Prints encrypted text
console.log("Encrypted: ", encrypted);
