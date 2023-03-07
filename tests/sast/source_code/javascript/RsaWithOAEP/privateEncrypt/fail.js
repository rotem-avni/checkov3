crypto = require('crypto');        
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
            passphrase: 'top secret'
        }
    });

    // Creating private key file
    return keyPair.privateKey;
}

// Generate keys
let privateKey = generateKeyFiles();

// Creating a function to encrypt string
function encryptString (plaintext, privateKey) {
    privateKey = {
        key: privateKey,
        padding: crypto.constants.RSA_NO_PADDING,
        passphrase: 'top secret'
        }
        // privateEncrypt() method with its parameters
        const encrypted = crypto.privateEncrypt(
            privateKey, Buffer.from(plaintext));
            return encrypted.toString("base64");
}

// Defining a text to be encrypted
const plainText = "GfG";

// Defining encrypted text
const encrypted = encryptString(plainText, privateKey);