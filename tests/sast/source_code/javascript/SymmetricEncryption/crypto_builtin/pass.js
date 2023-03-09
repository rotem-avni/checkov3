// createCipher is deprecated
let crypto = require('crypto');
let functionCipher = crypto.createCipheriv('aes128', "Password")
let myHashedPassword = functionCipher.update("my private password in plain text", "utf8", "hex")
myHashedPassword += functionCipher.final("hex")