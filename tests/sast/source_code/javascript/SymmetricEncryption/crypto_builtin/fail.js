// createCipher is deprecated
let crypto = require('crypto');
let functionCipher = crypto.createCipher('des128', "Password")
let myHashedPassword = functionCipher.update("my private password in plain text", "utf8", "hex")
myHashedPassword += functionCipher.final("hex")