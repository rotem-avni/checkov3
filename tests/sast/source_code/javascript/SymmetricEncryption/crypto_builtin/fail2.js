const {
  createCipheriv,
} = await import('node:crypto');

let functionCipher = createCipheriv('des128', "Password")
let myHashedPassword = functionCipher.update("my private password in plain text", "utf8", "hex")
myHashedPassword += functionCipher.final("hex")