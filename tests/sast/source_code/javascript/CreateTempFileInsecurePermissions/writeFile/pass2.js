const fs = require('fs');
const mode = fs.constants.S_IXGRP | fs.constants.S_IRUSR
fs.writeFile("programming.txt", "bla", {mode});