const fs = require('fs');
const mode = fs.constants.S_IXGRP | fs.constants.S_IRUSR
fs.writeFileSync("temp_programming.txt", "bla", {mode});