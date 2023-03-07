const fs = require('fs');
const mode = fs.constants.S_IXUSR;
const flags = 'w'
fs.open('temp_bla', flags, mode, function (err, f) {
    if (err) {
        return console.error(err);
    }
    console.log(f);
    console.log("File opened!!");
});