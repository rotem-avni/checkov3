const fs = require('fs');

fs.writeFileSync("temp_programming.txt", "bla", {mode:fs.constants.S_IXUSR | fs.constants.S_IRUSR	});