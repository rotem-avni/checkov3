const fs = require('fs');

fs.writeFile("programming.txt", "bla", {mode:fs.constants.S_IXUSR | fs.constants.S_IRUSR	});