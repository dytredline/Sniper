const cp = require('child_process');
const cmd = req.query.cmd;
cp.exec(cmd);
