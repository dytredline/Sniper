const crypto = require('crypto');
function h(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');
}
