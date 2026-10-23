const crypto = require('crypto');
function h(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex');
}
