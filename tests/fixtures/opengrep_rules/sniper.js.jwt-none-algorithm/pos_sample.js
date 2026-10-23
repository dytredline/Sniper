const jwt = require('jsonwebtoken');
function check(tok, key) {
  return jwt.verify(tok, key, { algorithms: ['HS256', 'none'] });
}
