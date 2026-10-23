const serialize = require('node-serialize');
function load(cookie) {
  return serialize.unserialize(cookie);
}
