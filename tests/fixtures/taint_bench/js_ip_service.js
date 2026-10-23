// Fonksiyonlar arası ölçüm (JS): hedefler burada, kaynaklar js_ip_routes.ts içinde.
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const ALLOWED_FORMATS = ['png', 'jpg'];

function convert(file, format) {
  if (!ALLOWED_FORMATS.includes(format)) {
    throw new Error('format');
  }
  exec(`convert ${file} out.${format}`); // EXPECT: CMD
}

function safeConvert(format) {
  if (!ALLOWED_FORMATS.includes(format)) {
    return;
  }
  exec(`convert input.png out.${format}`);
}

class ReportStore {
  constructor(root) {
    this.root = root;
  }

  read(name) {
    return fs.readFileSync(path.join(this.root, name), 'utf8'); // EXPECT: PATH
  }

  readSafe(name) {
    return fs.readFileSync(path.join(this.root, path.basename(name)), 'utf8');
  }
}

async function preview(url) {
  return axios.get(url); // EXPECT: SSRF
}

async function previewInternal(id) {
  return axios.get(`https://api.internal.example/items/${id}`);
}

function findUser(db, name) {
  return db.query("SELECT * FROM users WHERE name = '" + name + "'"); // EXPECT: SQL
}

function audit(message) {
  logger.info('audit ' + message); // EXPECT: LOGG-03
}

module.exports = { convert, safeConvert, ReportStore, preview, previewInternal, findUser, audit };
