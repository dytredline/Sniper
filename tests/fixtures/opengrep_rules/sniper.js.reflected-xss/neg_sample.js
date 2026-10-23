const express = require('express');
const app = express();

const escapeHtml = require('escape-html');
app.get('/hi', (req, res) => {
  res.send('<h1>Merhaba ' + escapeHtml(req.query.name) + '</h1>');
});
