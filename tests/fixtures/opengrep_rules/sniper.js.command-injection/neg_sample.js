const express = require('express');
const app = express();

const { execFile } = require('child_process');
app.get('/p', (req, res) => {
  execFile('ping', ['-c1', req.query.host], (e, out) => res.json({ out }));
});
