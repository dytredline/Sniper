const express = require('express');
const app = express();

const { exec } = require('child_process');
app.get('/p', (req, res) => {
  exec('ping -c1 ' + req.query.host, (e, out) => res.send(out));
});
