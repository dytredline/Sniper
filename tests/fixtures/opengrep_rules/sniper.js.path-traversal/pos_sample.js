const express = require('express');
const app = express();

const fs = require('fs');
app.get('/f', (req, res) => {
  const data = fs.readFileSync('/srv/files/' + req.query.name);
  res.json({ size: data.length });
});
