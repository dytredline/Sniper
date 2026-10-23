const express = require('express');
const app = express();

const fs = require('fs');
const path = require('path');
app.get('/f', (req, res) => {
  const data = fs.readFileSync(path.join('/srv/files', path.basename(req.query.name)));
  res.json({ size: data.length });
});
