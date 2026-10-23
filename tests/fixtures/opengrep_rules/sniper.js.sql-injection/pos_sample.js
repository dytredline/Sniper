const express = require('express');
const app = express();

app.get('/u', (req, res) => {
  const q = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  db.query(q, (err, rows) => res.json(rows));
});
