const express = require('express');
const app = express();

app.get('/u', (req, res) => {
  db.query('SELECT * FROM users WHERE name = ?', [req.query.name], (err, rows) => res.json(rows));
  db.query('SELECT * FROM users WHERE id = ' + parseInt(req.query.id, 10));
});
