const express = require('express');
const app = express();

app.get('/go', (req, res) => {
  res.redirect(req.query.next);
});
