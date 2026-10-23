const express = require('express');
const app = express();

app.post('/calc', (req, res) => {
  const result = eval(req.body.expr);
  res.json({ result });
});
