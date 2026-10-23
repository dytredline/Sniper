const express = require('express');
const app = express();

app.post('/calc', (req, res) => {
  const result = JSON.parse(req.body.expr);
  res.json({ result, two: eval('1 + 1') });
});
