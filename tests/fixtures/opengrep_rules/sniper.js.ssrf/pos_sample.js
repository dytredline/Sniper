const express = require('express');
const app = express();

const axios = require('axios');
app.get('/fetch', async (req, res) => {
  const r = await axios.get(req.query.url);
  res.json(r.data);
});
