const express = require('express');
const app = express();

const axios = require('axios');
app.get('/fetch', async (req, res) => {
  const r = await axios.get('https://api.example.com/search', { params: { q: req.query.q } });
  res.json(r.data);
});
