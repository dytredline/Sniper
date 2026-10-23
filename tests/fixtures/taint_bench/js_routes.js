const express = require('express');
const userController = require('./js_controller');

const router = express.Router();
router.get('/users/search', userController.search);
router.post('/users', userController.create);
router.post('/items', (req, res) => {
  console.log("items: " + req.body.items.length);
  console.log("item name: " + req.body.name); // EXPECT: LOGG-03
  const { title } = req.body;
  console.log(`title=${title}`); // EXPECT: LOGG-03
  console.log("payload", JSON.stringify(req.body));
  res.json({ ok: true });
});
module.exports = router;
