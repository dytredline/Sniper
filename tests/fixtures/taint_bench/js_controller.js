const db = require('./db');
const logger = require('./logger');

exports.search = async (rq, rs) => {
  const name = rq.query.name;
  logger.info(`user search ${name}`); // EXPECT: LOGG-03
  const rows = await db.query( // EXPECT: SQL
    "SELECT * FROM users WHERE name = '" + name + "'"
  );
  const byId = await db.query("SELECT * FROM users WHERE id = $1", [rq.query.id]);
  const matcher = new RegExp(rq.query.pattern); // EXPECT: DOS-REGEX
  rs.json({ rows, byId, ok: matcher.test("x") });
};

exports.create = async (rq, rs) => {
  const { email, age } = rq.body;
  const contact = email;
  logger.info("created " + contact); // EXPECT: LOGG-03, LOGG-02
  logger.info("age bucket " + Math.floor(age / 10));
  await db.query("INSERT INTO users(email) VALUES ($1)", [email]);
  rs.sendStatus(201);
};
