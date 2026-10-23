// Fonksiyonlar arası ölçüm (TS): Express işleyicileri, kaynaklar burada.
import express from 'express';
import { convert, safeConvert, ReportStore, preview, previewInternal, findUser, audit } from './js_ip_service';

const router = express.Router();
const store = new ReportStore('/srv/reports');

router.post('/convert', (req, res) => {
  convert(req.body.file, req.body.format);
  safeConvert(req.body.format);
  audit(req.body.note);
  audit('sabit');
  res.json({ ok: true });
});

router.get('/report', (req, res) => {
  res.send(store.read(req.query.name as string));
  res.send(store.readSafe(req.query.name as string));
});

router.get('/preview', async (req, res) => {
  await preview(req.query.url as string);
  await previewInternal(req.query.id as string);
  res.json({});
});

router.get('/user', async (req, res) => {
  const name = String(req.query.name);
  res.json(await findUser(db, name));
});

router.get('/go', (req, res) => {
  const next = req.query.next as string;
  if (next.startsWith('/') && !next.startsWith('//')) {
    return res.redirect(next);
  }
  res.redirect(next); // EXPECT: REDIRECT
});

router.get('/list', (req, res) => {
  const items = (req.query.items as string).split(',');
  items.forEach((item) => {
    res.write(`<li>${item}</li>`); // EXPECT: XSS
  });
  const count = items.length;
  res.end(`<p>${count}</p>`);
});

export default router;
