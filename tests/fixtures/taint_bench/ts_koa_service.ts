import Router from '@koa/router';
import { exec } from 'child_process';

const router = new Router();

router.post('/convert', async (ctx) => {
  const file: string = ctx.request.body.file;
  const width = Number(ctx.request.body.width);
  exec(`convert ${file} -resize ${width} out.png`); // EXPECT: CMD
  exec(`convert input.png -resize ${width} out.png`);
  logger.info("convert width", width);
  logger.warn("convert file " + file); // EXPECT: LOGG-03
  ctx.body = { ok: true };
});

export default router;
