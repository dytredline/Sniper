import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';

const root = new URL('../', import.meta.url);
const css = fs.readFileSync(new URL('static/ui-refresh.css', root), 'utf8');
const pages = ['index.html', 'login.html'].map(name => fs.readFileSync(new URL(`static/${name}`, root), 'utf8'));

test('every page exposes the five supported interface languages', () => {
  for (const html of pages) {
    for (const [locale, label] of [
      ['tr', 'Türkçe'], ['en', 'English'], ['ja', '日本語'], ['zh-CN', '简体中文'], ['ko', '한국어'],
    ]) {
      assert.match(html, new RegExp(`<option value="${locale}">${label}</option>`));
    }
  }
});

test('CJK typography and wrapping contracts are present', () => {
  for (const locale of ['ja', 'ko', 'zh-CN']) assert.ok(css.includes(`[lang="${locale}"]`), locale);
  assert.match(css, /line-break:\s*strict/);
  assert.match(css, /overflow-wrap:\s*anywhere/);
  assert.match(css, /\.hero-row h1/);
  assert.match(css, /\.nav-item/);
  assert.match(css, /\.ui-quick-link/);
});

test('mobile language control has a viewport-bounded width', () => {
  assert.match(css, /width:\s*min\(104px,28vw\)/);
  assert.match(css, /max-width:\s*104px/);
});
