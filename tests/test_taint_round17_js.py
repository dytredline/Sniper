"""17. tur JS/TS modern çatılar (W1-JS). Olumlu ve olumsuz örnekler.

* React: bileşenler arası prop → ``dangerouslySetInnerHTML`` (prop adı bazında; arındırılmış / sabit prop temiz);
  URL durum kancaları (``useSearchParams`` / ``useParams`` / ``useLocation``; ``location.state`` kaynak değil);
* Next.js: sunucu eylemleri (``'use server'``), ``request.nextUrl``, rota ``{ params }``, sayfa ``searchParams``,
  ``getServerSideProps``, ``NextResponse.redirect`` (isteğin kendi adresine göreli yol temiz);
* Hono (``c.req.*`` kaynakları, ``c.html`` / ``c.redirect``; ``c.get()`` bağlam değişkeni kaynak değil),
  Fastify ``reply.type('text/html').send``, adı 'router'/'app' olmayan yönlendiriciler, ``db.prepare`` SQL;
* NestJS: ``ParseIntPipe`` ve ``ValidationPipe`` + class-validator ile doğrulanmış DTO alanları temiz;
* MCP sunucusu ``tool`` / ``registerTool`` argümanları, JWT anahtar geri çağrısının başlığı (``kid``).
"""
import os
from pathlib import Path
import sys
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_js_ast  # noqa: E402
from tests.test_taint_js_ast import NODE_ENV  # noqa: E402


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsRound17Tests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def results(self, files):
        results = taint_js_ast.analyze_files({k: _src(v) for k, v in files.items()})
        self.assertIsNotNone(results)
        return results

    def flows(self, files, filename):
        results = self.results(files)
        self.assertIn(filename, results, "ayrıştırılamadı")
        return sorted({(f.sink_kind, f.line) for f in results[filename].flows})

    def test_react_props_reach_dangerously_set_inner_html_by_name(self):
        files = {
            "src/Card.jsx": """
                import DOMPurify from 'dompurify';
                export function Card({ title, body }) {
                  return <div><h2>{title}</h2><div dangerouslySetInnerHTML={{ __html: body }} /></div>;
                }
                export function Raw(props) {
                  return <div dangerouslySetInnerHTML={{ __html: props.html }} />;
                }
                export function Clean(props) {
                  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(props.html) }} />;
                }
                export function Wrapper({ content }) {
                  return <section><Raw html={content} /></section>;
                }
            """,
            "src/Page.jsx": """
                import { useSearchParams, useLocation } from 'react-router-dom';
                import { Card, Raw, Clean, Wrapper } from './Card';
                export default function Page() {
                  const [params] = useSearchParams();
                  const q = params.get('q');
                  const { state } = useLocation();
                  return (<div>
                    <Card title={q} body={"<b>sabit</b>"} />
                    <Clean html={q} />
                    <Wrapper content={q} />
                    <Raw html={state} />
                  </div>);
                }
            """,
        }
        results = self.results(files)
        card = sorted({(f.sink_kind, f.line, f.source_file) for f in results["src/Card.jsx"].flows})
        # Yalnız Raw (Wrapper üzerinden, satır 6) — Card'ın gövdesi sabit, Clean arındırılmış, location.state kaynak değil.
        self.assertEqual(card, [("html", 6, "src/Page.jsx")])
        self.assertTrue(all(f.source_label != "§prop" for r in results.values() for f in r.flows))

    def test_next_server_actions_routes_and_pages(self):
        files = {
            "app/actions.ts": """
                'use server';
                import { exec } from 'child_process';
                export async function run(cmd: string) { exec(cmd); }
                function helper(x: string) { exec('echo ' + x); }
                export async function safe() { helper('sabit'); }
            """,
            "app/item/[id]/route.ts": """
                import fs from 'fs';
                import { NextResponse, NextRequest } from 'next/server';
                export async function GET(req: NextRequest, { params }) {
                  fs.readFileSync('/data/' + params.id);
                  const next = req.nextUrl.searchParams.get('next');
                  if (!next) return NextResponse.redirect(new URL('/login?from=' + req.nextUrl.pathname, req.url));
                  return NextResponse.redirect(new URL(next, req.url));
                }
            """,
            "app/search/page.tsx": """
                export default function Search({ searchParams }) {
                  return <div dangerouslySetInnerHTML={{ __html: searchParams.q }} />;
                }
            """,
            "pages/old.tsx": """
                import { exec } from 'child_process';
                export async function getServerSideProps(context) { exec('echo ' + context.query.n); return { props: {} }; }
                export default function Old() { return <p>x</p>; }
            """,
        }
        results = self.results(files)
        flows = {name: sorted({(f.sink_kind, f.line) for f in r.flows}) for name, r in results.items()}
        self.assertEqual(flows["app/actions.ts"], [("command", 3)])
        self.assertEqual(flows["app/item/[id]/route.ts"], [("path", 4), ("redirect", 7)])
        self.assertEqual(flows["app/search/page.tsx"], [("html", 2)])
        self.assertEqual(flows["pages/old.tsx"], [("command", 2)])

    def test_hono_fastify_and_named_routers(self):
        files = {
            "hono.ts": """
                import { Hono } from 'hono';
                import Database from 'better-sqlite3';
                const db = new Database('a.db');
                const books = new Hono();
                books.get('/s', (c) => {
                  const q = c.req.query('q');
                  db.prepare("SELECT * FROM b WHERE n = '" + q + "'").all();
                  const user = c.get('user');
                  c.html('<p>' + user + '</p>');
                  c.text(q);
                  return c.html('<p>' + q + '</p>');
                });
                books.get('/r', (c) => c.redirect(c.req.query('to')));
                books.get('/h', (c) => c.redirect('/home'));
            """,
            "fastify.js": """
                const fastify = require('fastify')();
                fastify.get('/a', async (request, reply) => {
                  reply.type('text/html').send(request.query.q);
                  reply.type('application/json').send('<p>' + request.query.q + '</p>');
                  reply.header('Content-Type', 'text/plain').send('<p>' + request.query.q);
                  reply.code(200).send({ a: request.query.q });
                });
            """,
            "users.js": """
                const express = require('express');
                const { exec } = require('child_process');
                const users = express.Router();
                users.get('/x', (req, res) => { exec('id ' + req.query.u); res.end(); });
            """,
        }
        results = self.results(files)
        flows = {name: sorted({(f.sink_kind, f.line) for f in r.flows}) for name, r in results.items()}
        self.assertEqual(flows["hono.ts"], [("html", 11), ("redirect", 13), ("sql", 7)])
        self.assertEqual(flows["fastify.js"], [("html", 3)])
        self.assertEqual(flows["users.js"], [("command", 4)])

    def test_nest_pipes_and_validated_dto_fields(self):
        files = {
            "src/main.ts": """
                import { ValidationPipe } from '@nestjs/common';
                export function setup(app) { app.useGlobalPipes(new ValidationPipe({ whitelist: true })); }
            """,
            "src/dto.ts": """
                import { IsInt, IsIn, IsString, IsNotEmpty } from 'class-validator';
                export class OrderDto {
                  @IsNotEmpty() @IsInt() id: number;
                  @IsIn(['asc', 'desc']) dir: string;
                  @IsString() name: string;
                }
            """,
            "src/orders.controller.ts": """
                import { Controller, Post, Get, Body, Param, ParseIntPipe } from '@nestjs/common';
                import { DataSource } from 'typeorm';
                import { OrderDto } from './dto';
                @Controller('orders')
                export class OrdersController {
                  constructor(private readonly ds: DataSource) {}
                  @Post()
                  list(@Body() dto: OrderDto) {
                    this.ds.query('SELECT * FROM o WHERE id = ' + dto.id + ' ORDER BY c ' + dto.dir);
                    return this.ds.query("SELECT * FROM o WHERE name = '" + dto.name + "'");
                  }
                  @Get(':id')
                  one(@Param('id', ParseIntPipe) id: number) { return this.ds.query('SELECT * FROM o WHERE id = ' + id); }
                }
            """,
        }
        self.assertEqual(self.flows(files, "src/orders.controller.ts"), [("sql", 10)])

    def test_mcp_tools_and_jwt_key_callback(self):
        files = {
            "server.ts": """
                import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
                import { z } from 'zod';
                import { exec } from 'child_process';
                import fs from 'fs';
                import path from 'path';
                const server = new McpServer({ name: 'p', version: '1' });
                server.tool('run', { cmd: z.string() }, async ({ cmd }) => { exec(cmd); return { content: [] }; });
                server.registerTool('read', { inputSchema: { p: z.string() } }, async ({ p }) => {
                  fs.readFileSync(p);
                  fs.readFileSync('/d/' + path.basename(p));
                  return { content: [] };
                });
                server.tool('ping', async (extra) => { exec('ping ' + extra.requestId); return { content: [] }; });
            """,
            "auth.js": """
                const jwt = require('jsonwebtoken');
                const fs = require('fs');
                function getKey(header, cb) { cb(null, fs.readFileSync('/keys/' + header.kid)); }
                const pub = fs.readFileSync('/keys/pub.pem');
                module.exports = (t) => { jwt.verify(t, getKey, () => {}); return jwt.verify(t, pub); };
            """,
        }
        results = self.results(files)
        flows = {name: sorted({(f.sink_kind, f.line) for f in r.flows}) for name, r in results.items()}
        self.assertEqual(flows["server.ts"], [("command", 7), ("path", 9)])
        self.assertEqual(flows["auth.js"], [("path", 3)])


if __name__ == "__main__":
    unittest.main()
