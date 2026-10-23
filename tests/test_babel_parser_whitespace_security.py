"""Vendored Babel tokenizer whitespace/comment lookahead security regressions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest

import taint_js_ast


ROOT = Path(__file__).resolve().parents[1]
PARSER = ROOT / "vendor" / "babel-parser" / "index.js"
PROVENANCE = ROOT / "vendor" / "babel-parser" / "SNIPER-PROVENANCE.txt"
NODE = shutil.which("node")


class BabelParserWhitespaceSecurityTests(unittest.TestCase):
    def test_patched_parser_digest_is_pinned_and_documented(self):
        digest = hashlib.sha256(PARSER.read_bytes()).hexdigest()
        self.assertEqual(digest, taint_js_ast.PARSER_SHA256)
        self.assertIn(digest, PROVENANCE.read_text(encoding="utf-8"))

    def test_polynomial_regex_lookahead_is_not_present(self):
        source = PARSER.read_text(encoding="utf-8")
        self.assertFalse(
            "skipWhiteSpace.test(this.input)" in source,
            "polynomial all-lines whitespace regex returned",
        )
        self.assertFalse(
            "skipWhiteSpaceInLine.test(this.input)" in source,
            "polynomial same-line whitespace regex returned",
        )
        self.assertIn("function skipSpaceAndComments", source)

    @unittest.skipUnless(NODE, "Node.js is required for the vendored parser runtime test")
    def test_comment_lookahead_semantics_and_adversarial_inputs(self):
        script = r"""
const fs = require("node:fs");
const crypto = require("node:crypto");
const Module = require("node:module");
const path = require("node:path");
const parserPath = process.argv[1];
const parser = require(parserPath);
const now = () => Number(process.hrtime.bigint()) / 1e6;

// Compile an in-memory test copy with a private Parser export so the two hardened
// lookahead methods themselves, rather than only the public parser, are exercised.
const instrumented = fs.readFileSync(parserPath, "utf8") + "\nexports.__SniperParser = Parser;\n";
const testModule = new Module(parserPath, module);
testModule.filename = parserPath;
testModule.paths = Module._nodeModulePaths(path.dirname(parserPath));
testModule._compile(instrumented, parserPath);
const Parser = testModule.exports.__SniperParser;

function scan(text, sameLine) {
  const instance = new Parser({}, text, new Map());
  return sameLine ? instance.nextTokenInLineStartSince(0) : instance.nextTokenStartSince(0);
}

const lookaheadCases = [
  ["  /*x*/ //y\nnext", false, 12],
  ["  /*x*/ //y\nnext", true, 11],
  ["  /*x\n*/next", false, 8],
  ["  /*x\n*/next", true, 2],
  ["/* unterminated", false, 0],
  ["\u00a0\u2028\ufeffnext", false, 3],
  ["\u00a0\u2028\ufeffnext", true, 1],
];
for (const [text, sameLine, expected] of lookaheadCases) {
  const actual = scan(text, sameLine);
  if (actual !== expected) throw new Error(`lookahead mismatch: ${actual} !== ${expected}`);
}

// Golden digest produced by the two upstream 7.29.9 regexes over this deterministic
// corpus. It preserves broad offset compatibility without shipping those regexes again.
let seed = 0x5eed1234;
const alphabet = [" ", "\t", "\n", "\r", "\u2028", "\u00a0", "/", "*", "a", "b"];
const digest = crypto.createHash("sha256");
const encodedOffset = Buffer.allocUnsafe(4);
let compatibilityChecks = 0;
function random() {
  seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  return seed;
}
for (let sample = 0; sample < 20000; sample++) {
  let text = "";
  const length = random() % 80;
  for (let index = 0; index < length; index++) text += alphabet[random() % alphabet.length];
  const instance = new Parser({}, text, new Map());
  for (let pos = 0; pos <= text.length; pos++) {
    for (const sameLine of [false, true]) {
      const offset = sameLine
        ? instance.nextTokenInLineStartSince(pos)
        : instance.nextTokenStartSince(pos);
      encodedOffset.writeUInt32LE(offset);
      digest.update(encodedOffset);
      compatibilityChecks++;
    }
  }
}

const program = parser.parse(`
  const first = 1;
  /* same-line block */ const second = 2;
  // line comment\r\n
  const third = first + second;
  type Box<T> = { value: T };
  const view = <Box<string>>{ value: "ok" };
`, { sourceType: "module", plugins: ["typescript"] });
if (program.program.body.length !== 5) throw new Error("comment/whitespace semantics changed");

const attacks = [
  "/*" + " /*".repeat(350000),
  "/*" + "a/*".repeat(350000),
];
const timingsMs = [];
for (const [index, text] of attacks.entries()) {
  const started = now();
  const offset = scan(text, index === 1);
  timingsMs.push(now() - started);
  if (offset !== 0) throw new Error(`unterminated comment skipped to ${offset}`);
}
process.stdout.write(JSON.stringify({
  body: program.program.body.length,
  lookaheadCases: lookaheadCases.length,
  compatibilityChecks,
  compatibilityDigest: digest.digest("hex"),
  timingsMs,
}));
"""
        run = subprocess.run(
            [NODE, "-e", script, str(PARSER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=8,
            check=False,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout)
        self.assertEqual(result["body"], 5)
        self.assertEqual(result["lookaheadCases"], 7)
        self.assertEqual(result["compatibilityChecks"], 1_919_032)
        self.assertEqual(
            result["compatibilityDigest"],
            "c194db03a743eafd9017ffdcc3fb33d3a6b35f7e308d4d99c489331d5024572a",
        )
        self.assertEqual(len(result["timingsMs"]), 2)
        self.assertTrue(all(value < 1_000 for value in result["timingsMs"]), result)


if __name__ == "__main__":
    unittest.main()
