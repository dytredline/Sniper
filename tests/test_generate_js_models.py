"""scripts/generate_js_models.py: @types/node imzalarından yayıcı / değer taşımayan API üretimi."""
import json
from pathlib import Path
import tempfile
import textwrap
import unittest

from scripts import generate_js_models as gen

import taint_models

_NODE = textwrap.dedent('''
    /** belge // yorum { } */
    declare module "path" {
        namespace path {
            interface PlatformPath {
                join(...paths: string[]): string;
                isAbsolute(path: string): boolean;
                parse(path: string): ParsedPath;
                readonly sep: "\\\\" | "/";
            }
        }
        const path: path.PlatformPath;
        export = path;
    }
    declare module "node:path" { export * from "path"; }
    declare module "fs" {
        export function existsSync(path: PathLike): boolean;
        export function readFileSync(path: PathLike, options?: { encoding?: null }): Buffer;
        export function access(path: PathLike, cb: (err: Error | null) => void): void;
        export function statSync(path: PathLike): Stats | undefined;
        export namespace promises {
            function readFile(path: PathLike): Promise<string>;
            function access(path: PathLike): Promise<void>;
        }
        export namespace exists {
            function __promisify__(path: PathLike): Promise<boolean>;
        }
    }
    declare module "assert" {
        function assert(value: unknown, message?: string): asserts value;
        namespace assert {
            function equal(actual: unknown, expected: unknown): void;
            function match(value: string, re: RegExp): void;
        }
        export = assert;
    }
    declare module "url" {
        function parse(urlString: string): UrlWithStringQuery;
        function parse(urlString: string, parseQuery: true): UrlWithParsedQuery;
        function canParse(input: string): boolean;
    }
''')
_QS = textwrap.dedent('''
    declare namespace QueryString {
        function stringify(obj: any, options?: IStringifyOptions<BooleanOptional>): string;
        function parse(str: string, options?: IParseOptions & { decoder?: never | undefined }): ParsedQs;
    }
''')


class GenerateJsModelsTests(unittest.TestCase):
    def test_scalar_returns_become_clean_and_others_propagate(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = Path(tmp) / "node"
            qs = Path(tmp) / "qs"
            node.mkdir()
            qs.mkdir()
            (node / "index.d.ts").write_text(_NODE, encoding="utf-8")
            (qs / "index.d.ts").write_text(_QS, encoding="utf-8")
            scalar, propagators = gen.generate(node, qs)
        self.assertEqual(scalar, [
            "assert.assert", "assert.equal", "assert.match", "fs.access", "fs.existsSync",
            "fs.promises.access", "path.isAbsolute", "url.canParse",
        ])
        self.assertEqual(propagators, [
            "fs.promises.readFile", "fs.readFileSync", "fs.statSync", "path.join", "path.parse",
            "qs.parse", "qs.stringify", "url.parse",
        ])

    def test_scalar_return_classification(self):
        for ret in ("boolean", "number | undefined", "Promise<void>", "asserts value", "value is string", "void"):
            self.assertTrue(gen.scalar_return(ret), ret)
        for ret in ("string", "Buffer", "string | false", "Promise<string>", "{ a: number }", "number[]"):
            self.assertFalse(gen.scalar_return(ret), ret)

    def test_generated_file_loads_and_is_well_formed(self):
        path = Path(taint_models.MODEL_DIR) / "javascript-node.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["language"], "javascript")
        self.assertIn("@types/node@", data["description"])
        names = set(data["sanitizers"][0]["names"])
        self.assertIn("fs.existsSync", names)
        self.assertNotIn("path.join", names)
        self.assertIn("path.join", data["propagators"])
        self.assertFalse(any("__" in name for name in names | set(data["propagators"])))
        models = taint_models.models_for("javascript")
        self.assertEqual(models.errors, [])
        self.assertEqual(models.sanitizer_kinds("fs.existsSync"), taint_models.KNOWN_KINDS)
        # Elle yazılmış arındırıcı (path.basename → yol) üretilmiş yayıcıyla ezilmez.
        self.assertEqual(models.sanitizer_kinds("path.basename"), frozenset({"path"}))


if __name__ == "__main__":
    unittest.main()
