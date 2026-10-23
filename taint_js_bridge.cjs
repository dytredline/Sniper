'use strict';
// Sniper taint analizi: JS/TS ayrıştırma köprüsü.
//
// Python bu betiği hash'ini doğruladıktan sonra `node -e <içerik>` ile çalıştırır.
// argv: [ayrıştırıcı yolu, ayrıştırıcı sha256]. Ayrıştırıcı bir kez okunur, aynı tampondan
// doğrulanır ve derlenir (kontrol ile kullanım arasında dosya değişemez).
// Protokol: stdin'den satır başına bir JSON istek {"id", "name", "text"}; stdout'a satır başına
// bir JSON yanıt {"id", "ast"} veya {"id", "error"}. Ağ, dosya yazma ve kod çalıştırma yoktur.
const crypto = require('crypto');
const fs = require('fs');
const Module = require('module');
const readline = require('readline');

const parserPath = process.argv[1];
const expected = process.argv[2];
const code = fs.readFileSync(parserPath);
if (crypto.createHash('sha256').update(code).digest('hex') !== expected) {
  process.stderr.write('ayrıştırıcı hash uyuşmuyor\n');
  process.exit(3);
}
const parserModule = new Module(parserPath);
parserModule.filename = parserPath;
parserModule._compile(code.toString('utf8'), parserPath);
const parser = parserModule.exports;

const DROP_KEYS = new Set([
  'start', 'end', 'loc', 'range', 'extra', 'comments', 'leadingComments', 'trailingComments',
  'innerComments', 'typeAnnotation', 'returnType', 'typeParameters', 'typeArguments',
  'superTypeParameters', 'superTypeArguments', 'implements', 'predicate', 'errors', 'tokens',
  'interpreter', 'directives',
]);
const DROP_TYPES = new Set([
  'TSInterfaceDeclaration', 'TSTypeAliasDeclaration', 'TSDeclareFunction', 'TSDeclareMethod',
  'DeclareFunction', 'TypeAlias', 'InterfaceDeclaration', 'OpaqueType', 'TSIndexSignature',
]);
const MAX_STRING = 4000;

function typeName(annotation) {
  let node = annotation && annotation.type === 'TSTypeAnnotation' ? annotation.typeAnnotation : annotation;
  if (node && node.type === 'TypeAnnotation') node = node.typeAnnotation;
  if (!node || typeof node !== 'object') return null;
  if (node.type === 'TSTypeReference' || node.type === 'GenericTypeAnnotation') {
    const ref = node.typeName || node.id;
    if (ref && ref.type === 'Identifier') return String(ref.name).slice(0, 120);
    if (ref && (ref.type === 'TSQualifiedName' || ref.type === 'QualifiedTypeIdentifier')) {
      const right = ref.right || ref.id;
      return right && right.name ? String(right.name).slice(0, 120) : null;
    }
  }
  return null;
}

function compact(node, depth) {
  if (depth > 1500) throw new Error('çok derin sözdizimi ağacı');
  if (Array.isArray(node)) {
    const out = [];
    for (const item of node) {
      if (item && typeof item === 'object' && DROP_TYPES.has(item.type)) continue;
      out.push(compact(item, depth + 1));
    }
    return out;
  }
  if (node === null || typeof node !== 'object') {
    return typeof node === 'string' && node.length > MAX_STRING ? node.slice(0, MAX_STRING) : node;
  }
  const out = {};
  for (const key of Object.keys(node)) {
    if (key === 'typeAnnotation') {
      // Tip açıklamasından yalnız tür adı (sınıf çözümü için): { tn: "Repo" }.
      const tn = typeName(node[key]);
      if (tn) out.tn = tn;
      continue;
    }
    if (key === 'directives') {
      // Yalnız yönerge metinleri ('use server' / 'use client'): { dirs: ['use server'] }.
      const dirs = (node[key] || []).map((d) => d && d.value && d.value.value).filter((v) => typeof v === 'string').slice(0, 8);
      if (dirs.length) out.dirs = dirs.map((v) => v.slice(0, 40));
      continue;
    }
    if (DROP_KEYS.has(key)) continue;
    const value = node[key];
    if (value === null || value === undefined || value === false) continue;
    if (key === 'value' && node.type === 'TemplateElement') {
      out.value = { cooked: value.cooked == null ? value.raw : value.cooked };
      continue;
    }
    if (key === 'value' && (typeof value === 'bigint')) continue;
    if (key === 'value' && node.type === 'RegExpLiteral') continue;
    out[key] = compact(value, depth + 1);
  }
  if (node.loc && node.loc.start) out.l = node.loc.start.line;
  return out;
}

function pluginsFor(name) {
  const lower = String(name || '').toLowerCase();
  if (/\.(ts|mts|cts)$/.test(lower)) return [['typescript', 'decorators-legacy']];
  if (/\.tsx$/.test(lower)) return [['typescript', 'jsx', 'decorators-legacy']];
  return [['jsx', 'decorators-legacy'], ['jsx', 'flow', 'decorators-legacy'], ['typescript', 'decorators-legacy']];
}

function parse(name, text) {
  let lastError = null;
  for (const plugins of pluginsFor(name)) {
    try {
      return parser.parse(text, {
        sourceType: 'unambiguous',
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
        allowImportExportEverywhere: true,
        allowUndeclaredExports: true,
        allowSuperOutsideMethod: true,
        errorRecovery: true,
        plugins,
      });
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError || new Error('ayrıştırılamadı');
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity, terminal: false });
rl.on('line', (line) => {
  let id = null;
  let response;
  try {
    const request = JSON.parse(line);
    id = request.id;
    const ast = parse(request.name, String(request.text));
    response = { id, ast: compact(ast.program, 0) };
  } catch (error) {
    response = { id, error: String((error && error.message) || error).slice(0, 300) };
  }
  process.stdout.write(JSON.stringify(response) + '\n');
});
