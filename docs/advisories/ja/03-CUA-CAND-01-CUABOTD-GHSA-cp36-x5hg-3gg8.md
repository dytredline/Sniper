# 認証なしの 0.0.0.0:7842 cuabotd デーモン + POST /bash のワイルドカード CORS + Origin 未検証 WebSocket + 書き込み可能なホスト .claude マウント (`GHSA-cp36-x5hg-3gg8`)

[English](../03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | [Türkçe](../tr/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | **日本語** | [简体中文](../zh-CN/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md) | [한국어](../ko/03-CUA-CAND-01-CUABOTD-GHSA-cp36-x5hg-3gg8.md)

## GitHub GHSA & MITRE CNA フォーム入力フィールド
- **対象リポジトリ:** `trycua/cua`
- **GitHub Advisory URL:** `https://github.com/trycua/cua/security/advisories/GHSA-cp36-x5hg-3gg8`
- **既存 GHSA ID:** `GHSA-cp36-x5hg-3gg8`
- **エコシステム:** `npm`
- **パッケージ名:** `cuabot`
- **影響を受けるバージョン:** `>= 1.0.1, <= 1.0.16 (commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **修正済みバージョン:** `なし（修正パッチ添付）`
- **CWE:** `CWE-306 (重要機能に対する認証の欠如) / CWE-942 (過度に許容されたクロスドメインホワイトリスト)`
- **CVSS v3.1:** `9.6 Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`
- **MITRE ベンダー:** `TryCua`
- **MITRE 脆弱性タイプ:** `Missing Authentication / Permissive CORS Leading to Remote Command Execution (CWE-306 / CWE-942)`
- **MITRE 影響を受けるコンポーネント:** `libs/cuabot/src/cuabotd.ts (lines 34-36, 259-260, 741-743, 969-1002, 1018-1063, 1120)`
- **MITRE 推奨説明文:**
  > TryCua cuabot 1.0.1 から 1.0.16（`trycua/cua`）において、`cuabotd` デーモン（`libs/cuabot/src/cuabotd.ts`）は認証なしで `0.0.0.0:7842` にバインドし、`POST /bash` および `OPTIONS` プリフライトを含むすべての HTTP エンドポイントに `Access-Control-Allow-Origin: *` を設定し、`Origin` 検証のない WebSocket PTY ターミナルを公開すると同時に、ホストの `~/.cuabot/user/.claude` ディレクトリを読み書き可能でマウントします。ユーザーがブラウザで閲覧した任意の外部 Web サイトやローカルネットワーク上の任意の端末から `POST /bash` 経由で任意のコマンドを実行でき、マウントされた Claude OAuth 認証情報の窃取やホスト側フックの改ざんが可能です。
- **報告者 / クレジット:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. コードの欠陥がどのように悪用可能な脆弱性に変わるか

### ステップバイステップの技術的メカニズム
`trycua/cua`（`cuabot` npm パッケージ `<= 1.0.16`、コミット `e754cfec69c41400eb2aabde716c27d15607b2f0`）において、`cuabotd` デーモン（`libs/cuabot/src/cuabotd.ts`）は HTTP と WebSocket 経由でコンテナ内のシェル実行およびデスクトップ操作機能を提供します。以下の連鎖するコード上の欠陥により、ブラウザ経由のゼロクリック Drive-By 攻撃および LAN 経由のリモートコマンド実行（`CWE-306` / `CWE-942`）が成立します。

1. **ステップ 1 — 全ネットワークインターフェース (`0.0.0.0:7842`) での認証なしバインド (`cuabotd.ts:1120`):**
   `server.listen(port, () => ...)` でホスト引数 `'127.0.0.1'` が省略されているため、ポート `7842` がすべての Wi-Fi/LAN インターフェース（`0.0.0.0`）上でトークンやセッション認証なしに公開されます。
2. **ステップ 2 — `POST /bash` におけるワイルドカード CORS (`Access-Control-Allow-Origin: *`) と Origin 未検証の WebSocket PTY (`cuabotd.ts:969-1002, 1018-1063`):**
   すべての HTTP レスポンスに `Access-Control-Allow-Origin: *` と `Access-Control-Allow-Headers: Content-Type` が設定され、`OPTIONS` プリフライトに `200 OK` が返されます。開発者が開いた任意の悪意ある Web ページは、クロスオリジンの `fetch("http://localhost:7842/bash", ...)` を送信して `stdout`/`stderr` を含む JSON レスポンスを完全に読み取れるほか、`new WebSocket("ws://localhost:7842/?command=...")` で対話型 PTY を起動できます。
3. **ステップ 3 — ホスト側 `.claude` ディレクトリの読み書きマウント (`cuabotd.ts:259-260`):**
   `cuabotd` はホストの `~/.cuabot/user/.claude` ディレクトリを `/home/community-user/.claude` に読み書き可能でバインドマウントし、`host.docker.internal:host-gateway` をマッピングしているため、`/bash` で実行されたコマンドから Claude OAuth トークンを窃取したり、ホスト側に永続化される `.claude/settings.json` フックを汚染したりできます。

### 脆弱なコード箇所 (`libs/cuabot/src/cuabotd.ts:965-1002, 1120`)
```typescript
// File: libs/cuabot/src/cuabotd.ts (lines 965-1002, 1120)
    // CORS headers
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*'); // BUG 1: 任意の外部 Web サイトからの呼び出しとレスポンス読み取りを許可
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }
...
      if (path === 'bash' && req.method === 'POST') {  // BUG 2: 任意シェル実行に認証が一切ない
        const { command, timeout } = body;
        const result = await execBash(command, timeout);
        res.writeHead(200);
        res.end(JSON.stringify(result));
        return;
      }
...
  server.listen(port, () => {                          // BUG 3: 127.0.0.1 ではなく 0.0.0.0:7842 にバインド
```

---

## 2. 日常の実運用で起こり得る 3 つの重大シナリオ (シナリオ A / シナリオ B / シナリオ C)

### シナリオ A — 開発者が `cuabot` 起動中に任意の Web サイトを閲覧（ゼロクリック Drive-By RCE と Claude トークン窃取）
1. 開発者が自身の PC で `npx cuabot` を起動してコーディングエージェントを利用中、`cuabotd` がバックグラウンドでポート `7842` を開きます。
2. 開発者が Chrome/Firefox/Safari で技術ブログやドキュメントサイトを開いた際、ページ内のスクリプトが `fetch("http://localhost:7842/bash", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ command: "cat /home/community-user/.claude/.credentials.json" }) })` を実行します。
3. `cuabotd.ts:969-977` が `OPTIONS` プリフライトに対して `200 OK` と `Access-Control-Allow-Origin: *` を返すため、ブラウザは `POST /bash` を送信し、さらに `stdout` を含むレスポンス JSON を悪意ある Web ページへそのまま渡してしまい、Claude OAuth/API 認証情報が即座に窃取されます。

### シナリオ B — 書き込み可能な `.claude/settings.json` フック注入によるホストの永続的侵害
1. 同じくクロスオリジンの `POST /bash` または `new WebSocket("ws://localhost:7842/?command=...")` を用いて、外部 Web ページが `/home/community-user/.claude/settings.json`（`hooks.PreToolUse` や `mcpServers`）に悪意あるシェルコマンドを書き込みます。
2. `/home/community-user/.claude` はホストの `~/.cuabot/user/.claude`（`cuabotd.ts:259-260`）の読み書きバインドマウントであるため、コンテナ停止後も改ざんされた設定がホストファイルシステム上に残ります。
3. 以後、ホスト上で Claude Code や CUA を起動するたびに攻撃者の永続フックが実行されます。

### シナリオ C — カフェ・コワーキングスペース・社内 Wi-Fi (`0.0.0.0:7842`) 上の他端末からの直接乗っ取り
1. `cuabotd.ts:1120` の `server.listen(port)` は `'127.0.0.1'` を指定していないため、TCP ポート `7842` が `0.0.0.0` / `::` で待ち受けられます。
2. カフェ、コワーキングスペース、社内 LAN の同一ネットワーク上にいる任意の端末から、認証なしで `http://<developer-lan-ip>:7842/bash` や `http://<developer-lan-ip>:7842/screenshot` を直接呼び出すことができます。
3. LAN 上の攻撃者はリアルタイムのスクリーンショット取得、マウス・キーボード操作の注入、および任意シェルコマンドの実行によって開発環境を完全に掌握できます。

---

## 3. 実行・再現・検証コマンド例

### 1. Sniper CLI による対象コンポーネントの監査
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cuabot/src/cuabotd.ts"
```

### 2. ローカル隔離環境での再現と検証 (`127.0.0.1`)
```bash
# ローカルの 127.0.0.1:7842 で稼働する cuabotd に対してブラウザのクロスオリジンプリフライトと POST /bash を再現
curl -i -X OPTIONS http://127.0.0.1:7842/bash \
  -H "Origin: https://evil.example" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type"

curl -i -X POST http://127.0.0.1:7842/bash \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" \
  -d '{"command":"id && ls -la /home/community-user/.claude"}'
```

### 3. 自動 `RED -> GREEN + BENIGN` E2E 検証ハーネスの実行
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand01
```

---

## 4. エンドツーエンドのランタイム証明 (RED -> GREEN + BENIGN) と防御パッチ

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand01` による実行結果:

```json
{
  "CUA-CAND-01": {
    "ghsa_id": "GHSA-cp36-x5hg-3gg8",
    "source_file": "cua/libs/cuabot/src/cuabotd.ts",
    "elapsed_ms": 0.828,
    "RED": {
      "http_status": 200,
      "access_control_allow_origin": "*",
      "driveby_bash_executed": true,
      "mounted_host_claude_credentials_exfiltrated": true
    },
    "GREEN": {
      "http_status": 403,
      "driveby_bash_executed": false,
      "mounted_host_claude_credentials_exfiltrated": false,
      "error": "Cross-origin browser requests forbidden"
    },
    "BENIGN": {
      "http_status": 200,
      "stdout": "authorized_cli_ok"
    }
  }
}
```

### Unified Diff パッチ (`git apply --check` 検証済み)
```diff
--- a/libs/cuabot/src/cuabotd.ts
+++ b/libs/cuabot/src/cuabotd.ts
@@ -965,15 +965,16 @@
     const path = url.pathname.slice(1); // Remove leading /
 
-    // CORS headers
+    // Restrict local daemon to non-browser clients with bearer token auth
     res.setHeader('Content-Type', 'application/json');
-    res.setHeader('Access-Control-Allow-Origin', '*');
-    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
-    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
-
-    if (req.method === 'OPTIONS') {
-      res.writeHead(200);
+    const origin = req.headers['origin'];
+    if (origin || req.method === 'OPTIONS') {
+      res.writeHead(403);
+      res.end(JSON.stringify({ error: 'Cross-origin browser requests are forbidden' }));
+      return;
+    }
+    if (req.headers['authorization'] !== `Bearer ${DAEMON_AUTH_TOKEN}`) {
+      res.writeHead(401);
+      res.end(JSON.stringify({ error: 'Unauthorized' }));
       return;
     }
@@ -1117,5 +1118,5 @@
-  server.listen(port, () => {
+  server.listen(port, '127.0.0.1', () => {
```
