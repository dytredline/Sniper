from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

APP = Path(__file__).resolve().parents[1]
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import authz_routes  # noqa: E402
import memsafety_rust  # noqa: E402
import privacy_dataflow_auditor  # noqa: E402
from project_analyzer import analyze_project  # noqa: E402
import secret_intelligence_auditor  # noqa: E402
import taint_cfamily  # noqa: E402
import taint_flow  # noqa: E402
import taint_goruby  # noqa: E402


class RealWorldCorpusCalibrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.project = self.base / "repo"
        self.project.mkdir()
        self.allowed = (self.base.resolve(),)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_memsafety_rust_catches_cua_nv12_unchecked_slice_ptr_copy_and_allows_checked_slice(self) -> None:
        src = (
            "pub fn copy_nv12_unchecked(y: &[u8], dst: *mut u8, w: usize, h: usize, y_stride: usize, dst_stride: usize) {\n"
            "    if y_stride == dst_stride && y_stride == w {\n"
            "        unsafe {\n"
            "            std::ptr::copy_nonoverlapping(y.as_ptr(), dst, w * h);\n"
            "        }\n"
            "    }\n"
            "}\n\n"
            "pub fn copy_nv12_checked(y: &[u8], dst: *mut u8, w: usize, h: usize, y_stride: usize, dst_stride: usize) {\n"
            "    let needed = w * h;\n"
            "    if y.len() >= needed && y_stride == dst_stride && y_stride == w {\n"
            "        unsafe {\n"
            "            std::ptr::copy_nonoverlapping(y.as_ptr(), dst, needed);\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        findings = memsafety_rust.analyze_text(src, "videotoolbox.rs")
        unchecked_lines = [f.line for f in findings if f.kind == "overflow"]
        self.assertIn(4, unchecked_lines)
        self.assertNotIn(13, unchecked_lines)

    def test_privacy_auditor_ignores_apktool_health_result_and_flags_real_patient_health(self) -> None:
        benign = privacy_dataflow_auditor.audit_privacy_inline(
            'import logging\n'
            'logger = logging.getLogger(__name__)\n'
            'def check():\n'
            '    health_result = {"status": "ok"}\n'
            '    service_health = "ready"\n'
            '    logger.info("status %s %s", health_result, service_health)\n',
            filename="apktool_mcp.py",
        )
        self.assertNotIn("Sağlık", benign["pii_categories_detected"])
        self.assertEqual(benign["findings"], [])

        real_phi = privacy_dataflow_auditor.audit_privacy_inline(
            'import logging\n'
            'logger = logging.getLogger(__name__)\n'
            'def export_record(patient):\n'
            '    logger.warning("diagnosis=%s", patient.diagnosis)\n',
            filename="clinic.py",
        )
        self.assertIn("Sağlık", real_phi["pii_categories_detected"])
        self.assertGreaterEqual(len(real_phi["findings"]), 1)

    def test_authz_routes_recognizes_fastapi_security_get_user_id_and_inline_authorize_helper(self) -> None:
        src = (
            "from fastapi import APIRouter, Security\n"
            "router = APIRouter()\n\n"
            "def get_user_id() -> str:\n"
            "    return 'u1'\n\n"
            "def _authorize_team_management(ctx, team_id: str) -> None:\n"
            "    if not ctx:\n"
            "        raise PermissionError('denied')\n\n"
            "@router.post('/api/v1/blocks/{block_id}/execute')\n"
            "async def execute_block(block_id: str, user_id: str = Security(get_user_id)):\n"
            "    return {'ok': True}\n\n"
            "@router.put('/api/v1/agents/{agent_id}')\n"
            "async def update_agent(agent_id: str, user_id: str = Security(get_user_id)):\n"
            "    return {'ok': True}\n\n"
            "@router.delete('/api/v1/teams/{team_id}')\n"
            "async def delete_team(team_id: str, ctx=None):\n"
            "    _authorize_team_management(ctx, team_id)\n"
            "    return {'deleted': team_id}\n\n"
            "@router.delete('/api/v1/unprotected/{item_id}')\n"
            "async def delete_unprotected(item_id: str):\n"
            "    return {'deleted': item_id}\n"
        )
        res = authz_routes.analyze_sources([("routes.py", src)])
        unprotected_lines = {
            f["line"] for f in res["findings"]
            if "Korumasız hassas rota" in f["title"]
        }
        self.assertNotIn(12, unprotected_lines)
        self.assertNotIn(16, unprotected_lines)
        self.assertNotIn(20, unprotected_lines)
        self.assertIn(25, unprotected_lines)

    def test_taint_flow_nextcloud_origin_rewrite_sanitizes_ssrf_and_block_execute_dict_is_not_sql(self) -> None:
        nextcloud_code = (
            "from flask import Flask, request\n"
            "import httpx\n"
            "app = Flask(__name__)\n\n"
            "def _rewrite_to_nextcloud_host(raw_url: str) -> str:\n"
            "    return 'https://nextcloud.internal/dav'\n\n"
            "@app.post('/sync')\n"
            "def sync():\n"
            "    raw = request.args.get('url', '')\n"
            "    safe_url = _rewrite_to_nextcloud_host(raw)\n"
            "    return httpx.get(safe_url).text\n"
        )
        nc_analysis = taint_flow.analyze_python(nextcloud_code, filename="webdav.py")
        self.assertEqual([f for f in nc_analysis.flows if f.sink_kind == "ssrf"], [])

        autogpt_code = (
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n\n"
            "@app.post('/run')\n"
            "def run_block(block, db):\n"
            "    payload = {'input': request.args.get('x', '')}\n"
            "    block.execute(payload)\n"
            "    db.execute('SELECT * FROM items WHERE name = ' + request.args.get('x', ''))\n"
        )
        ag_analysis = taint_flow.analyze_python(autogpt_code, filename="executor.py")
        sql_lines = [f.line for f in ag_analysis.flows if f.sink_kind == "sql"]
        self.assertEqual(sql_lines, [8])

    def test_taint_goruby_pgx_context_first_arg_and_arity_filtering(self) -> None:
        go_src = (
            "package main\n\n"
            "import (\n"
            "    \"context\"\n"
            "    \"database/sql\"\n"
            "    \"net/http\"\n"
            ")\n\n"
            "type Querier struct{}\n"
            "func (q *Querier) Text(id string) string { return \"SELECT 1\" }\n\n"
            "type Dangerous struct{}\n"
            "func (d *Dangerous) Text(a, b, c string) string { return a + b + c }\n\n"
            "func HandleSafe(w http.ResponseWriter, r *http.Request, db *sql.DB, q *Querier) {\n"
            "    ctx := r.Context()\n"
            "    userParam := r.URL.Query().Get(\"id\")\n"
            "    _ = q.Text(userParam)\n"
            "    db.QueryRow(ctx, \"SELECT name FROM users WHERE id = $1\", userParam)\n"
            "}\n\n"
            "func HandleUnsafe(w http.ResponseWriter, r *http.Request, db *sql.DB) {\n"
            "    ctx := context.Background()\n"
            "    raw := r.URL.Query().Get(\"q\")\n"
            "    db.Query(ctx, \"SELECT * FROM users WHERE name = '\" + raw + \"'\")\n"
            "}\n"
        )
        res = taint_goruby.analyze_files({"repo.go": go_src}, "go")
        sql_lines = [f.line for f in res["repo.go"].flows if f.sink_kind == "sql"]
        self.assertNotIn(19, sql_lines)
        self.assertIn(25, sql_lines)

    def test_taint_cfamily_multiline_snprintf_numeric_format_is_not_sqli(self) -> None:
        c_src = (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "#include <sqlite3.h>\n"
            "void handle_http(sqlite3 *db) {\n"
            "    const char *req_input = getenv(\"QUERY_STRING\");\n"
            "    long long row_id = atoll(req_input);\n"
            "    char sql[256];\n"
            "    snprintf(sql, sizeof(sql),\n"
            "        \"SELECT name FROM nodes \"\n"
            "        \"WHERE id = %lld\",\n"
            "        row_id);\n"
            "    sqlite3_exec(db, sql, 0, 0, 0);\n"
            "}\n"
        )
        res = taint_cfamily.analyze_files({"store.c": c_src}, {})
        sql_flows = [f for f in res["store.c"].flows if f.sink_kind == "sql"]
        self.assertEqual(sql_flows, [])

    def test_secret_intelligence_ignores_llm_token_counters_and_no_api_key_sentinel(self) -> None:
        res = secret_intelligence_auditor.audit_secrets_inline(
            'prompt_tokens = "1234567890abcdef"\n'
            'api_key = "no_api_key_provided"\n'
            'client_secret = "not-used-at-runtime"\n',
            filename="llm_client.py",
        )
        self.assertEqual(res["finding_count"], 0)

    def test_project_analyzer_suppresses_comments_dts_and_calibrates_cicd_and_jwt(self) -> None:
        (self.project / "comment_eval.ts").write_text(
            "// Browser-rendered MCP App eval (PR 14):\n"
            "/* POST /exec (bearer) and sprintf(buf, \"%s\", x) */\n"
            "export const safeValue = 42;\n",
            encoding="utf-8",
        )
        (self.project / "types.d.ts").write_text(
            "export declare function eval(code: string): any;\n",
            encoding="utf-8",
        )
        (self.project / "Query.go").write_text(
            "package authz\n"
            "func Build(a, b string) string {\n"
            "    return AndQuery(a + b)\n"
            "}\n",
            encoding="utf-8",
        )
        (self.project / "jwt_verified.py").write_text(
            "import jwt\n"
            "from jwt import PyJWKClient\n"
            "def check_token(token: str, jwks_url: str):\n"
            "    hdr = jwt.get_unverified_header(token)\n"
            "    key = PyJWKClient(jwks_url).get_signing_key_from_jwt(token)\n"
            "    return jwt.decode(token, key.key, algorithms=['RS256'])\n",
            encoding="utf-8",
        )
        (self.project / "llm_metrics.py").write_text(
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def log_usage(prompt_tokens: int, completion_tokens: int, total_tokens: int):\n"
            "    logger.info('usage', prompt_tokens, completion_tokens, total_tokens)\n"
            "    api_key = 'no_api_key_provided'\n"
            "    return api_key\n",
            encoding="utf-8",
        )
        wf_dir = self.project / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "labeler.yml").write_text(
            "name: Labeler\n"
            "on:\n"
            "  pull_request_target:\n"
            "    types: [opened]\n"
            "jobs:\n"
            "  label:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/github-script@v7\n",
            encoding="utf-8",
        )
        (wf_dir / "self_hosted_pr.yml").write_text(
            "name: SelfHostedPR\n"
            "on: [pull_request]\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: [self-hosted, linux]\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: ./gradlew test\n",
            encoding="utf-8",
        )
        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        findings = result["findings"]
        files_with_exec = {f["file"] for f in findings if f["title"] == "Dinamik kod çalıştırma"}
        self.assertNotIn("comment_eval.ts", files_with_exec)
        self.assertNotIn("types.d.ts", files_with_exec)

        files_with_sqli = {f["file"] for f in findings if "SQL" in f["title"]}
        self.assertNotIn("Query.go", files_with_sqli)

        files_with_jwt = {f["file"] for f in findings if "JWT" in f["title"]}
        self.assertNotIn("jwt_verified.py", files_with_jwt)

        files_with_log = {f["file"] for f in findings if f["title"] == "Günlüğe hassas veri yazma olasılığı"}
        self.assertNotIn("llm_metrics.py", files_with_log)

        files_with_secret = {f["file"] for f in findings if f["title"] == "Kaynak kodda sabit sır olasılığı"}
        self.assertNotIn("llm_metrics.py", files_with_secret)

        prt_findings = [f for f in findings if f["title"] == "CI/CD iş akışında riskli pull_request_target tetikleyicisi"]
        self.assertEqual(len(prt_findings), 1)
        self.assertEqual(prt_findings[0]["severity"], "low")

        self_hosted_findings = [
            f for f in findings
            if f["title"] == "CI/CD iş akışında self-hosted runner üzerinde çatal (fork) PR kodu çalıştırma riski"
        ]
        self.assertEqual(len(self_hosted_findings), 1)
        self.assertEqual(self_hosted_findings[0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
