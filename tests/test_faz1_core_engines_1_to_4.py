"""Faz 1.1 – 1.4 ve Faz 2 R8 çekirdek motorlarının birim testleri (RED/GREEN doğrulamalı)."""

from __future__ import annotations

import unittest

from cross_lang_bridge_auditor import audit_cross_language_monorepo_bridges
from http_tls_semantics_auditor import audit_http_redirect_and_tls_semantics
from sibling_parity_auditor import audit_sibling_security_parity
from symlink_archive_auditor import audit_symlink_toctou_and_archive_semantics
from taint_flow import has_interprocedural_helper_path_guard


class TestFaz1CoreEngines1To4(unittest.TestCase):
    # --- Faz 1.1: Sibling Security Parity Auditor ---

    def test_sibling_parity_rails_controllers_red_and_green(self) -> None:
        red_files = {
            "app/controllers/oauth/authorizations_controller.rb": (
                "class Oauth::AuthorizationsController < ApplicationController\n"
                "  before_action :verify_confirmed_email!\n"
                "  before_action :enforce_organization_maintenance_mode\n"
                "end\n"
            ),
            "app/controllers/oauth/device_authorizations_controller.rb": (
                "class Oauth::DeviceAuthorizationsController < ApplicationController\n"
                "  def index; end\n"
                "end\n"
            ),
        }
        red_res = audit_sibling_security_parity(red_files)
        self.assertEqual(red_res["format"], "sniper-sibling-security-parity/1")
        rule_ids = [f["rule_id"] for f in red_res["findings"]]
        self.assertIn("SNIPER-PARITY-RAILS-01", rule_ids)

        green_files = {
            "app/controllers/oauth/authorizations_controller.rb": red_files[
                "app/controllers/oauth/authorizations_controller.rb"
            ],
            "app/controllers/oauth/device_authorizations_controller.rb": (
                "class Oauth::DeviceAuthorizationsController < ApplicationController\n"
                "  before_action :verify_confirmed_email!\n"
                "  before_action :enforce_organization_maintenance_mode\n"
                "  def index; end\n"
                "end\n"
            ),
        }
        green_res = audit_sibling_security_parity(green_files)
        self.assertEqual(green_res["finding_count"], 0)

    def test_sibling_parity_service_authz_and_except_red_and_green(self) -> None:
        red_svc = (
            "class UpdateService\n"
            "  def filter_consumers(consumers)\n"
            "    ItemConsumersFinder.new(current_user).execute.select { |c| Ability.allowed?(current_user, :read, c) }\n"
            "  end\n"
            "  def resolve_version\n"
            "    item.item_version\n"
            "  end\n"
            "  def build_servers\n"
            "    dynamic_servers.except(:orbit).merge(gitlab: static_gitlab_server)\n"
            "  end\n"
            "end\n"
        )
        red_res = audit_sibling_security_parity(red_svc, filename="update_service.rb")
        rule_ids = [f["rule_id"] for f in red_res["findings"]]
        self.assertIn("SNIPER-PARITY-SVC-02", rule_ids)
        self.assertGreaterEqual(len(rule_ids), 2)

        green_svc = (
            "class UpdateService\n"
            "  def filter_consumers(consumers)\n"
            "    ItemConsumersFinder.new(current_user).execute.select { |c| Ability.allowed?(current_user, :read, c) }\n"
            "  end\n"
            "  def resolve_version\n"
            "    return nil unless Ability.allowed?(current_user, :read_version, item)\n"
            "    item.item_version\n"
            "  end\n"
            "  def build_servers\n"
            "    dynamic_servers.except(:orbit, :gitlab).merge(gitlab: static_gitlab_server)\n"
            "  end\n"
            "end\n"
        )
        green_res = audit_sibling_security_parity(green_svc, filename="update_service.rb")
        self.assertEqual(green_res["finding_count"], 0)

    def test_sibling_parity_converter_sink_red_and_green(self) -> None:
        red_converters = {
            "BookMarkToPDF.java": (
                "public class BookMarkToPDF {\n"
                "  public void run(String html) {\n"
                "    String safe = customHtmlSanitizer.sanitize(html);\n"
                "    processExecutor.runCommand(List.of(\"weasyprint\", \"--allowed-protocols\", \"http,https\"));\n"
                "  }\n"
                "}\n"
            ),
            "ConvertWebsiteToPDF.java": (
                "public class ConvertWebsiteToPDF {\n"
                "  public void run(String url) {\n"
                "    processExecutor.runCommand(List.of(\"weasyprint\", url));\n"
                "  }\n"
                "}\n"
            ),
        }
        red_res = audit_sibling_security_parity(red_converters)
        self.assertIn(
            "SNIPER-PARITY-SINK-03",
            [f["rule_id"] for f in red_res["findings"]],
        )

        green_converters = {
            "BookMarkToPDF.java": red_converters["BookMarkToPDF.java"],
            "ConvertWebsiteToPDF.java": (
                "public class ConvertWebsiteToPDF {\n"
                "  public void run(String url) {\n"
                "    processExecutor.runCommand(List.of(\"weasyprint\", \"--allowed-protocols\", \"http,https\", url));\n"
                "  }\n"
                "}\n"
            ),
        }
        green_res = audit_sibling_security_parity(green_converters)
        self.assertEqual(green_res["finding_count"], 0)

    def test_sibling_parity_filesystem_branches_red_and_green(self) -> None:
        red_fs = (
            "public class BackupService {\n"
            "  public void dumpData(Path p) {\n"
            "    validateBackupFile(p);\n"
            "    if (!Files.isSymbolicLink(p)) { Files.writeString(p, \"ok\"); }\n"
            "  }\n"
            "  public void loadData(Path p) {\n"
            "    byte[] b = Files.readAllBytes(p);\n"
            "  }\n"
            "}\n"
        )
        red_res = audit_sibling_security_parity(red_fs, filename="BackupService.java")
        self.assertIn(
            "SNIPER-PARITY-FS-04",
            [f["rule_id"] for f in red_res["findings"]],
        )

        green_fs = (
            "public class BackupService {\n"
            "  public void dumpData(Path p) {\n"
            "    validateBackupFile(p);\n"
            "    if (!Files.isSymbolicLink(p)) { Files.writeString(p, \"ok\"); }\n"
            "  }\n"
            "  public void loadData(Path p) {\n"
            "    validateBackupFile(p);\n"
            "    if (!Files.isSymbolicLink(p)) { Files.size(p); }\n"
            "  }\n"
            "}\n"
        )
        green_res = audit_sibling_security_parity(green_fs, filename="BackupService.java")
        self.assertEqual(green_res["finding_count"], 0)

    # --- Faz 1.2: Cross-Language Bridge Auditor ---

    def test_cross_language_bridge_red_and_green(self) -> None:
        red_repo = {
            "ee/lib/api/mcp/base.rb": (
                "headers['X-Gitlab-Mcp-Server-Url'] = server.url\n"
                "headers['X-Gitlab-Mcp-Server-Token'] = server.token\n"
            ),
            "workhorse/internal/mcp/mcp.go": (
                "package mcp\n"
                "func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {\n"
                "  target := req.Header.Get(\"X-Gitlab-Mcp-Server-Url\")\n"
                "  req.Header.Set(\"Authorization\", \"Bearer \"+t.token)\n"
                "  return http.DefaultTransport.RoundTrip(req)\n"
                "}\n"
            ),
        }
        red_res = audit_cross_language_monorepo_bridges(red_repo)
        self.assertEqual(red_res["format"], "sniper-cross-language-bridge-audit/1")
        self.assertGreaterEqual(len(red_res["bridge_edges"]), 1)
        self.assertEqual(red_res["finding_count"], 1)
        self.assertEqual(red_res["findings"][0]["rule_id"], "SNIPER-XLANG-BRIDGE-01")

        green_repo = {
            "ee/lib/api/mcp/base.rb": red_repo["ee/lib/api/mcp/base.rb"],
            "workhorse/internal/mcp/mcp.go": (
                "package mcp\n"
                "func newClient() *http.Client {\n"
                "  tr := NewSafeTransport(WithSSRFFilter())\n"
                "  return &http.Client{Transport: tr, CheckRedirect: sameOrigin}\n"
                "}\n"
                "func handle(r *http.Request) {\n"
                "  _ = r.Header.Get(\"X-Gitlab-Mcp-Server-Url\")\n"
                "}\n"
            ),
        }
        green_res = audit_cross_language_monorepo_bridges(green_repo)
        self.assertEqual(green_res["finding_count"], 0)

    # --- Faz 1.3: HTTP Redirect & TLS Semantics Auditor ---

    def test_http_tls_semantics_red_and_green(self) -> None:
        red_go = (
            "package client\n"
            "func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {\n"
            "  tr := http.DefaultTransport.(*http.Transport).Clone()\n"
            "  tr.TLSClientConfig = &tls.Config{RootCAs: pool, InsecureSkipVerify: true}\n"
            "  req.Header.Set(\"Authorization\", \"Bearer \" + t.secret)\n"
            "  return tr.RoundTrip(req)\n"
            "}\n"
        )
        red_res = audit_http_redirect_and_tls_semantics(red_go, filename="client.go")
        rule_ids = {f["rule_id"] for f in red_res["findings"]}
        self.assertIn("SNIPER-HTTP-WRAP-01", rule_ids)
        self.assertIn("SNIPER-HTTP-REDIR-02", rule_ids)
        self.assertIn("SNIPER-TLS-DEAD-03", rule_ids)

        green_go = (
            "package client\n"
            "func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {\n"
            "  tr := NewSafeTransport(WithSSRFFilter())\n"
            "  tr.TLSClientConfig = &tls.Config{RootCAs: pool, InsecureSkipVerify: false}\n"
            "  if req.URL.Host != t.expectedHost { req.Header.Del(\"Authorization\") }\n"
            "  return tr.RoundTrip(req)\n"
            "}\n"
        )
        green_res = audit_http_redirect_and_tls_semantics(green_go, filename="client.go")
        self.assertEqual(green_res["finding_count"], 0)

    # --- Faz 1.4: Symlink TOCTOU & Archive Semantics Auditor ---

    def test_symlink_archive_semantics_red_and_green(self) -> None:
        red_java = (
            "public class FolderOutputSink {\n"
            "  public void write(Path src, Path target) throws Exception {\n"
            "    if (Files.notExists(target, LinkOption.NOFOLLOW_LINKS)) {\n"
            "      Files.move(src, target, StandardCopyOption.REPLACE_EXISTING);\n"
            "    }\n"
            "  }\n"
            "}\n"
        )
        red_res = audit_symlink_toctou_and_archive_semantics(
            red_java, filename="FolderOutputSink.java"
        )
        self.assertEqual(red_res["finding_count"], 1)
        self.assertEqual(red_res["findings"][0]["rule_id"], "SNIPER-FS-SYMLINK-01")

        green_py = (
            "import zipfile, tarfile\n"
            "def extract_all_safe(zpath, tpath, dest):\n"
            "    with zipfile.ZipFile(zpath) as zf:\n"
            "        zf.extractall(dest)\n"
            "    with tarfile.open(tpath) as tf:\n"
            "        tf.extractall(dest, filter='data')\n"
        )
        green_res = audit_symlink_toctou_and_archive_semantics(
            green_py, filename="archive_utils.py", python_version=(3, 12)
        )
        self.assertEqual(green_res["finding_count"], 0)
        self.assertGreaterEqual(green_res["suppressed_stdlib_safe_extractions"], 2)

    # --- Faz 2 R8: Interprocedural Helper Path Guard ---

    def test_interprocedural_helper_path_guard_r8(self) -> None:
        go_guarded = (
            "func validateBackupPath(p string) error {\n"
            "  rel, err := filepath.Rel(baseDir, p)\n"
            "  if err != nil || strings.HasPrefix(rel, \"..\") {\n"
            "    return errors.New(\"invalid path\")\n"
            "  }\n"
            "  return nil\n"
            "}\n"
            "func handleDownload(userPath string) error {\n"
            "  if err := validateBackupPath(userPath); err != nil {\n"
            "    return err\n"
            "  }\n"
            "  _, err := os.ReadFile(userPath)\n"
            "  return err\n"
            "}\n"
        )
        self.assertTrue(has_interprocedural_helper_path_guard(go_guarded, "userPath"))

        go_unguarded = (
            "func handleDownload(userPath string) error {\n"
            "  _, err := os.ReadFile(userPath)\n"
            "  return err\n"
            "}\n"
        )
        self.assertFalse(has_interprocedural_helper_path_guard(go_unguarded, "userPath"))

        py_guarded = (
            "def ensure_safe_path(p):\n"
            "    real = os.path.realpath(p)\n"
            "    if os.path.commonpath([BASE_DIR, real]) != BASE_DIR:\n"
            "        raise ValueError('traversal')\n"
            "\n"
            "def read_item(target_path):\n"
            "    ensure_safe_path(target_path)\n"
            "    return open(target_path, 'rb').read()\n"
        )
        self.assertTrue(has_interprocedural_helper_path_guard(py_guarded, "target_path"))


if __name__ == "__main__":
    unittest.main()
