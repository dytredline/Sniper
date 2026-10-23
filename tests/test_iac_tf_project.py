"""19. tur IaC: Terraform proje bağlamı (değişken/tfvars/locals/yerel modül), varsayılan ayar denetimleri ve
değerlerle Helm render."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

APP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP))

import iac_engine  # noqa: E402
import iac_helm  # noqa: E402
import iac_tf_eval  # noqa: E402
import iac_tf_project  # noqa: E402


def _d(files: dict[str, str]) -> dict[str, str]:
    return {k: textwrap.dedent(v).lstrip("\n") for k, v in files.items()}


def project(files: dict[str, str]) -> dict[str, list[tuple[str, int]]]:
    results = iac_tf_project.analyze_files(_d(files))
    return {rel: sorted((f["id"], f["line"]) for f in r.findings) for rel, r in results.items()}


class EvalTests(unittest.TestCase):
    def test_expressions(self):
        import iac_hcl

        root = iac_hcl.parse(textwrap.dedent('''
            locals {
              env  = "prod"
              name = "app-${local.env}"
              same = var.x ? ["0.0.0.0/0"] : ["0.0.0.0/0"]
              diff = var.x ? true : false
              lk   = lookup(var.m, "b", false)
              mg   = merge(var.m, { c = 1 })
              cmp  = local.env == "prod" && !false
            }
        '''))
        ctx = iac_tf_eval.Ctx({"m": {"a": "x", "b": True}, "x": iac_hcl.Unknown("var.x")},
                              {k: a.value for k, a in root.blocks[0].attrs.items()})
        self.assertEqual(ctx.local("name"), "app-prod")
        self.assertEqual(ctx.local("same"), ["0.0.0.0/0"])  # iki dal aynı → koşuldan bağımsız
        self.assertIsInstance(ctx.local("diff"), iac_hcl.Unknown)
        self.assertIs(ctx.local("lk"), True)
        self.assertEqual(ctx.local("mg"), {"a": "x", "b": True, "c": 1})
        self.assertIs(ctx.local("cmp"), True)

    def test_local_cycle_is_unknown(self):
        import iac_hcl

        root = iac_hcl.parse('locals {\n a = local.b\n b = local.a\n}\n')
        ctx = iac_tf_eval.Ctx({}, {k: a.value for k, a in root.blocks[0].attrs.items()})
        self.assertIsInstance(ctx.local("a"), iac_hcl.Unknown)


class TerraformProjectTests(unittest.TestCase):
    def test_variable_default_across_files(self):
        out = project({
            "variables.tf": '''
                variable "enc" {
                  default = false
                }
                variable "pub" {}
            ''',
            "main.tf": '''
                resource "aws_db_instance" "d" {
                  storage_encrypted   = var.enc
                  publicly_accessible = var.pub
                }
            ''',
        })
        self.assertEqual(out["main.tf"], [("SNP-IAC-TF-003", 2)])  # varsayılansız değişken: susar

    def test_tfvars_overrides_and_only_auto_files(self):
        files = {
            "variables.tf": 'variable "enc" {\n  default = false\n}\n',
            "main.tf": 'resource "aws_db_instance" "d" {\n  storage_encrypted = var.enc\n}\n',
        }
        self.assertEqual(project({**files, "terraform.tfvars": "enc = true\n"})["main.tf"], [])
        self.assertEqual(project({**files, "prod.auto.tfvars": "enc = true\n"})["main.tf"], [])
        # adı otomatik yüklenmeyen tfvars dikkate alınmaz
        self.assertEqual(project({**files, "prod.tfvars": "enc = true\n"})["main.tf"], [("SNP-IAC-TF-003", 2)])

    def test_locals_and_templates(self):
        out = project({"main.tf": '''
            locals {
              open  = ["0.0.0.0/0"]
              https = false
            }
            resource "aws_security_group" "s" {
              ingress {
                from_port   = 22
                to_port     = 22
                protocol    = "tcp"
                cidr_blocks = local.open
              }
            }
            resource "azurerm_storage_account" "a" {
              enable_https_traffic_only = local.https
            }
        '''})
        ids = [i for i, _ in out["main.tf"]]
        self.assertIn("SNP-IAC-TF-001", ids)
        self.assertIn("SNP-IAC-TF-003", ids)

    def test_local_module_inputs(self):
        out = project({
            "main.tf": '''
                module "db" {
                  source              = "./modules/db"
                  publicly_accessible = true
                }
                module "safe" {
                  source = "./modules/db"
                }
            ''',
            "modules/db/variables.tf": '''
                variable "publicly_accessible" {
                  default = false
                }
            ''',
            "modules/db/main.tf": '''
                resource "aws_db_instance" "this" {
                  storage_encrypted   = true
                  publicly_accessible = var.publicly_accessible
                }
            ''',
        })
        self.assertEqual(out["modules/db/main.tf"], [("SNP-IAC-TF-005", 3)])
        result = iac_tf_project.analyze_files(_d({
            "main.tf": 'module "db" {\n  source = "./modules/db"\n  publicly_accessible = true\n}\n',
            "modules/db/main.tf": 'resource "aws_db_instance" "this" {\n  storage_encrypted = true\n'
                                  '  publicly_accessible = var.publicly_accessible\n}\n',
            "modules/db/variables.tf": 'variable "publicly_accessible" {}\n',
        }))
        item = result["modules/db/main.tf"].findings[0]
        self.assertEqual(item["resource"], "module.db.aws_db_instance.this")
        self.assertIn("main.tf:1", item["evidence"])

    def test_module_source_outside_root_and_cycles(self):
        out = project({
            "a/main.tf": 'module "x" {\n  source = "../../outside"\n  encrypted = false\n}\n',
            "b/main.tf": 'module "c" {\n  source = "../c"\n}\n',
            "c/main.tf": 'module "b" {\n  source = "../b"\n}\n',
        })
        self.assertEqual(out["a/main.tf"], [("SNP-IAC-TF-003", 3)])  # çözülmeyen modül: yalnız çağrı girdileri
        self.assertEqual(out["b/main.tf"], [])
        self.assertEqual(out["c/main.tf"], [])

    def test_s3_defaults_are_module_wide(self):
        bucket = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
        self.assertEqual(project({"main.tf": bucket})["main.tf"],
                         [("SNP-IAC-TF-025", 1), ("SNP-IAC-TF-026", 1)])
        out = project({
            "main.tf": bucket,
            "versioning.tf": 'resource "aws_s3_bucket_versioning" "v" {\n  bucket = aws_s3_bucket.b.id\n'
                             '  versioning_configuration {\n    status = "Enabled"\n  }\n}\n',
            "logging.tf": 'resource "aws_s3_bucket_logging" "l" {\n  bucket = aws_s3_bucket.b.id\n'
                          '  target_bucket = aws_s3_bucket.logs.id\n  target_prefix = "x/"\n}\n',
            "logs.tf": 'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n}\n'
                       'resource "aws_s3_bucket_versioning" "lv" {\n  bucket = aws_s3_bucket.logs.id\n'
                       '  versioning_configuration {\n    status = "Enabled"\n  }\n}\n',
        })
        self.assertEqual(out["main.tf"], [])
        self.assertEqual(out["logs.tf"], [])  # günlük hedefi kovanın kendisi günlük istemez
        suspended = project({"main.tf": bucket, "v.tf": 'resource "aws_s3_bucket_versioning" "v" {\n'
                             '  bucket = aws_s3_bucket.b.id\n  versioning_configuration {\n    status = "Suspended"\n'
                             '  }\n}\n'})
        self.assertIn(("SNP-IAC-TF-025", 1), suspended["main.tf"])

    def test_ebs_and_other_defaults(self):
        vol = 'resource "aws_ebs_volume" "v" {\n  size = 10\n  availability_zone = "a"\n}\n'
        self.assertEqual(project({"main.tf": vol})["main.tf"], [("SNP-IAC-TF-027", 1)])
        self.assertEqual(project({"main.tf": vol, "acct.tf": 'resource "aws_ebs_encryption_by_default" "e" {\n'
                                  '  enabled = true\n}\n'})["main.tf"], [])
        out = project({"main.tf": '''
            resource "aws_efs_file_system" "f" {
              creation_token = "x"
            }
            resource "aws_lb" "n" {
              load_balancer_type = "network"
            }
            resource "aws_lb" "a" {
              name = "web"
            }
        '''})
        self.assertEqual(out["main.tf"], [("SNP-IAC-TF-028", 1), ("SNP-IAC-TF-034", 7)])

    def test_registry_module_inputs_resolved(self):
        out = project({"main.tf": '''
            variable "enc" {
              default = false
            }
            module "db" {
              source            = "terraform-aws-modules/rds/aws"
              storage_encrypted = var.enc
            }
            module "other" {
              source              = "git::https://example.invalid/x.git"
              publicly_accessible = true
            }
        '''})
        self.assertEqual(out["main.tf"], [("SNP-IAC-TF-003", 6)])  # bilinmeyen uzak modülde kaynak kuralı yok

    def test_unparsable_file_falls_back(self):
        results = iac_tf_project.analyze_files({"bad.tf": 'resource "x" "y" {\n  a = "unterminated\n}\n',
                                                "ok.tf": 'resource "aws_kms_key" "k" {\n  enable_key_rotation = true\n}\n'})
        self.assertNotIn("bad.tf", results)
        self.assertEqual(results["ok.tf"].findings, [])

    def test_scan_tree_respects_skip_dirs_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "x.tf").write_text('resource "aws_db_instance" "d" {\n storage_encrypted = false\n}\n')
            (root / "main.tf").write_text('resource "aws_db_instance" "d" {\n storage_encrypted = false\n}\n')
            os.symlink(root / "main.tf", root / "link.tf")
            results = iac_tf_project.scan_tree(root, {"node_modules"})
            self.assertEqual(sorted(results), ["main.tf"])


class HelmRenderTests(unittest.TestCase):
    TEMPLATE = textwrap.dedent('''
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: {{ include "x.fullname" . }}
        spec:
          template:
            spec:
              hostNetwork: {{ .Values.hostNetwork }}
              {{- if .Values.debug }}
              hostPID: true
              {{- end }}
              {{- if .Values.unknownThing.on }}
              hostIPC: true
              {{- end }}
              containers:
                - name: app
                  image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
                  securityContext:
                    {{- toYaml .Values.securityContext | nindent 12 }}
                  env:
                    {{- range .Values.env }}
                    - name: {{ .name }}
                      value: {{ .value | quote }}
                    {{- end }}
    ''').lstrip("\n")

    def test_render_with_values(self):
        values = {"hostNetwork": True, "debug": False, "image": {"repository": "nginx", "tag": "1.27.0"},
                  "securityContext": {"privileged": True}, "env": [{"name": "A", "value": "b"}]}
        result = iac_engine.analyze("templates/deploy.yaml", self.TEMPLATE, values)
        got = sorted((f["id"], f["line"]) for f in result.findings)
        lines = self.TEMPLATE.splitlines()
        self.assertIn(("SNP-IAC-K8S-003", 8), got)  # hostNetwork satırı şablon satırına eşlenir
        self.assertIn(("SNP-IAC-K8S-001", 19), got)  # toYaml satırı
        self.assertTrue(lines[18].strip().startswith("{{- toYaml"))
        self.assertNotIn("SNP-IAC-K8S-005", [i for i, _ in got])  # debug=false: dal atlandı
        self.assertNotIn("SNP-IAC-K8S-011", [i for i, _ in got])  # sabitlenmiş etiket

    def test_unknown_branch_keeps_placeholders(self):
        values = {"unknownThing": {"on": True}, "securityContext": {}}
        out, mapping = iac_helm.render(self.TEMPLATE, values)
        self.assertIn("hostIPC: true", out)  # bilinen doğru koşul
        values2 = {"securityContext": {}}  # unknownThing yok → nil → yanlış
        out2, _ = iac_helm.render(self.TEMPLATE, values2)
        self.assertNotIn("hostIPC", out2)
        tpl = 'kind: Pod\napiVersion: v1\nspec:\n  {{- if include "x" . }}\n  hostPID: {{ .Values.p }}\n  {{- end }}\n'
        out3, _ = iac_helm.render(tpl, {"p": True})
        self.assertIn(iac_helm.PH, out3)  # bilinmeyen koşul içinde değer yerine konmaz

    def test_without_values_old_behaviour(self):
        # Değerler yokken eski yer tutuculu yaklaşım: koşullu bloklardaki sabit satırlar da raporlanır (değerlerle
        # render bu yanlış alarmları kaldırır: debug=false → hostPID yok).
        result = iac_engine.analyze("templates/deploy.yaml", self.TEMPLATE)
        self.assertEqual(sorted(f["id"] for f in result.findings), ["SNP-IAC-K8S-005", "SNP-IAC-K8S-006"])

    def test_values_lookup_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chart = root / "charts" / "c"
            (chart / "templates").mkdir(parents=True)
            (chart / "values.yaml").write_text("hostNetwork: true\n")
            self.assertIsNone(iac_engine.helm_values_for(root, "charts/c/templates/d.yaml"))  # Chart.yaml yok
            (chart / "Chart.yaml").write_text("apiVersion: v2\nname: c\nversion: 1.0.0\n")
            self.assertEqual(iac_engine.helm_values_for(root, "charts/c/templates/d.yaml"), {"hostNetwork": True})
            self.assertIsNone(iac_engine.helm_values_for(root, "charts/c/other/d.yaml"))
            outside = Path(tmp + "-dis")
            outside.mkdir()
            try:
                (outside / "values.yaml").write_text("hostNetwork: true\n")
                (chart / "values.yaml").unlink()
                os.symlink(outside / "values.yaml", chart / "values.yaml")
                self.assertIsNone(iac_engine.helm_values_for(root, "charts/c/templates/d.yaml"))
            finally:
                (outside / "values.yaml").unlink()
                outside.rmdir()

    def test_values_are_not_executed(self):
        self.assertIsNone(iac_helm.load_values("!!python/object/apply:os.system ['true']\n"))


class ProjectAnalyzerIntegrationTests(unittest.TestCase):
    def test_variables_used_in_project_analysis(self):
        import project_analyzer

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "infra"
            root.mkdir()
            (root / "variables.tf").write_text('variable "pub" {\n  default = true\n}\n')
            (root / "main.tf").write_text('resource "aws_db_instance" "d" {\n  storage_encrypted = true\n'
                                          '  publicly_accessible = var.pub\n}\n')
            result = project_analyzer.analyze_project(str(root), allowed_roots=(Path(tmp),))
            iac = [(f["file"], f["line"], f["iac"]["check"]) for f in result["findings"] if f.get("iac")]
            self.assertIn(("main.tf", 3, "SNP-IAC-TF-005"), iac)


if __name__ == "__main__":
    unittest.main()
