"""Ajan başına otomatik uygulama eşiği (26. tur): per_agent seçimi (claude 0,90 / codex 0,99 / tanımsız → genel),
devre dışı ajan, uzlaşı modu, eski politika dosyası, doğrulamalar, API/CLI ayarı (MCP'den değiştirilemez) ve calibrate
önerisi (yalnız sahte küçük anahtarla)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import ai_triage as at
import mcp_triage_server
from storage import Store
from tests.test_finding_tracking_collab import ApiTestBase, audit_rows, finding, make_audit

APP = Path(__file__).resolve().parents[1]


def lf(conf):
    return {"verdict": "likely_false", "confidence": conf, "rationale": "Parametreli sorgu."}


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data_dir = base / "data"
        self.data_dir.mkdir()
        self.root = base / "proj"
        self.root.mkdir()
        (self.root / "app.py").write_text("x = 1\n")
        env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        env.start()
        self.addCleanup(env.stop)
        self.store = Store(self.data_dir / "sniper.db")
        make_audit(self.store, self.root, [finding("app.py", line) for line in range(1, 7)])
        self.ids = [i["id"] for i in sorted(self.store.list_tracked_findings(str(self.root)), key=lambda i: i["line"])]

    def status(self, tracked_id):
        return self.store.get_tracked_finding(tracked_id)["status"]

    def record(self, index, conf, agent, source="mcp"):
        return at.record_suggestion(self.store, self.ids[index], lf(conf), source=source, agent=agent)


class AgentKeyTests(unittest.TestCase):
    def test_normalization(self):
        cases = {"claude-code": "claude", "Claude Code": "claude", "anthropic/claude-opus": "claude", "codex": "codex",
                 "OpenAI Codex CLI": "codex", "Gemini CLI": "gemini-cli", "yerel model": "yerel-model", "": "",
                 "x" * 50: "x" * 32, "a//b": "a-b"}
        for raw, key in cases.items():
            self.assertEqual(at.agent_key(raw), key, raw)


class PerAgentTests(_Base):
    def test_defaults_and_selection(self):
        policy = at.load_policy(self.data_dir)["auto_apply"]
        self.assertEqual((policy["per_agent"]["claude"]["min_confidence"], policy["per_agent"]["codex"]["min_confidence"],
                          policy["min_confidence"], policy["require_consensus"], policy["consensus_min_confidence"]),
                         (0.90, 0.99, 0.9, "auto", 0.70))
        self.assertEqual(self.record(0, 0.95, "codex")["decision"], "pending")  # genel anahtar kapalı
        at.set_auto_apply(self.data_dir, True, None, "y", require_consensus=False)  # tek ajan modu (ajan başına eşik)
        self.assertEqual(self.record(1, 0.95, "codex")["decision"], "pending")       # codex eşiği 0,99
        self.assertEqual(self.record(2, 0.99, "OpenAI Codex")["decision"], "auto_applied")
        self.assertEqual(self.record(3, 0.92, "claude-code")["decision"], "auto_applied")
        self.assertEqual(self.record(4, 0.89, "claude-code")["decision"], "pending")
        self.assertEqual(self.record(5, 0.9, "gemini")["decision"], "auto_applied")  # tanımsız ajan → genel 0,9
        self.assertEqual([self.status(i) for i in self.ids], ["open", "open", "false_positive", "false_positive", "open",
                                                              "false_positive"])
        applied = [d for a, d in audit_rows(self.store) if a == "ai_triage.auto_applied"]
        self.assertEqual([(d["agent_key"], d["min_confidence"], d["threshold_origin"], d["mode"]) for d in applied],
                         [("codex", 0.99, "agent", "single"), ("claude", 0.9, "agent", "single"),
                          ("gemini", 0.9, "global", "single")])
        self.assertEqual(applied[0]["mode_reason"], "politika: tek ajan")
        self.assertEqual(applied[1]["agent"], "claude-code")

    def test_disabled_agent_and_custom_threshold(self):
        at.set_auto_apply(self.data_dir, True, 0.8, "y", require_consensus=False,
                          per_agent={"codex": {"enabled": False}, "gemini": {"min_confidence": 0.97}})
        policy = at.load_policy(self.data_dir)["auto_apply"]
        self.assertEqual(policy["per_agent"]["codex"], {"enabled": False, "min_confidence": 0.99})
        self.assertEqual(self.record(0, 1.0, "codex")["decision"], "pending")  # ajan kapalı: asla otomatik değil
        self.assertEqual(self.record(1, 0.81, "gemini-cli")["decision"], "auto_applied")  # "gemini-cli" tanımsız → genel 0,8
        self.assertEqual(self.record(2, 0.96, "gemini")["decision"], "pending")
        self.assertEqual(self.record(3, 0.97, "gemini")["decision"], "auto_applied")
        # null → varsayılana dönüş; min_confidence None → genel eşik korunur
        policy = at.set_auto_apply(self.data_dir, True, None, "y", per_agent={"codex": None, "gemini": None})["auto_apply"]
        self.assertEqual((policy["per_agent"]["codex"], "gemini" in policy["per_agent"], policy["min_confidence"]),
                         ({"enabled": True, "min_confidence": 0.99}, False, 0.8))

    def test_validation(self):
        bad = [{"Claude": {"min_confidence": 0.9}}, {"a b": {"min_confidence": 0.9}}, {"x" * 33: {"min_confidence": 0.9}},
               {"codex": {"min_confidence": 0.4}}, {"codex": {"min_confidence": 1.1}}, {"codex": {"min_confidence": True}},
               {"codex": {"enabled": "evet"}}, {"codex": {"extra": 1}}, {"codex": {}}, {"codex": 0.9}, ["codex"]]
        for item in bad:
            with self.assertRaises(at.TriageError, msg=item):
                at.set_auto_apply(self.data_dir, True, None, "y", per_agent=item)
        for value in ("evet", "AUTO", 1, []):
            with self.assertRaises(at.TriageError, msg=value):
                at.set_auto_apply(self.data_dir, True, None, "y", require_consensus=value)
        for value in (0.3, 1.5, True, "x"):
            with self.assertRaises(at.TriageError, msg=value):
                at.set_auto_apply(self.data_dir, True, None, "y", consensus_min_confidence=value)
        policy = at.set_auto_apply(self.data_dir, True, None, "y", require_consensus="auto",
                                   consensus_min_confidence=0.8)["auto_apply"]
        self.assertEqual((policy["require_consensus"], policy["consensus_min_confidence"]), ("auto", 0.8))
        policy = at.set_auto_apply(self.data_dir, False, None, "y")["auto_apply"]  # None → korunur
        self.assertEqual((policy["require_consensus"], policy["consensus_min_confidence"]), ("auto", 0.8))
        with self.assertRaises(at.TriageError):
            at.set_auto_apply(self.data_dir, True, True, "y")

    def test_old_policy_file_and_invalid_entries(self):
        (self.data_dir / at.POLICY_FILE).write_text(json.dumps({
            "external_agents": {}, "auto_apply": {"enabled": True, "min_confidence": 0.95}}))
        policy = at.load_policy(self.data_dir)["auto_apply"]
        self.assertEqual((policy["enabled"], policy["min_confidence"], policy["require_consensus"],
                          policy["consensus_min_confidence"]), (True, 0.95, "auto", 0.70))  # eski dosya → "auto"
        self.assertEqual(policy["per_agent"], {k: dict(v) for k, v in at.DEFAULT_PER_AGENT.items()})
        self.assertEqual(self.record(0, 0.95, "codex")["decision"], "pending")  # tek ajan: codex varsayılanı 0,99
        self.assertEqual(self.record(1, 0.96, "x-agent")["decision"], "pending")  # artık 2 ajan → uzlaşı, ortak yok
        (self.data_dir / at.POLICY_FILE).write_text(json.dumps({"auto_apply": {"enabled": True, "per_agent": {
            "Kötü Anahtar": {"min_confidence": 0.6}, "codex": {"min_confidence": 7}, "claude": {"min_confidence": 0.93},
            "x": "yanlış"}}}))
        per_agent = at.load_policy(self.data_dir)["auto_apply"]["per_agent"]
        self.assertEqual(per_agent, {"claude": {"enabled": True, "min_confidence": 0.93},
                                     "codex": {"enabled": True, "min_confidence": 0.99}})
        for raw, expected in ((False, False), (True, True), ("auto", "auto"), ("evet", "auto"), (None, "auto")):
            (self.data_dir / at.POLICY_FILE).write_text(json.dumps({"auto_apply": {"enabled": True,
                                                                                   "require_consensus": raw,
                                                                                   "consensus_min_confidence": 3}}))
            policy = at.load_policy(self.data_dir)["auto_apply"]
            self.assertEqual((policy["require_consensus"], policy["consensus_min_confidence"]), (expected, 0.70), raw)

    def test_explicit_false_file_stays_single_mode(self):
        (self.data_dir / at.POLICY_FILE).write_text(json.dumps({"auto_apply": {"enabled": True, "require_consensus": False}}))
        self.record(5, 0.99, "codex")
        self.assertEqual(at.load_policy(self.data_dir)["auto_apply"]["require_consensus"], False)
        applied = self.record(0, 0.92, "claude-code")  # iki ajan olsa da tek ajan modu
        self.assertEqual(applied["decision"], "auto_applied")
        audit = [d for a, d in audit_rows(self.store) if a == "ai_triage.auto_applied"][-1]
        self.assertEqual((audit["mode"], audit["mode_reason"], audit["min_confidence"]), ("single", "politika: tek ajan", 0.9))


def lt(conf):
    return {"verdict": "likely_true", "confidence": conf, "rationale": "Doğrudan birleştirme."}


class ConsensusTests(_Base):
    def audits(self):
        return [d for a, d in audit_rows(self.store) if a == "ai_triage.auto_applied"]

    def test_auto_single_agent_uses_agent_threshold(self):
        at.set_auto_apply(self.data_dir, True, None, "y")  # require_consensus varsayılan "auto"
        self.assertEqual(self.record(0, 0.85, "claude-code")["decision"], "pending")  # claude eşiği 0,90
        self.assertEqual(self.record(1, 0.92, "claude-code")["decision"], "auto_applied")
        audit = self.audits()[-1]
        self.assertEqual((audit["mode"], audit["mode_reason"], audit["min_confidence"], audit["threshold_origin"]),
                         ("single", "auto: 1 ajan", 0.9, "agent"))

    def test_auto_two_agents_switches_to_consensus(self):
        at.set_auto_apply(self.data_dir, True, None, "y")
        at.record_suggestion(self.store, self.ids[5], lt(0.9), source="mcp", agent="codex")  # projede 2. ajan
        first = self.record(0, 0.95, "claude-code")
        self.assertEqual((first["decision"], self.status(self.ids[0])), ("pending", "open"))  # tek başına uygulanmaz
        second = self.record(0, 0.75, "codex")  # ajan eşiği (0,99) değil, uzlaşı eşiği (0,70)
        self.assertEqual((second["decision"], self.status(self.ids[0])), ("auto_applied", "false_positive"))
        decisions = {s["id"]: s["decision"] for s in at.list_suggestions(self.store, tracked_id=self.ids[0])}
        self.assertEqual(decisions[first["id"]], "auto_applied")
        audit = self.audits()[-1]
        self.assertEqual((audit["mode"], audit["mode_reason"], audit["min_confidence"], audit["threshold_origin"]),
                         ("consensus", "auto: 2 ajan", 0.7, "consensus"))
        self.assertEqual([(c["agent_key"], c["confidence"], c["min_confidence"]) for c in audit["consensus"]],
                         [("claude", 0.95, 0.7)])
        # biri uzlaşı eşiğinin altında → uygulanmaz; aynı ajan ailesi iki kez → uzlaşı sayılmaz
        self.record(1, 0.65, "claude")
        self.assertEqual(self.record(1, 0.99, "codex")["decision"], "pending")
        self.record(2, 0.9, "claude-code")
        self.assertEqual(self.record(2, 0.95, "anthropic claude")["decision"], "pending")
        self.assertEqual(at.decide(self.store, second["id"], "revert")["decision"], "reverted")
        self.assertEqual(self.status(self.ids[0]), "open")

    def test_thirty_day_window(self):
        at.set_auto_apply(self.data_dir, True, None, "y")
        old = at.record_suggestion(self.store, self.ids[5], lt(0.9), source="mcp", agent="codex")
        with self.store._connect() as db:
            db.execute("UPDATE ai_triage_suggestions SET created_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (old["id"],))
        applied = self.record(0, 0.92, "claude-code")
        self.assertEqual(applied["decision"], "auto_applied")  # 31+ gün önceki ajan sayılmaz → tek ajan
        self.assertEqual(self.audits()[-1]["mode_reason"], "auto: 1 ajan")
        cutoff = datetime.now(timezone.utc) - timedelta(days=at.CONSENSUS_WINDOW_DAYS - 1)
        with self.store._connect() as db:
            db.execute("UPDATE ai_triage_suggestions SET created_at = ? WHERE id = ?",
                       (cutoff.replace(microsecond=0).isoformat(), old["id"]))
        self.assertEqual(self.record(1, 0.92, "claude-code")["decision"], "pending")  # 29 gün → 2 ajan → uzlaşı
        with self.store._connect() as db:
            self.assertEqual(at.consensus_mode(db, at.load_policy(self.data_dir), str(self.root), "claude"),
                             (True, "auto: 2 ajan"))

    def test_disabled_agent_cannot_join(self):
        at.set_auto_apply(self.data_dir, True, None, "y", per_agent={"codex": {"enabled": False}})
        self.record(5, 0.99, "codex")  # devre dışı ajan "auto" sayımına girmez
        self.assertEqual(self.record(0, 0.92, "claude-code")["decision"], "auto_applied")
        self.assertEqual(self.audits()[-1]["mode"], "single")
        at.set_auto_apply(self.data_dir, True, None, "y", require_consensus=True)
        self.record(1, 0.99, "claude-code")
        self.assertEqual(self.record(1, 1.0, "codex")["decision"], "pending")  # devre dışı ajan uzlaşıya giremez
        self.assertEqual(self.status(self.ids[1]), "open")
        at.record_suggestion(self.store, self.ids[2], lt(0.99), source="mcp", agent="gemini")
        self.assertEqual(self.record(2, 0.99, "claude")["decision"], "pending")  # diğer ajan likely_true dedi

    def test_explicit_true_uses_consensus_threshold_not_agent_threshold(self):
        at.set_auto_apply(self.data_dir, True, None, "y", require_consensus=True, consensus_min_confidence=0.8)
        first = self.record(0, 0.95, "claude-code")
        self.assertEqual(first["decision"], "pending")
        self.assertEqual(self.record(0, 0.97, "claude")["decision"], "pending")
        self.assertEqual(self.record(0, 0.79, "codex")["decision"], "pending")   # uzlaşı eşiğinin altında
        strong = self.record(0, 0.85, "codex")  # codex ajan eşiği 0,99 olsa da uzlaşıda 0,80 yeter
        self.assertEqual((strong["decision"], self.status(self.ids[0])), ("auto_applied", "false_positive"))
        audit = self.audits()[-1]
        self.assertEqual((audit["mode"], audit["mode_reason"], audit["min_confidence"], audit["require_consensus"]),
                         ("consensus", "politika: uzlaşı", 0.8, True))
        self.assertEqual([c["agent_key"] for c in audit["consensus"]], ["claude"])


class SurfaceTests(_Base):
    def test_cli_per_agent_and_consensus(self):
        def cli(*args):
            return subprocess.run([sys.executable, str(APP / "cli_reports.py"), "triage", "auto-apply", *args,
                                   "--db", str(self.store.path)], capture_output=True, text=True, timeout=60,
                                  env={**os.environ, "SNIPER_DATA_DIR": str(self.data_dir)})
        done = cli("on", "--agent", "Codex", "--min-confidence", "0.98", "--consensus", "on",
                   "--consensus-min-confidence", "0.75")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("codex", done.stdout)
        policy = at.load_policy(self.data_dir)["auto_apply"]
        self.assertEqual((policy["enabled"], policy["require_consensus"], policy["per_agent"]["codex"]["min_confidence"],
                          policy["min_confidence"], policy["consensus_min_confidence"]), (True, True, 0.98, 0.9, 0.75))
        self.assertEqual(cli("on", "--consensus", "auto").returncode, 0)
        self.assertEqual(at.load_policy(self.data_dir)["auto_apply"]["require_consensus"], "auto")
        self.assertEqual(cli("on", "--consensus", "off").returncode, 0)
        self.assertIs(at.load_policy(self.data_dir)["auto_apply"]["require_consensus"], False)
        self.assertNotEqual(cli("on", "--consensus-min-confidence", "0.2").returncode, 0)
        self.assertEqual(cli("on", "--agent", "claude", "--agent-state", "off").returncode, 0)
        self.assertFalse(at.load_policy(self.data_dir)["auto_apply"]["per_agent"]["claude"]["enabled"])
        self.assertEqual(cli("on", "--agent", "codex", "--agent-reset").returncode, 0)
        self.assertEqual(at.load_policy(self.data_dir)["auto_apply"]["per_agent"]["codex"]["min_confidence"], 0.99)
        self.assertNotEqual(cli("on", "--agent", "codex", "--min-confidence", "0.3").returncode, 0)
        self.assertNotEqual(cli("on", "--agent-state", "off").returncode, 0)
        self.assertIn("ai_triage.policy_changed", [a for a, _ in audit_rows(self.store)])

    def test_mcp_cannot_change_policy(self):
        """Politika MCP'den değiştirilemez (insan onayı ilkesi): araç listede yok, çağrı bilinmeyen araç hatası."""
        self.assertNotIn("set_auto_apply_policy", {t["name"] for t in mcp_triage_server.TOOLS})
        args = {"enabled": True, "per_agent": {"codex": {"min_confidence": 0.5}}, "require_consensus": False}
        for user in (None, {"id": None, "username": "a", "role": "analyst"},
                     {"id": None, "username": "yonetici", "role": "admin"}):
            server = mcp_triage_server.TriageMCPServer(self.store, user=user)
            reply = server.call_tool("set_auto_apply_policy", args)
            self.assertTrue(reply["isError"])
            self.assertIn("Bilinmeyen araç", reply["content"][0]["text"])
            listed = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
            self.assertNotIn("set_auto_apply_policy", {t["name"] for t in listed})
        init = mcp_triage_server.TriageMCPServer(self.store).handle(
            {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}})
        self.assertIn("MCP'den değiştirilemez", init["result"]["instructions"])
        policy = at.load_policy(self.data_dir)["auto_apply"]
        self.assertEqual((policy["enabled"], policy["per_agent"]["codex"]["min_confidence"]), (False, 0.99))
        self.assertNotIn("ai_triage.policy_changed", [a for a, _ in audit_rows(self.store)])


class ApiPolicyTests(ApiTestBase):
    def test_route_accepts_per_agent(self):
        c = self.client()
        status, body = c.post("/api/ai-triage/auto-apply", {"confirm": True, "enabled": True, "require_consensus": False,
                                                             "per_agent": {"claude": {"min_confidence": 0.93}}})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["policy"]["auto_apply"]["per_agent"]["claude"], {"enabled": True, "min_confidence": 0.93})
        self.assertEqual(c.post("/api/ai-triage/auto-apply", {"confirm": True, "enabled": True,
                                                              "per_agent": {"Claude!": {"min_confidence": 0.9}}})[0], 400)
        self.assertEqual(c.post("/api/ai-triage/auto-apply", {"confirm": True, "enabled": True, "other": 1})[0], 400)
        status, settings = c.get("/api/ai-triage/settings")
        self.assertEqual(settings["default_per_agent"]["codex"]["min_confidence"], 0.99)
        self.assertEqual(settings["consensus_defaults"], {"require_consensus": "auto", "consensus_min_confidence": 0.7,
                                                          "window_days": 30})
        status, body = c.post("/api/ai-triage/auto-apply", {"confirm": True, "enabled": True, "require_consensus": "auto",
                                                             "consensus_min_confidence": 0.75})
        self.assertEqual(status, 200, body)
        self.assertEqual((body["policy"]["auto_apply"]["require_consensus"],
                          body["policy"]["auto_apply"]["consensus_min_confidence"]), ("auto", 0.75))
        for bad in ({"require_consensus": "evet"}, {"consensus_min_confidence": 0.2}):
            self.assertEqual(c.post("/api/ai-triage/auto-apply", {"confirm": True, "enabled": True, **bad})[0], 400)


@unittest.skipUnless(
    (APP / "scripts" / "ai_triage_eval.py").is_file(),
    "maintainer evaluation helper is not shipped in Community source",
)
class CalibrateTests(unittest.TestCase):
    def test_sweep_and_recommendation(self):
        sys.path.insert(0, str(APP / "scripts"))
        import ai_triage_eval as ev

        key = {"key": {"t1": {"truth": "true"}, "t2": {"truth": "true"}, "f1": {"truth": "false"},
                       "f2": {"truth": "false"}, "f3": {"truth": "false"}, "d1": {"truth": "disputed"}}}
        claude = {"agent": "claude-code", "results": [
            {"finding_id": "t1", "verdict": "likely_false", "confidence": 0.6, "rationale": "x"},
            {"finding_id": "t2", "verdict": "likely_true", "confidence": 0.9, "rationale": "x"},
            {"finding_id": "f1", "verdict": "likely_false", "confidence": 0.95, "rationale": "x"},
            {"finding_id": "f2", "verdict": "likely_false", "confidence": 0.7, "rationale": "x"},
            {"finding_id": "d1", "verdict": "likely_false", "confidence": 0.99, "rationale": "x"}]}
        codex = {"agent": "codex", "results": [
            {"finding_id": "t1", "verdict": "likely_false", "confidence": 0.98, "rationale": "x"},
            {"finding_id": "f1", "verdict": "likely_false", "confidence": 0.99, "rationale": "x"},
            {"finding_id": "f3", "verdict": "bozuk", "confidence": 0.99, "rationale": "x"}]}
        worst = {"agent": "z", "results": [{"finding_id": "t2", "verdict": "likely_false", "confidence": 1.0, "rationale": "x"}]}
        report = ev.calibrate(key, [("a", claude), ("b", codex), ("c", worst)])
        cl = report["agents"]["claude"]
        self.assertEqual(len(cl["sweep"]), 50)
        self.assertEqual((cl["sweep"][0]["threshold"], cl["sweep"][-1]["threshold"]), (0.5, 0.99))
        self.assertEqual(cl["sweep"][0], {"threshold": 0.5, "fp_eliminated": 2, "tp_lost": 1})
        self.assertEqual(cl["zero_loss_threshold"], 0.61)
        self.assertEqual(cl["recommended"], 0.66)
        self.assertEqual(cl["at_recommended"], {"threshold": 0.66, "fp_eliminated": 2, "tp_lost": 0})
        cx = report["agents"]["codex"]
        self.assertEqual((cx["zero_loss_threshold"], cx["recommended"]), (0.99, 1.0))  # 1'i geçmez
        self.assertEqual(report["per_agent"], {"claude": {"enabled": True, "min_confidence": 0.66},
                                               "codex": {"enabled": True, "min_confidence": 1.0},
                                               "z": {"enabled": False, "min_confidence": 1.0}})
        at.validate_per_agent(report["per_agent"])  # politika için doğrudan kullanılabilir
        # 26. tur uzlaşı: ajan çiftleri, ikisi de likely_false ve ikisinin de güveni ≥ eşik
        pair = report["consensus"]["claude+codex"]
        self.assertEqual((pair["common"], pair["both_likely_false"]), (2, 2))
        self.assertEqual(pair["sweep"][0], {"threshold": 0.5, "fp_eliminated": 1, "tp_lost": 1})  # t1: min(0,6; 0,98)
        self.assertEqual((pair["zero_loss_threshold"], pair["recommended"]), (0.61, 0.66))
        self.assertEqual(pair["at_recommended"], {"threshold": 0.66, "fp_eliminated": 1, "tp_lost": 0})
        self.assertEqual(set(report["consensus"]), {"claude+codex", "claude+z", "codex+z"})
        self.assertEqual(report["consensus"]["claude+z"]["recommended"], 0.55)  # ortak likely_false yok
        self.assertEqual(report["consensus_min_confidence"], 0.66)  # çiftlerin en temkinlisi
        self.assertEqual(report["policy"], {"per_agent": report["per_agent"], "require_consensus": "auto",
                                            "consensus_min_confidence": 0.66})
        self.assertNotIn("consensus", ev.calibrate(key, [("a", claude)]))  # tek ajan: uzlaşı tablosu yok
        self.assertEqual(ev.calibrate(key, [("a", claude)], margin=0.0)["per_agent"]["claude"]["min_confidence"], 0.61)
        with self.assertRaises(ValueError):
            ev.calibrate(key, [("a", claude)], margin=0.9)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "k.json"
            key.write_text(json.dumps({"key": {"t1": {"truth": "true"}, "f1": {"truth": "false"}}}))
            res = Path(tmp) / "codex-sonuc.json"
            res.write_text(json.dumps({"results": [
                {"finding_id": "f1", "verdict": "likely_false", "confidence": 0.8, "rationale": "x"}]}))
            done = subprocess.run([sys.executable, str(APP / "scripts" / "ai_triage_eval.py"), "calibrate", "--key", str(key),
                                   "--results", str(res), "--json"], capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 0, done.stderr)
            report = json.loads(done.stdout)
            self.assertEqual(report["per_agent"], {"codex": {"enabled": True, "min_confidence": 0.55}})
            text = subprocess.run([sys.executable, str(APP / "scripts" / "ai_triage_eval.py"), "calibrate", "--key", str(key),
                                   "--results", str(res)], capture_output=True, text=True, timeout=60)
            self.assertIn("per_agent", text.stdout)


if __name__ == "__main__":
    unittest.main()
