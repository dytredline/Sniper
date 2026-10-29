"""Sniper 5'li Burp Suite eşdeğeri modüllerin (Repeater/Comparer, Autorize, Race Runner,
Token Sequencer, Traffic Decoder/Inspector) çalışma zamanı ve API/CLI regresyon testleri.
"""
from __future__ import annotations

import base64
import json
import secrets
import sys
import threading
import unittest
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
if str(APP_ROOT) in sys.path:
    sys.path.remove(str(APP_ROOT))
sys.path.insert(0, str(APP_ROOT))

import importlib
import autorize_matrix_tester
import cli_reports
importlib.reload(cli_reports)
import dom_invader_gadget_auditor
import http_repeater_comparer
import intruder_param_miner
import race_condition_runner
import smuggling_cache_poison_prober
import token_sequencer
import traffic_decoder_inspector


class BurpEquivWorkbenchTests(unittest.TestCase):
    def test_repeater_and_comparer_detects_price_tampering_and_mass_assignment(self) -> None:
        base_req = {
            "method": "POST",
            "url": "http://127.0.0.1/api/checkout",
            "headers": {"Authorization": "Bearer secret_user_jwt_token_value"},
            "json_body": {"item_id": 10, "price": 5000, "role": "user"},
        }

        def vulnerable_checkout_handler(req: dict) -> dict:
            body = req.get("json_body") or {}
            return {
                "status_code": 200,
                "headers": {"X-Auth-Echo": req["headers"].get("Authorization", "")},
                "body": {
                    "charged_price": body.get("price", 5000),
                    "role": body.get("role", "user"),
                    "ok": True,
                },
            }

        res_red = http_repeater_comparer.execute_loopback_repeater_mutation(
            base_req,
            {"json_body_overrides": {"price": 0, "role": "admin"}},
            target_handler_fn=vulnerable_checkout_handler,
        )
        self.assertEqual(res_red["format"], "sniper-http-repeater-comparer/1")
        self.assertGreaterEqual(res_red["finding_count"], 2)
        control_ids = {f["control_id"] for f in res_red["findings"]}
        self.assertIn("SNIPER-REPEATER-LOGIC-02", control_ids)
        self.assertIn("SNIPER-REPEATER-MASS-03", control_ids)

        def safe_checkout_handler(_req: dict) -> dict:
            return {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": {"charged_price": 5000, "role": "user", "ok": True},
            }

        res_green = http_repeater_comparer.execute_loopback_repeater_mutation(
            base_req,
            {"json_body_overrides": {"price": 0, "role": "admin"}},
            target_handler_fn=safe_checkout_handler,
        )
        self.assertEqual(res_green["finding_count"], 0)
        self.assertEqual(res_green["similarity_ratio"], 1.0)

        # Dış ağ URL'leri canlı Repeater'da reddedilmeli (yalnızca loopback izinli)
        with self.assertRaises(ValueError):
            http_repeater_comparer.execute_loopback_repeater_mutation(
                {"method": "GET", "url": "https://example.com/api"},
                {},
            )

    def test_autorize_matrix_detects_idor_unauth_and_mass_assignment(self) -> None:
        def vulnerable_api_handler(req: dict) -> dict:
            body = req.get("json_body") or {}
            return {
                "status_code": 200,
                "body": {
                    "order_id": 1055,
                    "owner": "user_a",
                    "iban": "TR0011223344",
                    "role": body.get("role", "user"),
                },
            }

        red_report = autorize_matrix_tester.run_loopback_autorize_probe(
            {
                "endpoint": "PATCH /api/orders/1055",
                "request": {"method": "PATCH", "json_body": {"note": "test"}},
                "injected_fields": {"role": "admin"},
            },
            target_handler_fn=vulnerable_api_handler,
        )
        self.assertEqual(red_report["format"], "sniper-autorize-matrix-report/1")
        self.assertEqual(red_report["finding_count"], 3)
        cids = {f["control_id"] for f in red_report["findings"]}
        self.assertEqual(cids, {"SNIPER-AUTORIZE-IDOR-01", "SNIPER-AUTORIZE-UNAUTH-02", "SNIPER-AUTORIZE-MASS-03"})

        def safe_api_handler(req: dict) -> dict:
            headers = req.get("headers") or {}
            if not headers.get("X-User-Id"):
                return {"status_code": 401, "body": {"error": "unauthorized"}}
            if headers.get("X-User-Id") != "user_a":
                return {"status_code": 403, "body": {"error": "forbidden"}}
            return {
                "status_code": 200,
                "body": {"order_id": 1055, "owner": "user_a", "role": "user"},
            }

        green_report = autorize_matrix_tester.run_loopback_autorize_probe(
            {
                "endpoint": "PATCH /api/orders/1055",
                "request": {"method": "PATCH", "json_body": {"note": "test"}},
                "injected_fields": {"role": "admin"},
            },
            target_handler_fn=safe_api_handler,
        )
        self.assertEqual(green_report["finding_count"], 0)
        self.assertEqual(green_report["matrix"][0]["cross_user_verdict"], "enforced")
        self.assertEqual(green_report["matrix"][0]["unauthenticated_verdict"], "enforced")
        self.assertEqual(green_report["matrix"][0]["mass_assignment_verdict"], "enforced")

    def test_parallel_race_condition_runner_catches_toctou_double_spend(self) -> None:
        # RED: Kilitsiz TOCTOU kupon kullanımı
        coupon_state = {"used": False}

        def unguarded_redeem(_slot: int) -> dict:
            if not coupon_state["used"]:
                # Yarış penceresi
                threading.Event().wait(0.01)
                coupon_state["used"] = True
                return {"status_code": 200, "ok": True}
            return {"status_code": 409, "ok": False}

        race_red = race_condition_runner.run_barrier_synchronized_race_probe(
            unguarded_redeem,
            concurrency=6,
            expected_max_success=1,
            operation_label="POST /api/coupons/redeem",
        )
        self.assertTrue(race_red["race_reproduced"])
        self.assertGreater(race_red["actual_success_count"], 1)
        self.assertEqual(race_red["findings"][0]["control_id"], "SNIPER-RACE-TOCTOU-01")

        # GREEN: Atomik kilitli kupon kullanımı
        safe_lock = threading.Lock()
        safe_state = {"used": False}

        def guarded_redeem(_slot: int) -> dict:
            with safe_lock:
                if safe_state["used"]:
                    return {"status_code": 409, "ok": False}
                safe_state["used"] = True
                return {"status_code": 200, "ok": True}

        race_green = race_condition_runner.run_barrier_synchronized_race_probe(
            guarded_redeem,
            concurrency=6,
            expected_max_success=1,
            operation_label="POST /api/coupons/redeem",
        )
        self.assertFalse(race_green["race_reproduced"])
        self.assertEqual(race_green["actual_success_count"], 1)
        self.assertEqual(race_green["finding_count"], 0)

    def test_token_sequencer_distinguishes_predictable_and_csprng_tokens(self) -> None:
        weak_tokens = [f"SESS_173000010{i}" for i in range(8)]
        weak_res = token_sequencer.analyze_token_sequence_entropy(weak_tokens, token_label="reset_code")
        self.assertTrue(weak_res["sequential_pattern_detected"])
        self.assertTrue(weak_res["timestamp_leak_detected"])
        self.assertEqual(weak_res["quality_grade"], "critical_predictable")
        self.assertEqual(weak_res["finding_count"], 1)
        self.assertEqual(weak_res["findings"][0]["control_id"], "SNIPER-SEQUENCER-WEAK-01")

        strong_tokens = [secrets.token_urlsafe(32) for _ in range(16)]
        strong_res = token_sequencer.analyze_token_sequence_entropy(strong_tokens, token_label="session_cookie")
        self.assertFalse(strong_res["sequential_pattern_detected"])
        self.assertEqual(strong_res["finding_count"], 0)
        self.assertIn(strong_res["quality_grade"], {"good", "excellent"})

    def test_traffic_decoder_and_inspector_unwraps_nested_jwt_and_ssrf(self) -> None:
        # 1. alg: none JWT
        hdr = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode("ascii").rstrip("=")
        pay = base64.urlsafe_b64encode(b'{"sub":"admin","role":"admin"}').decode("ascii").rstrip("=")
        unsigned_jwt = f"{hdr}.{pay}."
        dec_jwt = traffic_decoder_inspector.recursive_decode_and_inspect(unsigned_jwt)
        self.assertIn("jwt_alg_none_or_unsigned", dec_jwt["detected_signals"])
        self.assertEqual(dec_jwt["findings"][0]["control_id"], "SNIPER-DECODER-JWT-01")

        # 2. URL + Base64 kodlu IMDS SSRF hedefi ve HAR incelemesi
        b64_imds = base64.b64encode(b"http://169.254.169.254/latest/meta-data/").decode("ascii")
        inspector_res = traffic_decoder_inspector.inspect_har_or_http_exchange({
            "method": "POST",
            "url": f"http://127.0.0.1/api/fetch?target={b64_imds}",
            "headers": {"Authorization": f"Bearer {unsigned_jwt}"},
            "json_body": {"price": 100},
        })
        self.assertEqual(inspector_res["format"], "sniper-traffic-inspector/1")
        self.assertGreaterEqual(inspector_res["decoded_field_count"], 2)
        self.assertGreaterEqual(inspector_res["finding_count"], 2)
        self.assertIn("repeater_template", inspector_res)
        self.assertIn("autorize_template", inspector_res)

        # 3. CLI export fonksiyonları doğrulaması
        sample_audit = {
            "baseline_response": {"status_code": 403, "body": {"error": "forbidden"}},
            "mutated_response": {"status_code": 200, "body": {"price": 0, "role": "admin"}},
            "autorize_probes": [{
                "endpoint": "GET /api/secret/1",
                "owner_response": {"status": 200, "body": {"secret": "val"}},
                "other_user_response": {"status": 200, "body": {"secret": "val"}},
            }],
            "token_samples": [f"SESS_173000010{i}" for i in range(8)],
            "http_exchange": {"method": "GET", "url": f"http://127.0.0.1/cb?u={b64_imds}"},
        }
        self.assertEqual(json.loads(cli_reports.export_http_repeater_diff_json(sample_audit))["format"], "sniper-http-repeater-comparer/1")
        self.assertEqual(json.loads(cli_reports.export_autorize_matrix_json(sample_audit))["format"], "sniper-autorize-matrix-report/1")
        self.assertEqual(json.loads(cli_reports.export_token_sequencer_json(sample_audit))["format"], "sniper-token-sequencer-report/1")
        self.assertEqual(json.loads(cli_reports.export_traffic_inspector_json(sample_audit))["format"], "sniper-traffic-inspector/1")

    def test_intruder_4_modes_and_param_miner_discover_hidden_surface(self) -> None:
        tpl = "user=§alice§&pin=§0000§"
        sniper_plan = intruder_param_miner.generate_intruder_payload_positions(tpl, [["admin", "guest"]], attack_type="sniper")
        self.assertEqual(sniper_plan["request_count"], 4)
        ram_plan = intruder_param_miner.generate_intruder_payload_positions(tpl, [["X", "Y"]], attack_type="battering_ram")
        self.assertEqual(ram_plan["requests"][0]["rendered"], "user=X&pin=X")
        pf_plan = intruder_param_miner.generate_intruder_payload_positions(tpl, [["u1", "u2"], ["p1", "p2"]], attack_type="pitchfork")
        self.assertEqual(pf_plan["requests"][1]["rendered"], "user=u2&pin=p2")
        cb_plan = intruder_param_miner.generate_intruder_payload_positions(tpl, [["u1", "u2"], ["p1", "p2"]], attack_type="cluster_bomb")
        self.assertEqual(cb_plan["request_count"], 4)

        def blind_sqli_handler(rendered: str) -> dict:
            if "SLEEP" in rendered:
                return {"status_code": 200, "body": "OK", "elapsed_ms": 820.0}
            if "' OR 1=1" in rendered:
                return {"status_code": 500, "body": "SQL syntax error near OR", "elapsed_ms": 5.0}
            return {"status_code": 200, "body": "normal", "elapsed_ms": 5.0}

        camp = intruder_param_miner.execute_intruder_campaign(
            "id=§1§",
            [["' OR 1=1", "1; SLEEP(5)"]],
            target_handler_fn=blind_sqli_handler,
            attack_type="sniper",
            grep_match_patterns=["SQL syntax error"],
            time_anomaly_threshold_ms=500.0,
        )
        cids = {f["control_id"] for f in camp["findings"]}
        self.assertEqual(cids, {"SNIPER-INTRUDER-GREP-01", "SNIPER-INTRUDER-TIMING-02"})

        def hidden_param_handler(req: dict) -> dict:
            qp = req.get("query_params") or {}
            hdrs = req.get("headers") or {}
            if qp.get("debug") == "true" or hdrs.get("X-Original-URL") == "/admin":
                return {"status_code": 200, "body": "ADMIN_DEBUG_CONSOLE_ACTIVE"}
            return {"status_code": 403, "body": "Access Denied"}

        mined = intruder_param_miner.mine_unlinked_parameters_and_headers(
            {"method": "GET", "url": "http://127.0.0.1/panel"},
            target_handler_fn=hidden_param_handler,
            candidate_params=["debug", "noop"],
            candidate_headers=["X-Original-URL", "X-Noop"],
        )
        self.assertEqual(len(mined["discovered_parameters"]), 1)
        self.assertEqual(len(mined["discovered_headers"]), 1)
        self.assertEqual(mined["finding_count"], 2)

    def test_dom_invader_auditor_catches_cspp_gadget_clobbering_and_postmessage(self) -> None:
        vuln_js = """
        const params = new URLSearchParams(location.search);
        deepMerge(appConfig, Object.fromEntries(params));
        scriptEl.src = appConfig.transport_url;
        const cfg = window.APP_CFG || document.getElementById('cfg');
        window.addEventListener('message', (ev) => {
            document.getElementById('out').innerHTML = ev.data;
        });
        """
        res_red = dom_invader_gadget_auditor.audit_dom_invader_cspp_and_gadgets(vuln_js, filename="widget.js")
        self.assertEqual(res_red["finding_count"], 4)
        cids = {f["control_id"] for f in res_red["findings"]}
        self.assertEqual(
            cids,
            {"SNIPER-DOM-CSPP-01", "SNIPER-DOM-GADGET-02", "SNIPER-DOM-CLOBBER-03", "SNIPER-DOM-POSTMSG-04"},
        )

        safe_js = """
        const safeObj = Object.create(null);
        if (Object.hasOwn(safeObj, 'url') && !key.includes('__proto__') && !key.includes('constructor') && !key.includes('prototype')) {}
        window.addEventListener('message', (ev) => {
            if (ev.origin !== 'https://trusted.example') return;
            document.getElementById('out').textContent = String(ev.data);
        });
        """
        res_green = dom_invader_gadget_auditor.audit_dom_invader_cspp_and_gadgets(safe_js, filename="safe.js")
        self.assertEqual(res_green["finding_count"], 0)

    def test_smuggling_differential_and_web_cache_poisoning_prober(self) -> None:
        smug_red = smuggling_cache_poison_prober.evaluate_smuggling_differential_probes([
            {
                "variant": "CL.TE",
                "baseline_status": 200,
                "baseline_elapsed_ms": 15.0,
                "ambiguous_elapsed_ms": 2200.0,
                "followup_victim_status": 404,
                "poisoned_prefix_reflected": True,
            }
        ])
        self.assertEqual(smug_red["finding_count"], 1)
        self.assertEqual(smug_red["findings"][0]["control_id"], "SNIPER-SMUGGLE-DESYNC-01")

        cache_store: dict[str, dict] = {}

        def vulnerable_cdn_handler(req: dict) -> dict:
            cb = (req.get("query_params") or {}).get("_cb", "default")
            if cb not in cache_store:
                fwd_host = (req.get("headers") or {}).get("X-Forwarded-Host", "legit.local")
                cache_store[cb] = {
                    "status_code": 200,
                    "headers": {"X-Cache": "MISS"},
                    "body": f'<script src="https://{fwd_host}/app.js"></script>',
                }
            return cache_store[cb]

        cp_red = smuggling_cache_poison_prober.run_loopback_cache_poisoning_probe(
            {"method": "GET", "url": "http://127.0.0.1/index.html"},
            target_handler_fn=vulnerable_cdn_handler,
        )
        self.assertTrue(cp_red["cache_poisoned"])
        self.assertEqual(cp_red["findings"][0]["control_id"], "SNIPER-CACHE-POISON-01")


if __name__ == "__main__":
    unittest.main()
