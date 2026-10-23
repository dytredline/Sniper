import hashlib
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from storage import Store


def record(kind, **other):
    return {"@timestamp": "2026-10-13T08:00:00Z", "ecs": {"version": "8.17.0"},
            "event": {"kind": kind}, **other}


class SiemEcsSummaryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.previous_store = server.STORE
        server.STORE = Store(Path(self.temp.name) / "data" / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/api/tool-reports/siem-ecs-ndjson/summary"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

    def post(self, report):
        request = Request(self.url, data=json.dumps({"report": report}).encode(), method="POST",
                          headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    def assert_bad(self, report):
        with self.assertRaises(HTTPError) as caught:
            self.post(report)
        self.assertEqual(caught.exception.code, 400)
        body = json.loads(caught.exception.read())
        caught.exception.close()
        self.assertEqual(set(body), {"error", "status"})
        self.assertEqual(body["status"], 400)
        return body["error"]

    def test_counts_saved_kinds_and_never_echoes_private_log_data(self):
        report = "\n".join(json.dumps(item) for item in (
            record("event", message="private user@example.test token=secret", user={"name": "Alice"}),
            record("alert", event={"kind": "alert", "action": "private-rule"},
                   host={"name": "private-host"}),
            record("signal", url={"full": "https://internal.example.test/secret"}),
        )) + "\n"
        result = self.post(report)
        self.assertEqual(set(result), {"format", "record_count", "kind_counts", "report_sha256"})
        self.assertEqual(result["format"], "ecs-ndjson")
        self.assertEqual(result["record_count"], 3)
        self.assertEqual(result["kind_counts"], {
            "alert": 1, "asset": 0, "enrichment": 0, "event": 1, "metric": 0,
            "state": 0, "pipeline_error": 0, "signal": 1,
        })
        self.assertEqual(result["report_sha256"], hashlib.sha256(report.encode()).hexdigest())
        output = json.dumps(result)
        for private in ("private", "secret", "Alice", "example.test", "08:00:00"):
            self.assertNotIn(private, output)

    def test_valid_offset_and_single_record(self):
        item = record("pipeline_error")
        item["@timestamp"] = "2026-10-13T11:00:00+03:00"
        result = self.post(json.dumps(item))
        self.assertEqual(result["record_count"], 1)
        self.assertEqual(result["kind_counts"]["pipeline_error"], 1)

    def test_rejects_missing_or_invalid_minimal_ecs_contract(self):
        self.assert_bad("{}")
        for field, value in (("@timestamp", "2026-10-13T08:00:00"),
                             ("@timestamp", "2026-02-30T08:00:00Z"),
                             ("ecs", {"version": 8.17}),
                             ("event", {"kind": "not-an-ecs-kind"}),
                             ("event", {"kind": []})):
            item = record("event")
            item[field] = value
            with self.subTest(field=field, value=value):
                self.assert_bad(json.dumps(item))

    def test_flat_dotted_keys_and_per_field_shapes_count_without_leaking(self):
        flat = {"@timestamp": "2026-10-13T08:00:00Z", "ecs.version": "8.17.0",
                "event.kind": "alert", "message": "private flat marker",
                "user.name": "Alice", "url.full": "https://internal.example.test/secret"}
        # Each field resolved independently: flat ecs.version + nested event.kind,
        # nested ecs.version + flat event.kind, and a nested event object that
        # carries other fields while event.kind itself is flat.
        mixed_a = {"@timestamp": "2026-10-13T08:00:00Z", "ecs.version": "8.17.0",
                   "event": {"kind": "metric", "action": "private-rule"}}
        mixed_b = {"@timestamp": "2026-10-13T08:00:00Z", "ecs": {"version": "8.17"},
                   "event.kind": "state"}
        mixed_c = {"@timestamp": "2026-10-13T08:00:00Z", "ecs.version": "8.17.0",
                   "event": {"action": "private-rule"}, "event.kind": "asset"}
        report = "\n".join(json.dumps(item) for item in (
            flat, record("signal"), mixed_a, mixed_b, mixed_c)) + "\n"
        result = self.post(report)
        self.assertEqual(set(result), {"format", "record_count", "kind_counts", "report_sha256"})
        self.assertEqual(result["record_count"], 5)
        self.assertEqual(result["kind_counts"], {
            "alert": 1, "asset": 1, "enrichment": 0, "event": 0, "metric": 1,
            "state": 1, "pipeline_error": 0, "signal": 1,
        })
        self.assertEqual(result["report_sha256"], hashlib.sha256(report.encode()).hexdigest())
        output = json.dumps(result)
        for private in ("private", "secret", "Alice", "example.test", "08:00:00"):
            self.assertNotIn(private, output)

    def test_rejects_same_field_given_both_nested_and_flat(self):
        base = {"@timestamp": "2026-10-13T08:00:00Z", "ecs.version": "8.17.0",
                "event.kind": "alert"}
        for field, changes in (
                ("ecs.version", {"ecs": {"version": "8.17.0"}}),          # identical values
                ("ecs.version", {"ecs": {"version": "1.6.0"}}),           # differing values
                ("ecs.version", {"ecs": "private-ecs"}),                  # non-object parent
                ("ecs.version", {"ecs": None}),
                ("event.kind", {"event": {"kind": "alert"}}),
                ("event.kind", {"event": {"kind": "metric", "action": "private-rule"}}),
                ("event.kind", {"event": ["private-event"]}),
                ("event.kind", {"event.kind": None, "event": {"kind": "alert"}})):
            with self.subTest(changes=changes):
                error = self.assert_bad(json.dumps({**base, **changes}))
                self.assertEqual(error, f"İç içe ve düz {field} alanları çakışıyor")
                self.assertNotIn("private", error)
        # A conflicting line anywhere rejects the whole report, not just that line.
        conflict = json.dumps({**base, "event": {"kind": "alert"}})
        self.assert_bad(json.dumps(record("event")) + "\n" + conflict + "\n")

    def test_rejects_incomplete_or_invalid_flat_records(self):
        flat = {"@timestamp": "2026-10-13T08:00:00Z", "ecs.version": "8.17.0",
                "event.kind": "alert"}
        for changes, expected in (({"event.kind": None}, "Geçersiz event.kind"),
                                  ({"event.kind": "not-an-ecs-kind"}, "Geçersiz event.kind"),
                                  ({"event.kind": ["alert"]}, "Geçersiz event.kind"),
                                  ({"ecs.version": "not-a-version"}, "Geçersiz ecs.version"),
                                  ({"ecs.version": 8.17}, "Geçersiz ecs.version"),
                                  ({"ecs.version": None}, "Geçersiz ecs.version"),
                                  ({"@timestamp": "2026-10-13T08:00:00"}, "@timestamp")):
            with self.subTest(changes=changes):
                self.assertIn(expected, self.assert_bad(json.dumps({**flat, **changes})))
        missing_kind = {key: value for key, value in flat.items() if key != "event.kind"}
        self.assertEqual(self.assert_bad(json.dumps(missing_kind)), "Geçersiz event.kind")
        missing_version = {key: value for key, value in flat.items() if key != "ecs.version"}
        self.assertEqual(self.assert_bad(json.dumps(missing_version)), "ecs.version gerekli")
        # Duplicate dotted keys stay rejected by the duplicate-key guard.
        self.assert_bad('{"@timestamp":"2026-10-13T08:00:00Z",'
                        '"ecs.version":"8.17.0","event.kind":"alert",'
                        '"event.kind":"metric"}')
        # Deeper dotted spellings are not an accepted alias for these fields.
        self.assert_bad(json.dumps({"@timestamp": "2026-10-13T08:00:00Z",
                                    "ecs": {"version": "8.17.0"}, "event": {"kind.x": "alert"}}))

    def test_rejects_duplicate_keys_nonfinite_and_invalid_jsonl(self):
        self.assert_bad('{"@timestamp":"2026-10-13T08:00:00Z","ecs":{"version":"8.17.0"},'
                        '"event":{"kind":"event","kind":"alert"}}')
        self.assert_bad('{"@timestamp":"2026-10-13T08:00:00Z","ecs":{"version":"8.17.0"},'
                        '"event":{"kind":"event"},"private":NaN}')
        self.assert_bad('{"@timestamp":"2026-10-13T08:00:00Z","ecs":{"version":"8.17.0"},'
                        '"event":{"kind":"event"},"private":1e999}')
        self.assert_bad(json.dumps(record("event")) + "\n\n" + json.dumps(record("alert")))
        self.assert_bad("[" + json.dumps(record("event")) + "]")

    def test_literal_unicode_line_separators_inside_json_strings(self):
        for separator in ("\u2028", "\u2029", "\u0085"):
            with self.subTest(separator=ord(separator)):
                item = record("event", message="before" + separator + "after")
                report = json.dumps(item, ensure_ascii=False) + "\n" + json.dumps(record("alert")) + "\n"
                result = self.post(report)
                self.assertEqual(result["record_count"], 2)
                self.assertEqual(result["kind_counts"]["event"], 1)
                self.assertEqual(result["kind_counts"]["alert"], 1)
                self.assertEqual(result["report_sha256"], hashlib.sha256(report.encode()).hexdigest())

    def test_jsonl_accepts_crlf_but_not_bare_cr_record_separator(self):
        first = json.dumps(record("event"))
        second = json.dumps(record("alert"))
        result = self.post(first + "\r\n" + second + "\r\n")
        self.assertEqual(result["record_count"], 2)
        self.assert_bad(first + "\r" + second)

    def test_report_byte_and_record_limits(self):
        self.assert_bad("x" * 60001)
        self.assert_bad("\n".join(json.dumps(record("event")) for _ in range(501)))


if __name__ == "__main__":
    unittest.main()
