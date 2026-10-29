"""Independent Lab detail contract exercises using local persisted records and UI runtime.

This file is newly authored from README/API and the public Task10/Task12 contracts.
It does not import or reuse the inherited Lab detail test implementation.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request, urlopen

APP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP))
import server  # noqa: E402
from scanner import normalize_target  # noqa: E402
from storage import Store  # noqa: E402

NODE = Path(os.environ.get('SNIPER_NODE_BINARY') or shutil.which('node') or '/nonexistent-node')
PROBE = APP / 'tests' / 'task44_lab_ui_probe.cjs'
UI = Path(os.environ.get('SNIPER_TASK44_APP_JS', str(APP / 'static' / 'app.js')))


class LabPublicContractRuntime(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix='sniper-task44-')
        self.db = Store(Path(self.workspace.name) / 'lab.sqlite')
        self.store_patch = patch.object(server, 'STORE', self.db)
        self.store_patch.start()
        self.http = ThreadingHTTPServer(('127.0.0.1', 0), server.SniperHandler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f'http://127.0.0.1:{self.http.server_port}'
        self.records, self.order, self.control_id = self._make_records()

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=3)
        self.store_patch.stop()
        self.workspace.cleanup()

    def _read(self, run_id):
        with urlopen(f'{self.base_url}/api/lab-runs/{run_id}', timeout=5) as response:
            self.assertEqual(response.status, 200)
            return json.load(response)

    def _make_records(self):
        target = self.db.create_target(normalize_target('https://task44.synthetic.example'))
        engagement = self.db.create_engagement(
            target_id=target['id'], name='Scoped <team> & "audit"',
            authorization_ref='AUTH-44', scope_notes='synthetic-only',
            out_of_scope='public service', test_window='2026-10-17',
            special_approvals={'staging_capacity': True, 'controlled_lockout': True, 'redacted_data_proof': True},
        )
        control_id = self.db.get_engagement(engagement['id'])['tests'][0]['control_id']
        cases = [
            {
                'scenario_type': 'capacity_plan', 'name': 'Capacity Quartz',
                'environment': 'staging', 'authorization_ref': 'AUTH-CAP-44',
                'engagement_id': engagement['id'], 'target_rps': 37,
                'duration_seconds': 91, 'baseline_latency_ms': 83,
                'max_error_percent': 1.7, 'abort_latency_ms': 711,
                'recovery_seconds': 48,
                'emergency_contact': 'Ops <sre@synthetic.invalid> & "Team"',
                'evidence_summary': 'Capacity-only evidence',
            },
            {
                'scenario_type': 'lockout_plan', 'name': 'Synthetic Lock Quartz',
                'environment': 'lab', 'authorization_ref': 'AUTH-LOCK-44',
                'synthetic_account_alias': 'synthetic-44', 'max_attempts': 4,
                'interval_seconds': 11, 'expected_lockout_seconds': 420,
                'monitoring_signal': 'auth.synthetic.counter',
                'evidence_summary': 'No real account touched',
            },
            {
                'scenario_type': 'external_result', 'name': 'Linked masked note',
                'environment': 'staging', 'authorization_ref': 'AUTH-EXT-44',
                'engagement_id': engagement['id'], 'control_id': control_id,
                'tool_name': 'Approved Lab Tool', 'test_window': '20:10–20:20 UTC',
                'evidence_hash': 'sha256:' + 'a' * 64,
                'outcome_summary': 'Masked result only',
                'evidence_summary': 'External control evidence',
            },
            {
                'scenario_type': 'external_result',
                'name': 'Hostile <script>name</script>',
                'environment': 'lab', 'authorization_ref': 'AUTH-HOSTILE-44',
                'tool_name': '<svg onload=attack()> & "bad"',
                'test_window': '<iframe src=bad>now</iframe>',
                'evidence_hash': "sha256:bad'<script>hash</script>",
                'outcome_summary': '<img src=x onerror=attack()> masked',
                'evidence_summary': 'Unlinked local evidence',
            },
        ]
        order = []
        records = {}
        for data in cases:
            created = self.db.create_lab_run(**server.build_lab_plan(data))
            run_id = created['id']
            order.append(run_id)
            records[run_id] = self._read(run_id)
        return records, order, control_id

    def _ui(self, mode, order=None):
        payload = {'mode': mode, 'records': self.records, 'order': order or self.order}
        result = subprocess.run(
            [str(NODE), str(PROBE), str(UI)], input=json.dumps(payload),
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_single_persisted_record_control_without_overlap(self):
        one_id = self.order[2]
        record = self._read(one_id)
        self.assertEqual(record['id'], one_id)
        self.assertEqual(record['name'], 'Linked masked note')
        self.assertEqual(record['status'], 'planned')
        self.assertEqual(record['results']['requests_generated_by_sniper'], 0)
        viewed = self._ui('render', [one_id])
        self.assertEqual(len(viewed['views']), 2)  # includes the deliberate missing-run probe
        initial = viewed['views'][0]
        self.assertEqual(initial['selected'], one_id)
        self.assertEqual(initial['title'], 'Linked masked note')
        self.assertEqual(initial['status'], 'planned')
        self.assertEqual(initial['evidence'], 'External control evidence')
        self.assertIn('AUTH-EXT-44', initial['html'])
        self.assertIn('Sniper tarafından üretilen trafik/istek sayısı 0', initial['html'])
        self.assertEqual(viewed['apiCalls'][0], {'url': f'/api/lab-runs/{one_id}', 'method': 'GET', 'body': None})
        self.assertTrue(all(call['method'] == 'GET' for call in viewed['apiCalls']))

    def test_missing_record_clears_the_previous_dialog_state(self):
        run_id = self.order[2]
        result = self._ui('render', [run_id])
        before, after = result['views']
        self.assertEqual(before['selected'], run_id)
        self.assertEqual(before['title'], 'Linked masked note')
        self.assertIsNone(after['selected'])
        self.assertEqual(after['title'], '')
        self.assertEqual(after['html'], '')
        self.assertEqual(after['status'], 'planned')
        self.assertEqual(after['evidence'], '')
        self.assertEqual(len([item for item in after['toasts'] if item['kind'] == 'error']), 1)
        self.assertTrue(all(call['method'] == 'GET' for call in result['apiCalls']))

    def test_persisted_get_control_and_scenario_safe_render(self):
        capacity, lockout, linked, hostile = self.order
        cap_api, lock_api, linked_api, hostile_api = [self.records[key] for key in self.order]
        for run_id, expected_type in zip(self.order, ('capacity_plan', 'lockout_plan', 'external_result', 'external_result')):
            with self.subTest(run_id=run_id):
                record = self.records[run_id]
                self.assertEqual(record['id'], run_id)
                self.assertEqual(record['scenario_type'], expected_type)
                self.assertEqual(record['status'], 'planned')
                self.assertEqual(record['results'].get('requests_generated', record['results'].get('requests_generated_by_sniper')), 0)
                self.assertEqual(self.db.get_lab_run(run_id)['id'], run_id)
        self.assertEqual(cap_api['authorization_ref'], 'AUTH-CAP-44')
        self.assertEqual(lock_api['assumptions']['synthetic_account_alias'], 'synthetic-44')
        self.assertEqual(linked_api['assumptions']['control_id'], self.control_id)
        self.assertFalse(hostile_api['assumptions'].get('control_id'))
        result = self._ui('render')
        cap, lock, ext, attack, absent = result['views']
        self.assertEqual(len(result['views']), 5)
        self.assertEqual([item['title'] for item in result['views'][:4]],
                         [self.records[run_id]['name'] for run_id in self.order])
        for item in result['views'][:4]:
            self.assertIn('Sniper tarafından üretilen trafik/istek sayısı 0', item['html'])
            self.assertEqual(item['status'], 'planned')
            self.assertTrue(item['modals'][-1][0] == 'lab-detail-modal')
        self.assertIn('data-lab-scenario-details="capacity_plan"', cap['html'])
        for piece in ('37 istek/sn', '91 sn', '83 ms', '%1.7', '711 ms', '48 sn', 'AUTH-CAP-44'):
            with self.subTest(capacity_piece=piece): self.assertIn(piece, cap['html'])
        self.assertIn('Ops &lt;sre@synthetic.invalid&gt; &amp; &quot;Team&quot;', cap['html'])
        self.assertNotIn('<sre@synthetic.invalid>', cap['html'])
        self.assertIn('Scoped &lt;team&gt; &amp; &quot;audit&quot;', cap['html'])
        self.assertEqual(cap['evidence'], 'Capacity-only evidence')
        self.assertIn('data-lab-scenario-details="lockout_plan"', lock['html'])
        for piece in ('synthetic-44', 'auth.synthetic.counter', '4 adım', '11 sn', '420 sn', 'AUTH-LOCK-44'):
            with self.subTest(lockout_piece=piece): self.assertIn(piece, lock['html'])
        self.assertNotIn('AUTH-CAP-44', lock['html'])
        self.assertNotIn('sre@synthetic.invalid', lock['html'])
        self.assertEqual(lock['evidence'], 'No real account touched')
        self.assertIn('data-lab-scenario-details="external_result"', ext['html'])
        for piece in ('Approved Lab Tool', '20:10–20:20 UTC', 'sha256:' + 'a' * 64,
                      self.control_id, 'Masked result only', 'AUTH-EXT-44'):
            with self.subTest(external_piece=piece): self.assertIn(piece, ext['html'])
        self.assertNotIn('synthetic-44', ext['html'])
        self.assertNotIn('AUTH-LOCK-44', ext['html'])
        self.assertEqual(ext['evidence'], 'External control evidence')
        self.assertIn('data-lab-scenario-details="external_result"', attack['html'])
        for forbidden in ('<script', '<svg', '<iframe', '<img', self.control_id, 'Approved Lab Tool'):
            with self.subTest(forbidden=forbidden): self.assertNotIn(forbidden, attack['html'])
        for encoded in ('&lt;svg', '&lt;iframe', '&lt;script', '&lt;img', '&amp;', '&quot;', '&#39;'):
            with self.subTest(encoded=encoded): self.assertIn(encoded, attack['html'])
        self.assertEqual(attack['title'], 'Hostile <script>name</script>')  # textContent, never innerHTML
        self.assertEqual(attack['evidence'], 'Unlinked local evidence')
        self.assertNotIn('BAĞLI KONTROL', attack['html'])
        self.assertEqual([item['selected'] for item in result['views']], self.order + [None])
        self.assertIsNone(absent['selected'])
        self.assertEqual(absent['title'], '')
        self.assertEqual(absent['html'], '')
        self.assertTrue(any(item['kind'] == 'error' for item in absent['toasts']))
        self.assertEqual([call['method'] for call in result['apiCalls']], ['GET'] * 5)
        self.assertTrue(all(call['url'].startswith('/api/lab-runs/') for call in result['apiCalls']))

    def test_out_of_order_success_and_error_leave_post_on_fast_record(self):
        slow_id, fast_id, control_id = self.order[:3]
        response = self._ui('race', [slow_id, fast_id, control_id])
        self.assertEqual(response['control']['selected'], control_id)
        self.assertEqual(response['control']['title'], self.records[control_id]['name'])
        self.assertIn('AUTH-EXT-44', response['control']['html'])
        self.assertEqual(response['firstWinner']['selected'], fast_id)
        self.assertEqual(response['firstWinner']['title'], self.records[fast_id]['name'])
        self.assertEqual(response['firstWinner']['evidence'], 'No real account touched')
        self.assertEqual(response['lateSuccess']['selected'], fast_id)
        self.assertEqual(response['lateSuccess']['title'], self.records[fast_id]['name'])
        self.assertIn('AUTH-LOCK-44', response['lateSuccess']['html'])
        self.assertNotIn('AUTH-CAP-44', response['lateSuccess']['html'])
        self.assertEqual(response['lateSuccess']['evidence'], 'No real account touched')
        posts = [call for call in response['apiCalls'] if call['method'] == 'POST']
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]['url'], f'/api/lab-runs/{fast_id}/update')
        self.assertEqual(json.loads(posts[0]['body']),
                         {'status': 'completed', 'evidence_summary': 'B-only signed evidence'})
        self.assertEqual(response['lateFailure']['selected'], fast_id)
        self.assertEqual(response['lateFailure']['title'], self.records[fast_id]['name'])
        self.assertEqual(len(response['lateFailure']['toasts']), response['priorToastCount'])
        self.assertTrue(all(item['kind'] != 'error' for item in response['lateFailure']['toasts']))
        self.assertEqual(len([call for call in response['apiCalls'] if call['method'] == 'POST']), 1)
        req = Request(
            self.base_url + posts[0]['url'], data=posts[0]['body'].encode('utf-8'),
            headers={'Content-Type': 'application/json'}, method='POST',
        )
        with urlopen(req, timeout=5) as reply:
            self.assertEqual(reply.status, 200)
        persisted_fast = self.db.get_lab_run(fast_id)
        persisted_slow = self.db.get_lab_run(slow_id)
        self.assertEqual(persisted_fast['status'], 'completed')
        self.assertEqual(persisted_fast['evidence_summary'], 'B-only signed evidence')
        self.assertEqual(persisted_slow['status'], 'planned')
        self.assertEqual(persisted_slow['evidence_summary'], 'Capacity-only evidence')
        self.assertEqual(persisted_fast['results'].get('requests_generated', persisted_fast['results'].get('requests_generated_by_sniper')), 0)
        self.assertEqual(persisted_slow['results'].get('requests_generated', persisted_slow['results'].get('requests_generated_by_sniper')), 0)
        self.assertEqual(self._read(fast_id)['status'], 'completed')
        self.assertEqual(self._read(slow_id)['status'], 'planned')
        self.assertTrue(all(call['url'].startswith('/api/lab-runs/') for call in response['apiCalls']))


if __name__ == '__main__':
    unittest.main()
