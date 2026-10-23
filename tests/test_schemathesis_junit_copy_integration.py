from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from html.parser import HTMLParser
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

import server
from storage import Store


ROOT = Path(__file__).resolve().parent.parent
UI_ROOT = Path(os.environ.get('SNIPER_TEST_UI_ROOT', str(ROOT))).resolve()
DRIVER = Path(__file__).with_name('task45_schemathesis_ui_driver.cjs')
ROUTE = '/api/tool-reports/schemathesis-junit/summary'
REPORT = ('<?xml version="1.0"?><testsuite name="synthetic-api">'
          '<testcase name="GET /canary"><failure message="token=HIDDEN_CANARY">'
          'PRIVATE_BODY_CANARY</failure></testcase>'
          '<testcase name="GET /health"/></testsuite>')


class IdTags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = {}

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if 'id' in attributes:
            self.tags[attributes['id']] = (tag, attributes)


class SchemathesisDigestCopyIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous_store = server.STORE
        server.STORE = Store(Path(self.temp.name) / 'data' / 'sniper.db')
        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = 'http://127.0.0.1:' + str(self.httpd.server_address[1])

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

    def test_saved_summary_control_uses_real_http_and_redacts_report(self):
        payload = json.dumps({'report': REPORT}).encode('utf-8')
        request = Request(self.base_url + ROUTE, data=payload, method='POST',
                          headers={'Content-Type': 'application/json'})
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            aggregate = json.loads(response.read())
        self.assertEqual(aggregate['format'], 'schemathesis-junit-xml')
        self.assertEqual(aggregate['suite_count'], 1)
        self.assertEqual(aggregate['testcase_count'], 2)
        self.assertEqual(aggregate['outcome_counts'],
                         {'passed': 1, 'failed': 1, 'errors': 0, 'skipped': 0})
        self.assertEqual(aggregate['report_sha256'],
                         hashlib.sha256(REPORT.encode('utf-8')).hexdigest())
        self.assertNotIn('HIDDEN_CANARY', json.dumps(aggregate))
        self.assertNotIn('PRIVATE_BODY_CANARY', json.dumps(aggregate))

    def test_real_html_module_clipboard_and_http_lifecycle(self):
        html_path = UI_ROOT / 'static' / 'index.html'
        module_path = UI_ROOT / 'static' / 'schemathesis_junit_preview.js'
        catalog = IdTags()
        catalog.feed(html_path.read_text(encoding='utf-8'))
        self.assertIn('schemathesis-junit-preview-form', catalog.tags)
        self.assertIn('schemathesis-junit-report-sha256', catalog.tags)
        self.assertIn('schemathesis-junit-preview-result', catalog.tags)
        node = os.environ.get('SNIPER_NODE_BIN') or shutil.which('node')
        self.assertTrue(node, 'Node.js is required for the focused UI integration test')
        run = subprocess.run([node, str(DRIVER), str(html_path), str(module_path),
                              self.base_url, REPORT], capture_output=True, text=True,
                             timeout=20, check=False)
        self.assertEqual(run.returncode, 0, msg=run.stderr)
        state = json.loads(run.stdout)
        expected = hashlib.sha256(REPORT.encode('utf-8')).hexdigest()
        imported = state['importState']
        self.assertEqual(imported['digest'], expected)
        self.assertFalse(imported['resultHidden'])
        self.assertEqual(imported['requestCount'], 1)
        self.assertEqual(imported['suites'], '1')
        self.assertEqual(imported['cases'], '2')
        self.assertIn('başarısız:1', imported['outcomes'])
        self.assertEqual(state['requests'][0], {'route': ROUTE, 'method': 'POST',
                         'keys': ['report'], 'reportSha256': expected})
        self.assertNotIn('HIDDEN_CANARY', run.stdout)
        self.assertNotIn('PRIVATE_BODY_CANARY', run.stdout)

        copy_id = 'schemathesis-junit-copy-sha256'
        status_id = 'schemathesis-junit-copy-status'
        self.assertTrue(copy_id in catalog.tags, 'saved JUnit preview must contain a copy control')
        self.assertIn(status_id, catalog.tags)
        button_tag, button_attrs = catalog.tags[copy_id]
        status_tag, status_attrs = catalog.tags[status_id]
        self.assertEqual(button_tag, 'button')
        self.assertEqual(button_attrs.get('type'), 'button')
        self.assertIn('hidden', button_attrs)
        self.assertIn('disabled', button_attrs)
        self.assertIn('schemathesis-junit-report-sha256',
                      button_attrs.get('aria-describedby', ''))
        self.assertEqual(status_tag, 'output')
        self.assertEqual(status_attrs.get('role'), 'status')
        self.assertEqual(status_attrs.get('aria-live'), 'polite')
        self.assertTrue(state['initial']['disabled'])
        self.assertTrue(state['initial']['hidden'])
        self.assertFalse(imported['buttonDisabled'])
        self.assertFalse(imported['buttonHidden'])
        self.assertRegex(imported['buttonLabel'], r'(?i)kopyala')
        self.assertRegex(imported['digest'], r'^[0-9a-f]{64}$')

        success = state['success']
        self.assertEqual(success['clipboardWrites'], [expected])
        self.assertEqual(success['requestCount'], 1, 'copy must not make a second API request')
        self.assertRegex(success['status'], r'(?i)panoya kopyalandı')
        denial = state['denial']
        self.assertEqual(denial['clipboardWrites'], [expected])
        self.assertEqual(denial['requestCount'], 1)
        self.assertNotRegex(denial['status'], r'(?i)panoya kopyalandı')
        self.assertRegex(denial['status'], r'(?i)kopyalanamadı')
        self.assertNotIn('HIDDEN_CANARY', denial['status'])
        self.assertNotIn('PRIVATE_BODY_CANARY', denial['status'])
        self.assertEqual(denial['digest'], expected)
        self.assertFalse(denial['resultHidden'])

        closed = state['closed']
        self.assertTrue(closed['disabled'])
        self.assertTrue(closed['hidden'])
        self.assertEqual(closed['status'], '')
        self.assertEqual(closed['digest'], '')
        reopened = state['reopened']
        self.assertTrue(reopened['disabled'])
        self.assertTrue(reopened['hidden'])
        self.assertEqual(reopened['status'], '')
        self.assertEqual(reopened['digest'], '')
        invalid = state['invalid']
        self.assertTrue(invalid['disabled'])
        self.assertTrue(invalid['hidden'])
        self.assertTrue(invalid['resultHidden'])
        self.assertEqual(invalid['digest'], '')
        self.assertEqual(invalid['status'], '')
        self.assertEqual(invalid['clipboardWrites'], [expected])
        self.assertEqual(invalid['requestCount'], 2)
        self.assertEqual([call['route'] for call in state['requests']], [ROUTE, ROUTE])
        self.assertEqual([call['method'] for call in state['requests']], ['POST', 'POST'])
        self.assertEqual(state['requests'][1]['reportSha256'],
                         hashlib.sha256(b'<not-junit/>').hexdigest())


if __name__ == '__main__':
    unittest.main()
