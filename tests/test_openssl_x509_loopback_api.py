import hashlib
import json
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler

import server
from storage import Store


class _QuietHandler(BaseHTTPRequestHandler):
    def handle(self):
        try:
            self.connection.recv(1)
        except (OSError, TimeoutError):
            pass

    def log_message(self, *_args):
        pass


def _run(*args):
    subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, check=True, timeout=15)


class OpenSSLX509LoopbackAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='openssl-loopback-test-')
        cls.base = Path(cls.temp.name)
        cls.ca_key = cls.base / 'ca.key'
        cls.ca_pem = cls.base / 'ca.pem'
        _run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '8',
             '-keyout', str(cls.ca_key), '-out', str(cls.ca_pem),
             '-subj', '/CN=Sniper Synthetic CA',
             '-addext', 'basicConstraints=critical,CA:TRUE',
             '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        cls.certificates = {}
        for label, san in (('ip', 'IP:127.0.0.1'), ('dns', 'DNS:localhost')):
            key = cls.base / f'{label}.key'
            csr = cls.base / f'{label}.csr'
            pem = cls.base / f'{label}.pem'
            ext = cls.base / f'{label}.ext'
            ext.write_text(f'subjectAltName={san}\nbasicConstraints=critical,CA:FALSE\n'
                           'keyUsage=critical,digitalSignature,keyEncipherment\n'
                           'extendedKeyUsage=serverAuth\n')
            _run('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
                 '-keyout', str(key), '-out', str(csr), '-subj', '/CN=PrivateFixture')
            _run('openssl', 'x509', '-req', '-in', str(csr), '-CA', str(cls.ca_pem),
                 '-CAkey', str(cls.ca_key), '-CAcreateserial', '-out', str(pem),
                 '-days', '2', '-extfile', str(ext))
            cls.certificates[label] = (pem, key)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.env = os.environ.copy()
        self.previous_store = server.STORE
        self.scratch = tempfile.TemporaryDirectory(prefix='openssl-run-', dir=self.base)
        self.data = Path(self.scratch.name)
        self.trust = self.data / 'openssl-trust-ca.pem'
        self.trust.write_bytes(self.ca_pem.read_bytes())
        self.trust.chmod(0o600)
        os.environ['SNIPER_DATA_DIR'] = str(self.data)
        os.environ['SNIPER_OPENSSL_CA_SHA256'] = hashlib.sha256(self.trust.read_bytes()).hexdigest()
        os.environ['SNIPER_OPENSSL_BINARY_SHA256'] = hashlib.sha256(Path('/usr/bin/openssl').read_bytes()).hexdigest()
        server.STORE = Store(self.data / 'sniper.db')
        self.http = ThreadingHTTPServer(('127.0.0.1', 0), server.SniperHandler)
        self.http.daemon_threads = True
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f'http://127.0.0.1:{self.http.server_port}'
        self.opener = build_opener(ProxyHandler({}))
        self.tls = None
        self.tls_thread = None

    def tearDown(self):
        if self.tls:
            self.tls.shutdown()
            self.tls.server_close()
            self.tls_thread.join(timeout=3)
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=3)
        server.STORE = self.previous_store
        os.environ.clear()
        os.environ.update(self.env)
        self.scratch.cleanup()

    def tls_server(self, cert='ip'):
        pem, key = self.certificates[cert]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(pem), str(key))
        self.tls = ThreadingHTTPServer(('127.0.0.1', 0), _QuietHandler)
        self.tls.daemon_threads = True
        self.tls.socket = ctx.wrap_socket(self.tls.socket, server_side=True)
        self.tls_thread = threading.Thread(target=self.tls.serve_forever, daemon=True)
        self.tls_thread.start()
        return self.tls.server_port

    def post(self, route, payload):
        req = Request(self.origin + route, method='POST',
                      data=json.dumps(payload).encode('utf-8'),
                      headers={'Content-Type': 'application/json'})
        try:
            with self.opener.open(req, timeout=9) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def active(self, target, **other):
        payload = {'confirm_local': True, 'target': target}
        payload.update(other)
        return self.post('/api/tool-runs/openssl-x509-loopback', payload)

    def authorized(self, target, **other):
        payload = {'confirm_authorized': True, 'target': target}
        payload.update(other)
        return self.post('/api/tool-runs/openssl-x509-authorized', payload)

    def test_verified_ip_peer_returns_actual_expiry_aggregate(self):
        port = self.tls_server()
        status, body = self.active(f'127.0.0.1:{port}')
        self.assertEqual(status, 200)
        self.assertEqual(body['format'], 'openssl-x509-loopback-v1')
        self.assertEqual(body['verification'], 'passed')
        self.assertEqual(body['validity'], 'expiring_soon')
        self.assertGreaterEqual(body['days_until_expiry'], 1)
        self.assertLessEqual(body['days_until_expiry'], 3)
        self.assertLess(datetime.now(timezone.utc).timestamp(),
                        datetime.fromisoformat(body['not_after_utc'].replace('Z', '+00:00')).timestamp())
        self.assertRegex(body['report_sha256'], r'^[0-9a-f]{64}$')
        allowed = {key: body[key] for key in (
            'format', 'verification', 'validity', 'not_before_utc',
            'not_after_utc', 'days_until_expiry')}
        canonical = json.dumps(allowed, sort_keys=True, separators=(',', ':'),
                               ensure_ascii=False, allow_nan=False).encode()
        self.assertEqual(body['report_sha256'], hashlib.sha256(canonical).hexdigest())
        text = json.dumps(body)
        for secret in ('127.0.0.1', 'PrivateFixture', 'BEGIN CERTIFICATE', 'Fingerprint', str(port)):
            self.assertNotIn(secret, text)

    def test_wrong_ca_rejects_without_claiming_verified_dates(self):
        port = self.tls_server()
        self.trust.write_bytes(self.certificates['ip'][0].read_bytes())
        os.environ['SNIPER_OPENSSL_CA_SHA256'] = hashlib.sha256(self.trust.read_bytes()).hexdigest()
        status, body = self.active(f'127.0.0.1:{port}')
        self.assertEqual(status, 200)
        self.assertEqual(body, {'format': 'openssl-x509-loopback-v1', 'verification': 'rejected'})

    def test_dns_only_certificate_rejects_ip_identity(self):
        port = self.tls_server('dns')
        status, body = self.active(f'127.0.0.1:{port}')
        self.assertEqual(status, 200)
        self.assertEqual(body['verification'], 'rejected')
        self.assertNotIn('validity', body)

    def test_authorized_target_route_runs_real_bounded_tls_and_writes_audit_receipt(self):
        port = self.tls_server()
        status, body = self.authorized(f'https://127.0.0.1:{port}')
        self.assertEqual(status, 200)
        self.assertEqual(body['format'], 'openssl-x509-authorized-v1')
        self.assertEqual(body['verification'], 'passed')
        self.assertEqual(body['normalized_target'], f'https://127.0.0.1:{port}')
        self.assertEqual(body['consent_version'], 'authorized-tls-target-v1')
        self.assertRegex(body['report_sha256'], r'^[0-9a-f]{64}$')

        receipt = server.STORE.recent_audit_log(5)[0]
        self.assertEqual(receipt['action'], 'openssl_x509.authorized.completed')
        self.assertEqual(receipt['entity_id'], 'openssl-x509-authorized')
        self.assertEqual(receipt['details']['normalized_target'], body['normalized_target'])
        self.assertEqual(receipt['details']['consent_version'], body['consent_version'])
        self.assertEqual(receipt['details']['actor']['username'], 'local-operator')
        self.assertRegex(receipt['occurred_at'], r'^\d{4}-\d\d-\d\dT')

    def test_authorized_target_requires_exact_boolean_consent_and_unambiguous_https_url(self):
        route = '/api/tool-runs/openssl-x509-authorized'
        invalid = (
            {'target': 'https://example.com'},
            {'confirm_authorized': False, 'target': 'https://example.com'},
            {'confirm_authorized': 1, 'target': 'https://example.com'},
            {'confirm_authorized': True, 'target': 'http://example.com'},
            {'confirm_authorized': True, 'target': 'https://user@example.com'},
            {'confirm_authorized': True, 'target': 'https://example.com/a'},
            {'confirm_authorized': True, 'target': 'https://example.com?x=1'},
            {'confirm_authorized': True, 'target': 'https://example.com\\@127.0.0.1'},
            {'confirm_authorized': True, 'target': 'https://example.com', 'extra': True},
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                status, _ = self.post(route, payload)
                self.assertEqual(status, 400)
        self.assertFalse(any(row['action'] == 'openssl_x509.authorized.completed'
                             for row in server.STORE.recent_audit_log(20)))

    def test_rejects_without_consent_or_forbidden_target_before_connection(self):
        for payload in (
            {'target': '127.0.0.1:443'},
            {'confirm_local': False, 'target': '127.0.0.1:443'},
            {'confirm_local': True, 'target': 'localhost:443'},
            {'confirm_local': True, 'target': '8.8.8.8:443'},
            {'confirm_local': True, 'target': '127.0.0.1:0'},
            {'confirm_local': True, 'target': '127.0.0.1:65536'},
            {'confirm_local': True, 'target': '127.0.0.1:443', 'extra': True},
        ):
            with self.subTest(payload=payload):
                status, _ = self.post('/api/tool-runs/openssl-x509-loopback', payload)
                self.assertEqual(status, 400)

    def test_missing_or_mismatched_pins_fail_closed(self):
        for key in ('SNIPER_OPENSSL_CA_SHA256', 'SNIPER_OPENSSL_BINARY_SHA256'):
            original = os.environ[key]
            try:
                os.environ[key] = '0' * 64
                status, _ = self.active('127.0.0.1:443')
                self.assertEqual(status, 503)
            finally:
                os.environ[key] = original
        self.trust.unlink()
        status, _ = self.active('127.0.0.1:443')
        self.assertEqual(status, 503)

    def test_insecure_runtime_permissions_fail_before_tls_connection(self):
        self.data.chmod(0o722)
        status, body = self.active('127.0.0.1:443')
        self.assertEqual(status, 503)
        self.assertEqual(body['error'], 'Yerel TLS doğrulaması kullanılamıyor.')
        self.data.chmod(0o700)

        lock_path = self.data / 'openssl-x509-loopback.lock'
        lock_path.write_bytes(b'')
        lock_path.chmod(0o666)
        status, body = self.active('127.0.0.1:443')
        self.assertEqual(status, 503)
        self.assertEqual(body['error'], 'Yerel TLS doğrulaması kullanılamıyor.')

    def test_saved_report_control_stays_distinct(self):
        now = datetime.now(timezone.utc)
        before = now.strftime('%b %d %H:%M:%S %Y GMT')
        after = now.replace(year=now.year + 1).strftime('%b %d %H:%M:%S %Y GMT')
        value = f'notBefore={before}\nnotAfter={after}\nsha256 Fingerprint=' + ':'.join(['AB']*32)
        status, body = self.post('/api/tool-reports/openssl-x509/summary', {'report': value})
        self.assertEqual(status, 200)
        self.assertEqual(body['format'], 'openssl-x509-dates-fingerprint-v1')
        self.assertEqual(body['validity'], 'valid')


if __name__ == '__main__':
    unittest.main()
