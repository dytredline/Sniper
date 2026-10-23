import hashlib
import json
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import server
from storage import Store


class NmapInlineSummaryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "data" / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

    def request_json(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=body,
            method="GET" if payload is None else "POST",
            headers={"Content-Type": "application/json"} if body else {},
        )
        try:
            with urlopen(request, timeout=5) as response:
                return json.loads(response.read())
        except HTTPError as e:
            raise e

    def test_nmap_summary_benign_dtd(self):
        xml = '''<?xml version="1.0"?>
<!DOCTYPE nmaprun [
<!ELEMENT nmaprun (host*)>
<!ELEMENT host (status?, ports?)>
<!ELEMENT status EMPTY>
<!ATTLIST status state CDATA #REQUIRED>
<!ELEMENT ports (port*)>
<!ELEMENT port (state?)>
<!ATTLIST port protocol CDATA #REQUIRED portid CDATA #REQUIRED>
<!ELEMENT state EMPTY>
<!ATTLIST state state CDATA #REQUIRED>
]>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
      </port>
      <port protocol="udp" portid="53">
        <state state="open"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>'''
        result = self.request_json("/api/tool-reports/nmap/summary", {"report": xml})
        self.assertEqual(result["format"], "nmap-xml")
        self.assertEqual(result["host_count"], 3)
        self.assertEqual(result["up_host_count"], 2)
        self.assertEqual(result["open_port_count"], 3)
        self.assertEqual(result["open_protocol_counts"], {"tcp": 2, "udp": 1})
        self.assertEqual(result["open_port_bands"], {"well_known": 3, "registered": 0, "dynamic": 0})
        self.assertIn("report_sha256", result)

    def test_nmap_summary_empty_nmaprun(self):
        xml = '''<?xml version="1.0"?>
<!DOCTYPE nmaprun [
<!ELEMENT nmaprun (host*)>
<!ELEMENT host (ports?)>
<!ELEMENT ports (port*)>
<!ELEMENT port (state?)>
<!ATTLIST port protocol CDATA #REQUIRED portid CDATA #REQUIRED>
<!ELEMENT state EMPTY>
<!ATTLIST state state CDATA #REQUIRED>
]>
<nmaprun/>'''
        result = self.request_json("/api/tool-reports/nmap/summary", {"report": xml})
        self.assertEqual(result["host_count"], 0)
        self.assertEqual(result["up_host_count"], 0)
        self.assertEqual(result["open_port_count"], 0)
        self.assertEqual(result["open_protocol_counts"], {"tcp": 0, "udp": 0})
        self.assertEqual(result["open_port_bands"], {"well_known": 0, "registered": 0, "dynamic": 0})

    def test_nmap_summary_negative_portid_rejected_http_400(self):
        xml = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="-1">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>'''
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nmap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)
        error_body = cm.exception.read().decode("utf-8")
        self.assertNotIn("-1", error_body)

    def test_nmap_summary_entity_declaration_rejected_http_400(self):
        xml = '''<?xml version="1.0"?>
<!DOCTYPE nmaprun [
<!ENTITY foo "bar">
]>
<nmaprun/>'''
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nmap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)
        error_body = cm.exception.read().decode("utf-8")
        self.assertNotIn("foo", error_body)

    def test_nmap_summary_external_dtd_rejected_http_400(self):
        xml = '''<?xml version="1.0"?>
<!DOCTYPE nmaprun SYSTEM "http://example.com/dtd">
<nmaprun/>'''
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nmap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)
        error_body = cm.exception.read().decode("utf-8")
        self.assertNotIn("example.com", error_body)

    def test_nmap_summary_xml_declaration_and_pi_allowed(self):
        xml = '''<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="nmap.xsl"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>'''
        result = self.request_json("/api/tool-reports/nmap/summary", {"report": xml})
        self.assertEqual(result["format"], "nmap-xml")
        self.assertEqual(result["up_host_count"], 1)
        self.assertEqual(result["open_port_count"], 1)
        self.assertEqual(result["open_port_bands"]["registered"], 1)
        # Verify SHA-256 matches exact UTF-8 input
        expected_sha256 = hashlib.sha256(xml.encode("utf-8")).hexdigest()
        self.assertEqual(result["report_sha256"], expected_sha256)

    def test_nmap_summary_nonnumeric_portid_rejected_http_400(self):
        xml = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="abc">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>'''
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nmap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)
        error_body = cm.exception.read().decode("utf-8")
        self.assertNotIn("abc", error_body)

    def test_nmap_summary_closed_port_counts_toward_max_ports(self):
        xml = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>'''
        result = self.request_json("/api/tool-reports/nmap/summary", {"report": xml})
        self.assertEqual(result["host_count"], 1)
        self.assertEqual(result["up_host_count"], 1)
        self.assertEqual(result["open_port_count"], 1)
        self.assertEqual(result["open_protocol_counts"], {"tcp": 1, "udp": 0})
        self.assertEqual(result["open_port_bands"], {"well_known": 1, "registered": 0, "dynamic": 0})

    def test_nmap_summary_missing_portid_open_tcp_rejected_http_400(self):
        xml = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>'''
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nmap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)
        error_body = cm.exception.read().decode("utf-8")
        self.assertNotIn("port", error_body)

    def test_nmap_summary_5001_port_elements_under_down_host_rejected_http_400(self):
        # Build XML with 5001 <port> elements under a single DOWN host
        port_elements = ""
        for i in range(5001):
            port_elements += f'<port protocol="tcp" portid="{i}"><state state="open"/></port>'
        xml = f'''<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down"/>
    <ports>
      {port_elements}
    </ports>
  </host>
</nmaprun>'''
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/nmap/summary", {"report": xml})
        self.assertEqual(cm.exception.code, 400)
        error_body = cm.exception.read().decode("utf-8")
        self.assertNotIn("5001", error_body)
