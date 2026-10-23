import json
from pathlib import Path
import tempfile
import unittest

from project_analyzer import ProjectRejected, analyze_project, validate_project_path
from storage import Store


class ProjectAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.project = self.base / "sample-app"
        self.project.mkdir()
        self.allowed = (self.base.resolve(),)

    def tearDown(self):
        self.temp.cleanup()

    def test_detects_requested_security_gaps_without_storing_secret_value(self):
        secret_value = "VERY_PRIVATE_TEST_TOKEN_12345"
        (self.project / "app.py").write_text(
            f'''import hashlib, requests, qrcode, sqlite3
API_KEY = "{secret_value}"
def login(password):
    print("password", password)
    return hashlib.sha1(password.encode()).hexdigest()
def fetch(url):
    return requests.get(url, verify=False)
def query(db, name):
    return db.execute(f"SELECT * FROM users WHERE name='{{name}}'")
def command(value):
    import subprocess
    return subprocess.run("tool " + value, shell=True)
def serve(app):
    app.run(host="0.0.0.0")
def make_qr(value):
    return qrcode.make(value)
''',
            encoding="utf-8",
        )
        (self.project / "requirements.txt").write_text("requests\nqrcode==7.4\n", encoding="utf-8")

        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        titles = {item["title"] for item in result["findings"]}
        self.assertIn("Kaynak kodda sabit sır olasılığı", titles)
        self.assertIn("SQL sorgusunda dinamik tanımlayıcı/veri", titles)
        self.assertIn("Dış isteklerde SSRF koruması doğrulanamadı", titles)
        self.assertIn("QR parametresinde bütünlük koruması doğrulanamadı", titles)
        self.assertIn("Servis tüm ağ arayüzlerinde dinliyor", titles)
        self.assertIn("Python bağımlılıkları sabitlenmemiş", titles)
        self.assertLess(result["score"], 60)
        self.assertNotIn(secret_value, json.dumps(result, ensure_ascii=False))

    def test_requirements_marker_does_not_mask_unpinned_range(self):
        (self.project / "requirements.txt").write_text("requests>=2 ; python_version == \"3.11\"", encoding="utf-8")
        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        findings = [f for f in result["findings"] if f["category"] == "components" and f["title"] == "Python bağımlılıkları sabitlenmemiş"]
        self.assertEqual(len(findings), 1)
        (self.project / "requirements.txt").write_text("requests==2 ; python_version == \"3.11\"", encoding="utf-8")
        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        findings = [f for f in result["findings"] if f["category"] == "components" and f["title"] == "Python bağımlılıkları sabitlenmemiş"]
        self.assertEqual(len(findings), 0)

    def test_analyze_project_requirements(self):
        cases = [
            ("requests>=2 # requests==2", 1),
            ("requests==2 # requests>=3", 0),
            ("requests>=2 ; python_version == \"3.11\" # ==2", 1),
            ("# requests==2", 0),
            ("demo @ https://example.com/demo.zip#egg=demo", 0),
        ]
        for line, expected_count in cases:
            (self.project / "requirements.txt").write_text(line, encoding="utf-8")
            result = analyze_project(str(self.project), allowed_roots=self.allowed)
            findings = [
                f for f in result["findings"]
                if f["category"] == "components" and f["title"] == "Python bağımlılıkları sabitlenmemiş"
            ]
            self.assertEqual(len(findings), expected_count)


    def test_secure_signals_do_not_create_false_gap_findings(self):
        (self.project / "secure.py").write_text(
            '''import ipaddress, logging, hmac, qrcode
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def verify_password(value, digest):
    return PasswordHasher().verify(digest, value)
def safe_fetch(url):
    host = ipaddress.ip_address("203.0.113.8")
    if host.is_private or host.is_loopback or host.is_link_local:
        raise ValueError("blocked")
def make_qr(value, nonce, expires_at):
    signature = hmac.digest(b"key", value.encode(), "sha256")
    return qrcode.make((value, nonce, expires_at, signature.hex()))
def query(db, value):
    return db.execute("SELECT name FROM users WHERE id = ?", (value,))
logging.info("security_event")
HOST = "127.0.0.1"
''',
            encoding="utf-8",
        )
        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        gap_categories = {item["category"] for item in result["findings"]}
        self.assertNotIn("ssrf", gap_categories)
        self.assertNotIn("qr", gap_categories)
        self.assertFalse(any(item["title"] == "Parola işleme için yavaş KDF doğrulanamadı" for item in result["findings"]))
        self.assertGreaterEqual(result["score"], 90)

    def test_rejects_root_itself_and_missing_source(self):
        with self.assertRaises(ProjectRejected):
            validate_project_path(str(self.base), allowed_roots=(self.base.resolve(),))
        empty = self.base / "empty"
        empty.mkdir()
        with self.assertRaises(ProjectRejected):
            analyze_project(str(empty), allowed_roots=self.allowed)

    def test_project_audit_is_queryable_in_store(self):
        (self.project / "main.py").write_text("print('ok')\n", encoding="utf-8")
        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        store = Store(self.base / "data" / "sniper.db")
        saved = store.create_project_audit(result)
        self.assertTrue(saved["id"].startswith("prj_"))
        self.assertEqual(saved["project_name"], "sample-app")
        self.assertEqual(store.list_project_audits()[0]["id"], saved["id"])
        self.assertIn("findings", store.get_project_audit(saved["id"]))


    def test_project_audit_finding_triage_persists_and_returns_correctly(self):
        # Create audit with exactly two findings using deterministic input
        (self.project / "main.py").write_text(
            "API_KEY = 'hardcoded_secret'\nprint(1/0)\n",
            encoding="utf-8"
        )

        # Build deterministic synthetic result with exactly two findings
        # Using the required exact finding shape and modifying title/line for second
        base_finding = {
            "category": "secrets",
            "severity": "high",
            "title": "Olası sabit sır",
            "file": "src/main.py",
            "line": 12,
            "evidence": "Sır adı görüldü; değer kaydedilmedi.",
            "recommendation": "Sır yönetimini inceleyin.",
            "reference": "CWE-798"
        }
        first_finding = base_finding.copy()
        first_finding["title"] = "Olası sabit sır"
        first_finding["line"] = 1
        second_finding = base_finding.copy()
        second_finding["title"] = "İkinci sır tespiti"
        second_finding["line"] = 2

        synthetic_result = {
            "created_at": "2024-01-01T00:00:00Z",
            "project_path": str(self.project),
            "project_name": "test-project",
            "score": 0.0,
            "grade": "F",
            "file_count": 1,
            "bytes_scanned": 42,
            "findings": [first_finding, second_finding]
        }

        store = Store(self.base / "data" / "sniper.db")
        audit = store.create_project_audit(synthetic_result)
        audit_id = audit["id"]

        # Verify default triage state per finding
        first_finding = audit["findings"][0]
        second_finding = audit["findings"][1]
        self.assertEqual(first_finding["triage"]["disposition"], "unreviewed")
        self.assertEqual(first_finding["triage"]["note"], "")
        self.assertIsNone(first_finding["triage"]["reviewed_at"])
        self.assertEqual(second_finding["triage"]["disposition"], "unreviewed")

        # Perform triage on first finding only
        updated = store.update_project_audit_finding_triage(
            audit_id=audit_id,
            finding_index=0,
            disposition="false_positive",
            note="Test triage note"
        )

        # Assert returned audit has updated triage on index 0, unchanged on index 1
        self.assertEqual(updated["findings"][0]["triage"]["disposition"], "false_positive")
        self.assertEqual(updated["findings"][0]["triage"]["note"], "Test triage note")
        self.assertIsNotNone(updated["findings"][0]["triage"]["reviewed_at"])
        self.assertEqual(updated["findings"][1]["triage"]["disposition"], "unreviewed")

        # Reload audit from store to confirm persistence
        reloaded = store.get_project_audit(audit_id)
        self.assertEqual(reloaded["findings"][0]["triage"]["disposition"], "false_positive")
        self.assertEqual(reloaded["findings"][0]["triage"]["note"], "Test triage note")

        # Verify invalid index raises ValueError and original data is untouched
        import sqlite3
        with sqlite3.connect(store.path) as db:
            raw_findings_before = db.execute(
                "SELECT findings_json FROM project_audits WHERE id = ?",
                (audit_id,)
            ).fetchone()[0]

        with self.assertRaises(ValueError):
            store.update_project_audit_finding_triage(
                audit_id=audit_id,
                finding_index=2,
                disposition="confirmed",
                note="should not persist"
            )

        # Ensure raw findings JSON remains unchanged
        reloaded_audit = store.get_project_audit(audit_id)
        with sqlite3.connect(store.path) as db:
            raw_findings_after = db.execute(
                "SELECT findings_json FROM project_audits WHERE id = ?",
                (audit_id,)
            ).fetchone()[0]
        self.assertEqual(raw_findings_after, raw_findings_before)

    def test_detects_terraform_and_webserver_config_security_issues(self):
        (self.project / "main.tf").write_text(
            '''resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket_acl" "public_bucket" {
  acl = "public-read"
}

resource "aws_db_instance" "db" {
  storage_encrypted = false
}

resource "aws_instance" "app" {
  metadata_options {
    http_tokens = "optional"
  }
}
''',
            encoding="utf-8",
        )
        (self.project / "nginx.conf").write_text(
            '''server {
    listen 443 ssl;
    server_tokens on;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    location /files/ {
        autoindex on;
    }
}
''',
            encoding="utf-8",
        )
        (self.project / ".htaccess").write_text(
            "Options +Indexes\nServerSignature On\n",
            encoding="utf-8",
        )

        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(result["languages"].get("Terraform"), 1)
        self.assertEqual(result["languages"].get("ServerConfig"), 2)
        titles = {item["title"] for item in result["findings"]}
        self.assertIn("Terraform güvenlik grubunda dünyaya açık (0.0.0.0/0) ağ erişimi", titles)
        self.assertIn("Terraform bulut depolama kaynağında herkese açık erişim", titles)
        self.assertIn("Terraform altyapı kaynağında şifreleme devre dışı (encrypted = false)", titles)
        self.assertIn("Terraform sunucu örneğinde IMDSv2 zorunluluğu kapalı (http_tokens = optional)", titles)
        self.assertIn("Web sunucusu yapılandırmasında dizin listeleme (autoindex/Indexes) açık", titles)
        self.assertIn("Web sunucusu yapılandırmasında eski TLS protokolü (TLSv1.0/1.1) etkin", titles)
        self.assertIn("Web sunucusu sürüm bilgisi ifşası (server_tokens on) açık", titles)

    def test_clean_terraform_and_nginx_config_pass_without_false_positives(self):
        (self.project / "main.tf").write_text(
            '''resource "aws_security_group" "internal" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_s3_bucket_public_access_block" "private_bucket" {
  block_public_acls   = true
  block_public_policy = true
}

resource "aws_db_instance" "db" {
  storage_encrypted = true
}

resource "aws_instance" "app" {
  metadata_options {
    http_tokens = "required"
  }
}
''',
            encoding="utf-8",
        )
        (self.project / "nginx.conf").write_text(
            '''server {
    listen 443 ssl;
    server_tokens off;
    ssl_protocols TLSv1.2 TLSv1.3;
    location /files/ {
        autoindex off;
    }
}
''',
            encoding="utf-8",
        )
        (self.project / ".htaccess").write_text(
            "Options -Indexes\nServerSignature Off\n",
            encoding="utf-8",
        )

        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["score"], 100)

    def test_detects_mobile_android_and_ios_security_issues(self):
        (self.project / "AndroidManifest.xml").write_text(
            '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <uses-permission android:name="android.permission.READ_SMS" />
    <application
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true">
    </application>
</manifest>
''',
            encoding="utf-8",
        )
        (self.project / "network_security_config.xml").write_text(
            '''<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
''',
            encoding="utf-8",
        )
        (self.project / "Info.plist").write_text(
            '''<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>
''',
            encoding="utf-8",
        )
        (self.project / "App.entitlements").write_text(
            '''<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <true/>
</dict>
</plist>
''',
            encoding="utf-8",
        )
        (self.project / "MainActivity.kt").write_text(
            '''class MainActivity {
    fun setup(webView: WebView, sharedPreferences: SharedPreferences, biometricPrompt: BiometricPrompt) {
        webView.addJavascriptInterface(Bridge(), "Android")
        webView.settings.setAllowFileAccessFromFileURLs(true)
        sharedPreferences.edit().putString("jwt_token", "secret")
        biometricPrompt.authenticate(promptInfo)
        adapter.listenUsingInsecureRfcommWithServiceRecord("svc", uuid)
        builder.setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
    }
    fun onReceivedSslError(view: WebView, handler: SslErrorHandler) {
        onReceivedSslError(view, handler); handler.proceed()
    }
}
''',
            encoding="utf-8",
        )
        (self.project / "client.dart").write_text(
            '''void configure(HttpClient client) {
  client.badCertificateCallback = (cert, host, port) => true;
}
''',
            encoding="utf-8",
        )
        (self.project / "Store.cs").write_text(
            '''public class Store {
    public void Save() {
        PlayerPrefs.SetInt("coins", 9999);
    }
}
''',
            encoding="utf-8",
        )
        (self.project / "build.gradle").write_text(
            '''android {
    buildTypes {
        release {
            minifyEnabled false
        }
    }
}
''',
            encoding="utf-8",
        )

        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(result["languages"].get("MobileConfig"), 2)
        self.assertEqual(result["languages"].get("Gradle"), 1)
        titles = {item["title"] for item in result["findings"]}
        self.assertIn("Android uygulamasında debuggable=true açık bırakılmış", titles)
        self.assertIn("Android uygulama verisi yedeklemeye (allowBackup) açık", titles)
        self.assertIn("Mobil uygulamada şifresiz HTTP (Cleartext Traffic) izni açık", titles)
        self.assertIn("Android ağ yapılandırmasında kullanıcı sertifikalarına güveniliyor", titles)
        self.assertIn("Android manifest içinde yüksek riskli sistem izni", titles)
        self.assertIn("iOS App Transport Security (ATS) şifresiz bağlantıya izin veriyor", titles)
        self.assertIn("iOS Entitlements içinde get-task-allow (hata ayıklama) açık", titles)
        self.assertIn("Mobil WebView içinde güvensiz JS köprüsü veya yerel dosya erişimi", titles)
        self.assertIn("Mobil cihazda hassas verinin şifresiz yerel depolamada saklanması", titles)
        self.assertIn("Biyometrik doğrulamada kriptografik anahtar (CryptoObject / Keychain) bağlaması eksik", titles)
        self.assertIn("Mobil istemcide TLS sertifika hatası koşulsuz yoksayılıyor", titles)
        self.assertIn("Bluetooth (BLE/RFCOMM) üzerinde şifresiz bağlantı kanalı", titles)
        self.assertIn("Kilit ekranında hassas bildirim görünürlüğü (VISIBILITY_PUBLIC)", titles)
        self.assertIn("Oyun/Uygulama içi bakiye veya yetki durumu şifresiz PlayerPrefs içinde tutuluyor", titles)
        self.assertIn("Android derlemesinde kod karartma (R8 / ProGuard minifyEnabled) devre dışı", titles)
        mobile_check = next(item for item in result["checks"] if item["id"] == "mobile_masvs")
        self.assertEqual(mobile_check["status"], "review")

    def test_detects_desktop_electron_and_ai_llm_issues(self):
        from auth_protocol_auditor import audit_auth_artifact
        from desktop_protocol_security_auditor import (
            audit_desktop_app_project,
            audit_realtime_and_binary_protocols,
        )

        (self.project / "main.js").write_text(
            '''const { BrowserWindow, shell } = require("electron");
const win = new BrowserWindow({
    webPreferences: {
        nodeIntegration: true,
        contextIsolation: false,
        webSecurity: false,
        sandbox: false,
    }
});
shell.openExternal(userInputUrl);
''',
            encoding="utf-8",
        )
        (self.project / "model_runner.py").write_text(
            '''import grpc, torch
model = torch.load("checkpoint.pt")
channel = grpc.insecure_channel("localhost:50051")
result = eval(llm_response)
''',
            encoding="utf-8",
        )
        (self.project / "service.proto").write_text(
            '''syntax = "proto3";
message UserAuth {
    string password = 1;
    repeated string roles = 2;
}
''',
            encoding="utf-8",
        )

        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(result["languages"].get("Protobuf"), 1)
        titles = {item["title"] for item in result["findings"]}
        self.assertIn("Electron penceresinde nodeIntegration: true etkin (Uzaktan Kod Çalıştırma riski)", titles)
        self.assertIn("Electron penceresinde contextIsolation devre dışı", titles)
        self.assertIn("Yapay zeka / PyTorch model yüklemesinde güvensiz serileştirme (torch.load)", titles)
        self.assertIn("Şifresiz (cleartext) gRPC kanal bağlantısı", titles)
        self.assertIn("Dinamik kod çalıştırma", titles)

        desktop_audit = audit_desktop_app_project(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(desktop_audit["format"], "sniper-desktop-security-audit-v1")
        self.assertIn("electron", desktop_audit["frameworks_detected"])
        self.assertGreaterEqual(desktop_audit["finding_count"], 5)

        proto_audit = audit_realtime_and_binary_protocols(
            (self.project / "service.proto").read_text(encoding="utf-8"),
            filename="service.proto",
        )
        self.assertEqual(proto_audit["format"], "sniper-realtime-protocol-audit-v1")
        self.assertEqual(proto_audit["protocol_type"], "grpc")
        self.assertGreaterEqual(proto_audit["finding_count"], 2)

        oauth_audit = audit_auth_artifact(
            "https://auth.example.com/authorize?response_type=token&client_id=app&redirect_uri=http://evil.example.com/*"
        )
        self.assertEqual(oauth_audit["format"], "sniper-auth-protocol-audit-v1")
        self.assertEqual(oauth_audit["artifact_type"], "oauth_url")
        self.assertGreaterEqual(oauth_audit["finding_count"], 3)

    def test_detects_solidity_and_c_buffer_overflow_issues(self):
        from crypto_cbom_pqc_auditor import audit_crypto_pqc_inline, audit_crypto_pqc_project
        from web3_iot_firmware_auditor import (
            audit_iot_firmware_inline,
            audit_smart_contract_inline,
            audit_web3_and_iot_project,
        )

        (self.project / "Vault.sol").write_text(
            '''pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    address public owner;

    function withdraw(uint256 amount, bytes32 hash, uint8 v, bytes32 r, bytes32 s) public {
        require(tx.origin == owner, "not owner");
        address signer = ecrecover(hash, v, r, s);
        uint256 rand = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }

    function upgrade(address impl, bytes memory data) public {
        impl.delegatecall(data);
        selfdestruct(payable(msg.sender));
    }
}
''',
            encoding="utf-8",
        )
        (self.project / "firmware.c").write_text(
            '''#include <stdio.h>
#include <string.h>
void handle_uart(char *user_input) {
    char buf[64];
    gets(buf);
    strcpy(buf, user_input);
    printf(user_input);
}
''',
            encoding="utf-8",
        )
        (self.project / "mosquitto.conf").write_text(
            '''listener 1883
allow_anonymous true
topic readwrite #
''',
            encoding="utf-8",
        )
        (self.project / "crypto_legacy.py").write_text(
            '''import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key_weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
key_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
key_ecc = ec.generate_private_key(ec.SECP256R1())
digest = hashlib.md5(b"legacy").hexdigest()
pqc_kem = "ML-KEM-768"
aead = AESGCM.generate_key(bit_length=256)
''',
            encoding="utf-8",
        )
        (self.project / "schema.prisma").write_text(
            '''datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}
''',
            encoding="utf-8",
        )

        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(result["languages"].get("Solidity"), 1)
        self.assertEqual(result["languages"].get("Prisma"), 1)
        self.assertEqual(result["languages"].get("C/C++"), 1)
        titles = {item["title"] for item in result["findings"]}
        self.assertIn("Solidity akıllı sözleşmesinde Reentrancy (yeniden giriş) riski (.call{value:})", titles)
        self.assertIn("Solidity akıllı sözleşmesinde tx.origin ile kimlik doğrulama", titles)
        self.assertIn("C/C++ bellek taşması (Buffer Overflow) riski taşıyan güvensiz fonksiyon (gets/strcpy)", titles)

        sc_audit = audit_smart_contract_inline(
            (self.project / "Vault.sol").read_text(encoding="utf-8"),
            filename="Vault.sol",
        )
        self.assertEqual(sc_audit["format"], "sniper-smart-contract-audit-v1")
        self.assertGreaterEqual(sc_audit["finding_count"], 5)

        iot_audit = audit_iot_firmware_inline(
            (self.project / "firmware.c").read_text(encoding="utf-8"),
            filename="firmware.c",
        )
        self.assertEqual(iot_audit["format"], "sniper-iot-firmware-audit-v1")
        self.assertGreaterEqual(iot_audit["finding_count"], 2)

        web3_iot_proj = audit_web3_and_iot_project(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(web3_iot_proj["format"], "sniper-web3-iot-project-audit-v1")
        self.assertGreaterEqual(web3_iot_proj["finding_count"], 8)

        pqc_inline = audit_crypto_pqc_inline(
            (self.project / "crypto_legacy.py").read_text(encoding="utf-8"),
            filename="crypto_legacy.py",
        )
        self.assertEqual(pqc_inline["format"], "sniper-crypto-cbom-pqc-inline-v1")
        self.assertEqual(pqc_inline["cyclonedx_cbom"]["bomFormat"], "CycloneDX")
        self.assertEqual(pqc_inline["cyclonedx_cbom"]["specVersion"], "1.6")
        self.assertGreaterEqual(pqc_inline["quantum_vulnerable_count"], 3)
        self.assertGreaterEqual(pqc_inline["deprecated_crypto_count"], 1)
        self.assertGreaterEqual(pqc_inline["pqc_ready_count"], 2)

        pqc_proj = audit_crypto_pqc_project(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(pqc_proj["format"], "sniper-crypto-cbom-pqc-audit-v1")
        self.assertGreaterEqual(pqc_proj["finding_count"], 4)


    def test_python_pattern_strings_and_comments_do_not_self_match(self):
        (self.project / "detector.py").write_text(
            'import re\n'
            '# electron: nodeIntegration: true and tx.origin == owner are examples\n'
            'DOM = re.compile(r"innerHTML\\s*=|dangerouslySetInnerHTML")\n'
            'SOL = "require(tx.origin == owner); (bool ok, ) = msg.sender.call{value: amount}(\\"\\")"\n'
            'MSG = "torch.load(path) without weights_only"\n',
            encoding="utf-8",
        )
        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        titles = {item["title"] for item in result["findings"]}
        self.assertFalse(any("DOM" in t or "Solidity" in t or "Electron" in t or "torch.load" in t for t in titles), titles)

    def test_python_real_torch_load_call_is_still_detected(self):
        (self.project / "model.py").write_text("import torch\nmodel = torch.load(path)\n", encoding="utf-8")
        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        self.assertTrue(any("torch.load" in item["title"] for item in result["findings"]))

    def test_dom_sink_heuristic_flags_raw_and_ignores_literal_escaped_or_reviewed(self):
        (self.project / "ui.js").write_text(
            "el.innerHTML = userInput;\n"
            "a.innerHTML = '';\n"
            "b.innerHTML = `<b>${esc(name)}</b>`;\n"
            "c.disabled = false; c.innerHTML = `Kaydet <span>→</span>`;\n"
            "d.innerHTML = prebuilt; // sniper-reviewed: html-safe\n",
            encoding="utf-8",
        )
        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        dom_lines = sorted(item["line"] for item in result["findings"] if item["title"].startswith("DOM"))
        self.assertEqual(dom_lines, [1])

    def test_solidity_rules_are_scoped_to_sol_files(self):
        (self.project / "notes.js").write_text("if (tx.origin == owner) { send(); }\n", encoding="utf-8")
        result = analyze_project(str(self.project), allowed_roots=self.allowed)
        self.assertFalse(any("Solidity" in item["title"] for item in result["findings"]))


if __name__ == "__main__":
    unittest.main()


