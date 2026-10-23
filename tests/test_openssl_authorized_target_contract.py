from __future__ import annotations

import unittest
from pathlib import Path

from openssl_authorized_active import normalize_authorized_target


class OpenSSLAuthorizedTargetContractTests(unittest.TestCase):
    def test_readme_documents_separate_authorized_contract_and_preserved_loopback(self) -> None:
        readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
        self.assertIn("POST /api/tool-runs/openssl-x509-authorized", readme)
        self.assertIn('{"confirm_authorized":true,"target":"https://HOST[:PORT]"}', readme)
        self.assertIn("authorized-tls-target-v1", readme)
        self.assertIn("The existing loopback route and payload/response contract remain unchanged", readme)
        self.assertIn("does not connect to a real external target", readme)

    def test_normalizes_dns_ipv4_ipv6_and_default_port(self) -> None:
        self.assertEqual(
            normalize_authorized_target("HTTPS://Api.Example.COM/"),
            ("https://api.example.com:443", "api.example.com", 443),
        )
        self.assertEqual(
            normalize_authorized_target("https://127.0.0.1:9443"),
            ("https://127.0.0.1:9443", "127.0.0.1", 9443),
        )
        self.assertEqual(
            normalize_authorized_target("https://[::1]:443"),
            ("https://[::1]:443", "::1", 443),
        )

    def test_rejects_ambiguous_or_active_url_components(self) -> None:
        invalid = (
            "https://example.com:",
            "https://example.com:0443",
            "https://127.1",
            "https://0x7f.0.0.1",
            "https://example.com?",
            "https://example.com#",
            "https://example.com/%2fadmin",
            "https://user:pass@example.com",
            "https://example.com\\@127.0.0.1",
            "https://example.com/a",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_authorized_target(value)


if __name__ == "__main__":
    unittest.main()
