"""Nmap XML: tüm tcp/udp port öğelerinde portid 1..65535 ASCII ondalık doğrulanır."""

from __future__ import annotations

import unittest

from tool_report_nmap import parse_nmap_inline_summary


def report(host_state: str, port_state: str, portid: str | None, protocol: str = "tcp") -> str:
    attribute = "" if portid is None else ' portid="' + portid + '"'
    return (
        '<nmaprun><host><status state="' + host_state + '"/><ports>'
        '<port protocol="' + protocol + '"' + attribute + '><state state="' + port_state + '"/></port>'
        "</ports></host></nmaprun>"
    )


class NmapInactivePortIdentityTests(unittest.TestCase):
    def test_valid_ports_keep_open_port_semantics(self):
        cases = [
            ("up", "open", "443", "tcp", 1),
            ("up", "open", "65535", "udp", 1),
            ("up", "closed", "443", "tcp", 0),
            ("up", "filtered", "1", "udp", 0),
            ("down", "open", "443", "tcp", 0),
            ("down", "closed", "8080", "udp", 0),
        ]
        for host, state, portid, protocol, expected in cases:
            with self.subTest(host=host, state=state, portid=portid, protocol=protocol):
                summary = parse_nmap_inline_summary(report(host, state, portid, protocol))
                self.assertEqual(summary["open_port_count"], expected)

    def test_invalid_port_identity_is_rejected_even_when_not_counted(self):
        bad_ids = [None, "65536", "-1", "abc", "+443", " 443", "443 ", "4_43", "0443",
                   "٤٤٣", "443.0", ""]
        for host, state in [("down", "open"), ("down", "closed"), ("up", "closed"),
                            ("up", "filtered"), ("up", "open")]:
            for protocol in ("tcp", "udp"):
                for portid in bad_ids:
                    with self.subTest(host=host, state=state, protocol=protocol, portid=repr(portid)):
                        with self.assertRaises(ValueError) as cm:
                            parse_nmap_inline_summary(report(host, state, portid, protocol))
                        self.assertEqual(str(cm.exception), "Geçersiz XML.")

    def test_portid_zero_only_for_non_open_ports(self):
        # nmap -p0 çıktısında kapalı/filtreli port 0 görülebilir; açık port 0 geçersizdir.
        for host, state in [("down", "closed"), ("up", "closed"), ("up", "filtered"), ("down", "open")]:
            with self.subTest(host=host, state=state):
                if state == "open":
                    with self.assertRaises(ValueError):
                        parse_nmap_inline_summary(report(host, state, "0", "tcp"))
                else:
                    self.assertEqual(parse_nmap_inline_summary(report(host, state, "0", "tcp"))["open_port_count"], 0)
        with self.assertRaises(ValueError):
            parse_nmap_inline_summary(report("up", "open", "0", "tcp"))

    def test_non_tcp_udp_ports_are_still_ignored(self):
        summary = parse_nmap_inline_summary(report("up", "open", "0", "sctp"))
        self.assertEqual(summary["open_port_count"], 0)
        self.assertEqual(summary["port_element_count"] if "port_element_count" in summary else 0, 0)


if __name__ == "__main__":
    unittest.main()
