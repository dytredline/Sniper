import json
from pathlib import Path
import tempfile
import unittest

from zero_trust_mesh_auditor import audit_zero_trust_inline, audit_zero_trust_project


def _controls(report, severity=None):
    return [
        (f["control_id"], f["severity"])
        for f in report["findings"]
        if severity is None or f["severity"] == severity
    ]


SECURE_NAMESPACE = """\
apiVersion: v1
kind: Namespace
metadata:
  name: payments
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: payments
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: payments
spec:
  mtls:
    mode: STRICT
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-frontend
  namespace: payments
spec:
  selector:
    matchLabels:
      app: api
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/web/sa/frontend"]
    to:
    - operation:
        methods: ["GET", "POST"]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: payments
spec:
  replicas: 2
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
      - name: api
        image: registry.example/api:1.0  # sabit etiket
"""


class ZeroTrustInlineTests(unittest.TestCase):
    def test_peer_authentication_permissive_is_high(self):
        report = audit_zero_trust_inline(
            "apiVersion: security.istio.io/v1beta1\n"
            "kind: PeerAuthentication\n"
            "metadata:\n"
            "  name: default\n"
            "  namespace: istio-system\n"
            "spec:\n"
            "  mtls:\n"
            "    mode: PERMISSIVE\n",
            filename="peer.yaml",
        )
        self.assertEqual(report["format"], "sniper-zero-trust-mesh-inline-v1")
        self.assertIn(("SNIPER-ZT-03", "high"), _controls(report))
        finding = next(f for f in report["findings"] if f["control_id"] == "SNIPER-ZT-03")
        self.assertEqual(finding["cwe"], "CWE-319")
        self.assertEqual(finding["line"], 8)
        self.assertIn("mesh genelinde", finding["evidence"])
        self.assertIn("PeerAuthentication", report["kinds_detected"])

    def test_peer_authentication_disable_is_critical(self):
        report = audit_zero_trust_inline(
            "kind: PeerAuthentication\nmetadata:\n  name: x\n  namespace: shop\nspec:\n  mtls:\n    mode: DISABLE\n"
        )
        self.assertIn(("SNIPER-ZT-03", "critical"), _controls(report))

    def test_authorization_policy_wildcard_principal_is_high(self):
        report = audit_zero_trust_inline(
            "apiVersion: security.istio.io/v1beta1\n"
            "kind: AuthorizationPolicy\n"
            "metadata:\n"
            "  name: allow-any\n"
            "  namespace: shop\n"
            "spec:\n"
            "  action: ALLOW\n"
            "  rules:\n"
            "  - from:\n"
            "    - source:\n"
            "        principals: [\"*\"]\n",
            filename="authz.yaml",
        )
        self.assertIn(("SNIPER-ZT-04", "high"), _controls(report))
        finding = next(f for f in report["findings"] if f["control_id"] == "SNIPER-ZT-04")
        self.assertEqual(finding["cwe"], "CWE-863")

    def test_authorization_policy_empty_spec_is_deny_all(self):
        report = audit_zero_trust_inline(
            "kind: AuthorizationPolicy\nmetadata:\n  name: deny-all\n  namespace: shop\nspec: {}\n"
        )
        self.assertEqual(report["finding_count"], 0)

    def test_deployment_without_network_policy_flags_default_deny(self):
        report = audit_zero_trust_inline(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: ledger\n"
            "  namespace: payments\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "      - name: ledger\n"
            "        image: ledger:1\n",
            filename="deploy.yaml",
        )
        zt01 = [f for f in report["findings"] if f["control_id"] == "SNIPER-ZT-01"]
        self.assertEqual({f["severity"] for f in zt01}, {"medium", "low"})
        self.assertTrue(all(f["cwe"] == "CWE-923" for f in zt01))
        self.assertTrue(any("payments" in f["evidence"] for f in zt01))
        self.assertIn("payments", report["namespaces_detected"])

    def test_negative_control_secure_namespace_has_no_findings(self):
        report = audit_zero_trust_inline(SECURE_NAMESPACE, filename="secure.yaml")
        self.assertEqual(report["finding_count"], 0, report["findings"])
        self.assertEqual(report["heuristic_documents"], 0)
        self.assertEqual(
            report["kinds_detected"],
            ["AuthorizationPolicy", "Deployment", "Namespace", "NetworkPolicy", "PeerAuthentication"],
        )
        self.assertEqual(report["namespaces_detected"], ["payments"])

    def test_network_policy_open_cidrs_and_allow_all(self):
        report = audit_zero_trust_inline(
            "kind: NetworkPolicy\n"
            "metadata:\n"
            "  name: wide\n"
            "  namespace: shop\n"
            "spec:\n"
            "  podSelector:\n"
            "    matchLabels:\n"
            "      app: web\n"
            "  policyTypes: [Ingress, Egress]\n"
            "  ingress:\n"
            "  - from:\n"
            "    - ipBlock:\n"
            "        cidr: 0.0.0.0/0\n"
            "  - {}\n"
            "  egress:\n"
            "  - to:\n"
            "    - ipBlock:\n"
            "        cidr: \"0.0.0.0/0\"\n"
            "    ports:\n"
            "    - port: 443\n"
        )
        pairs = _controls(report)
        self.assertIn(("SNIPER-ZT-02", "high"), pairs)
        self.assertGreaterEqual(pairs.count(("SNIPER-ZT-02", "medium")), 1)

    def test_gateway_service_and_destination_rule(self):
        report = audit_zero_trust_inline(
            "apiVersion: networking.istio.io/v1beta1\n"
            "kind: Gateway\n"
            "metadata:\n"
            "  name: gw\n"
            "  namespace: edge\n"
            "spec:\n"
            "  servers:\n"
            "  - port:\n"
            "      number: 80\n"
            "      name: http\n"
            "      protocol: HTTP\n"
            "    hosts: [\"*\"]\n"
            "---\n"
            "apiVersion: v1\n"
            "kind: Service\n"
            "metadata:\n"
            "  name: public\n"
            "  namespace: edge\n"
            "spec:\n"
            "  type: LoadBalancer\n"
            "---\n"
            "apiVersion: networking.istio.io/v1beta1\n"
            "kind: DestinationRule\n"
            "metadata:\n"
            "  name: plain\n"
            "  namespace: edge\n"
            "spec:\n"
            "  host: api.edge.svc.cluster.local\n"
            "  trafficPolicy:\n"
            "    tls:\n"
            "      mode: DISABLE\n"
        )
        pairs = _controls(report)
        self.assertIn(("SNIPER-ZT-05", "medium"), pairs)
        self.assertIn(("SNIPER-ZT-06", "medium"), pairs)
        self.assertIn(("SNIPER-ZT-03", "high"), pairs)

    def test_linkerd_injection_disabled_in_enabled_namespace(self):
        report = audit_zero_trust_inline(
            "kind: Namespace\n"
            "metadata:\n"
            "  name: mesh\n"
            "  annotations:\n"
            "    linkerd.io/inject: enabled\n"
            "---\n"
            "kind: NetworkPolicy\n"
            "metadata:\n"
            "  name: deny\n"
            "  namespace: mesh\n"
            "spec:\n"
            "  podSelector: {}\n"
            "  policyTypes: [\"Ingress\", \"Egress\"]\n"
            "---\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: legacy\n"
            "  namespace: mesh\n"
            "spec:\n"
            "  template:\n"
            "    metadata:\n"
            "      annotations:\n"
            "        linkerd.io/inject: disabled\n"
            "        config.linkerd.io/skip-inbound-ports: \"25\"\n"
        )
        pairs = _controls(report)
        self.assertIn(("SNIPER-ZT-03", "medium"), pairs)
        self.assertIn(("SNIPER-ZT-03", "low"), pairs)
        self.assertNotIn("SNIPER-ZT-01", [c for c, _s in pairs])

    def test_envoy_plaintext_cluster_and_missing_rbac(self):
        envoy = {
            "static_resources": {
                "listeners": [
                    {
                        "name": "ingress",
                        "filter_chains": [
                            {
                                "filters": [
                                    {
                                        "name": "envoy.filters.network.http_connection_manager",
                                        "typed_config": {"http_filters": [{"name": "envoy.filters.http.router"}]},
                                    }
                                ]
                            }
                        ],
                    }
                ],
                "clusters": [
                    {
                        "name": "backend",
                        "load_assignment": {
                            "endpoints": [
                                {
                                    "lb_endpoints": [
                                        {"endpoint": {"address": {"socket_address": {"address": "10.0.0.5", "port_value": 8080}}}}
                                    ]
                                }
                            ]
                        },
                    },
                    {
                        "name": "local",
                        "load_assignment": {
                            "endpoints": [
                                {
                                    "lb_endpoints": [
                                        {"endpoint": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": 9000}}}}
                                    ]
                                }
                            ]
                        },
                    },
                ],
            }
        }
        report = audit_zero_trust_inline(json.dumps(envoy), filename="envoy.json")
        pairs = _controls(report)
        self.assertEqual(pairs.count(("SNIPER-ZT-03", "medium")), 1)
        self.assertIn(("SNIPER-ZT-04", "low"), pairs)
        self.assertIn("EnvoyBootstrap", report["kinds_detected"])

    def test_json_manifest_accepted(self):
        manifest = {
            "apiVersion": "security.istio.io/v1beta1",
            "kind": "PeerAuthentication",
            "metadata": {"name": "default", "namespace": "shop"},
            "spec": {"mtls": {"mode": "PERMISSIVE"}},
        }
        report = audit_zero_trust_inline(json.dumps(manifest, indent=2), filename="peer.json")
        self.assertIn(("SNIPER-ZT-03", "high"), _controls(report))
        self.assertIn("shop", report["namespaces_detected"])

    def test_malformed_yaml_does_not_raise_and_uses_heuristics(self):
        broken = (
            "kind: PeerAuthentication\n"
            "metadata:\n"
            "  name: x\n"
            "      bad-indent: : [\n"
            "spec:\n"
            "  mtls:\n"
            "    mode: PERMISSIVE\n"
            "---\n"
            "\t{{ not yaml at all ]]\n"
        )
        report = audit_zero_trust_inline(broken, filename="broken.yaml")
        self.assertGreaterEqual(report["heuristic_documents"], 1)
        self.assertIn(("SNIPER-ZT-03", "high"), _controls(report))

    def test_invalid_input_raises(self):
        with self.assertRaises(ValueError):
            audit_zero_trust_inline("")
        with self.assertRaises(ValueError):
            audit_zero_trust_inline(None)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            audit_zero_trust_inline("a: b\n" * 200_000)


class ZeroTrustProjectTests(unittest.TestCase):
    def test_project_aggregates_across_files(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp) / "mesh-project"
            (root / "k8s").mkdir(parents=True)
            (root / "k8s" / "deploy.yaml").write_text(
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n  namespace: shop\n",
                encoding="utf-8",
            )
            (root / "k8s" / "netpol.yaml").write_text(
                "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: deny\n"
                "  namespace: shop\nspec:\n  podSelector: {}\n  policyTypes:\n  - Ingress\n",
                encoding="utf-8",
            )
            (root / "package.json").write_text('{"name": "x"}', encoding="utf-8")
            report = audit_zero_trust_project(str(root), allowed_roots=(Path(tmp).resolve(),))
        self.assertEqual(report["format"], "sniper-zero-trust-mesh-audit-v1")
        self.assertEqual(report["scanned_files"], 2)
        zt01 = [f for f in report["findings"] if f["control_id"] == "SNIPER-ZT-01"]
        # Ingress default-deny başka dosyada var → yalnızca egress (low) bulgusu kalır.
        self.assertEqual([f["severity"] for f in zt01], ["low"])
        self.assertEqual(report["controls_evaluated"][0], "SNIPER-ZT-01")


class YamlSubsetCoverageTests(unittest.TestCase):
    """followup-03: çapa/takma ad, çok satırlı akış, sekme girintisi."""

    def test_anchor_alias_and_merge_key_are_resolved(self):
        manifest = (
            "apiVersion: security.istio.io/v1beta1\n"
            "kind: PeerAuthentication\n"
            "metadata: &meta\n"
            "  name: default\n"
            "  namespace: shop\n"
            "spec:\n"
            "  mtls: &weak {mode: PERMISSIVE}\n"
            "---\n"
            "x-defaults: &dr\n"
            "  trafficPolicy:\n"
            "    tls:\n"
            "      mode: DISABLE\n"
            "apiVersion: networking.istio.io/v1beta1\n"
            "kind: DestinationRule\n"
            "metadata: {name: legacy, namespace: shop}\n"
            "spec:\n"
            "  <<: *dr\n"
            "  host: legacy.shop.svc.cluster.local\n"
        )
        report = audit_zero_trust_inline(manifest, filename="mesh.yaml")
        self.assertEqual(report["heuristic_documents"], 0)
        controls = _controls(report)
        self.assertIn(("SNIPER-ZT-03", "high"), controls)
        titles = [f["title"] for f in report["findings"]]
        self.assertTrue(any("PERMISSIVE" in t for t in titles))
        self.assertTrue(any("DestinationRule" in t and "DISABLE" in t for t in titles))

    def test_undefined_alias_falls_back_to_heuristics(self):
        manifest = (
            "apiVersion: security.istio.io/v1beta1\n"
            "kind: PeerAuthentication\n"
            "metadata:\n  name: x\n"
            "spec:\n  selector: *missing\n  mtls:\n    mode: DISABLE\n"
        )
        report = audit_zero_trust_inline(manifest)
        self.assertEqual(report["heuristic_documents"], 1)
        self.assertIn(("SNIPER-ZT-03", "critical"), _controls(report))

    def test_multiline_flow_collections(self):
        manifest = (
            "apiVersion: networking.k8s.io/v1\n"
            "kind: NetworkPolicy\n"
            "metadata: {name: open,\n"
            "  namespace: shop}\n"
            "spec:\n"
            "  podSelector: {}\n"
            "  policyTypes: [\n"
            "    Ingress,\n"
            "  ]\n"
            "  ingress:\n"
            "    - from: [{ipBlock: {cidr: 0.0.0.0/0}},\n"
            "             {namespaceSelector: {}}]\n"
        )
        report = audit_zero_trust_inline(manifest)
        self.assertEqual(report["heuristic_documents"], 0)
        self.assertIn("shop", report["namespaces_detected"])
        self.assertTrue(any("0.0.0.0/0" in f["evidence"] for f in report["findings"]))

    def test_tab_indentation_is_parsed(self):
        manifest = (
            "apiVersion: security.istio.io/v1beta1\n"
            "kind: PeerAuthentication\n"
            "metadata:\n\tname: default\n\tnamespace: shop\n"
            "spec:\n\tmtls:\n\t\tmode: DISABLE\n"
        )
        report = audit_zero_trust_inline(manifest)
        self.assertEqual(report["heuristic_documents"], 0)
        self.assertIn("shop", report["namespaces_detected"])
        self.assertIn(("SNIPER-ZT-03", "critical"), _controls(report))


GATEWAY_API = """\
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: shared
  namespace: infra
spec:
  gatewayClassName: example
  listeners:
    - name: http
      protocol: HTTP
      port: 80
      allowedRoutes:
        namespaces:
          from: All
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        mode: Terminate
        certificateRefs: [{name: shop-cert}]
    - name: tls-pass
      protocol: TLS
      port: 8443
      tls: {mode: Passthrough}
"""

HTTPS_REDIRECT_ROUTE = """\
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: redirect
  namespace: shop
spec:
  parentRefs:
    - name: shared
      namespace: infra
      sectionName: http
  rules:
    - filters:
        - type: RequestRedirect
          requestRedirect:
            scheme: https
            statusCode: 301
"""


class GatewayApiTests(unittest.TestCase):
    def test_gateway_api_listeners_are_audited(self):
        report = audit_zero_trust_inline(GATEWAY_API, filename="gateway.yaml")
        self.assertIn("Gateway", report["kinds_detected"])
        by_title = {f["title"]: f for f in report["findings"]}
        http = by_title["Gateway API dinleyicisi düz HTTP sunuyor, HTTPS yönlendirmesi bulunamadı"]
        self.assertEqual(http["severity"], "low")  # aynı Gateway'de HTTPS dinleyicisi var
        self.assertEqual(http["line"], 9)
        self.assertEqual(
            by_title["Gateway API dinleyicisi tüm ad alanlarından rota bağlanmasına izin veriyor"]["severity"],
            "medium",
        )
        self.assertEqual(by_title["Gateway API dinleyicisi TLS Passthrough modunda"]["severity"], "info")

    def test_http_listener_without_tls_is_medium(self):
        manifest = (
            "apiVersion: gateway.networking.k8s.io/v1\nkind: Gateway\n"
            "metadata: {name: gw, namespace: web}\n"
            "spec:\n  listeners:\n  - name: web\n    protocol: HTTP\n    port: 80\n"
        )
        report = audit_zero_trust_inline(manifest)
        self.assertEqual(_controls(report), [("SNIPER-ZT-05", "medium")])

    def test_https_redirect_route_suppresses_plain_http_finding(self):
        report = audit_zero_trust_inline(GATEWAY_API + HTTPS_REDIRECT_ROUTE, filename="gateway.yaml")
        titles = [f["title"] for f in report["findings"]]
        self.assertNotIn("Gateway API dinleyicisi düz HTTP sunuyor, HTTPS yönlendirmesi bulunamadı", titles)
        self.assertIn("Gateway API dinleyicisi tüm ad alanlarından rota bağlanmasına izin veriyor", titles)

    def test_redirect_route_in_other_file_is_correlated_in_project_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "gateway.yaml").write_text(GATEWAY_API, encoding="utf-8")
            (root / "route.yaml").write_text(HTTPS_REDIRECT_ROUTE, encoding="utf-8")
            report = audit_zero_trust_project(str(root), allowed_roots=(Path(tmp).resolve(),))
        titles = [f["title"] for f in report["findings"]]
        self.assertEqual(report["scanned_files"], 2)
        self.assertNotIn("Gateway API dinleyicisi düz HTTP sunuyor, HTTPS yönlendirmesi bulunamadı", titles)

    def test_istio_gateway_is_not_treated_as_gateway_api(self):
        manifest = (
            "apiVersion: networking.istio.io/v1beta1\nkind: Gateway\n"
            "metadata: {name: gw, namespace: web}\n"
            "spec:\n  servers:\n  - port: {number: 80, protocol: HTTP}\n    hosts: ['*']\n"
        )
        report = audit_zero_trust_inline(manifest)
        self.assertTrue(all("Gateway API" not in f["title"] for f in report["findings"]))
        self.assertTrue(any("Istio Gateway" in f["title"] for f in report["findings"]))


if __name__ == "__main__":
    unittest.main()
