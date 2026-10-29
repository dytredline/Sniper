"""Faz 2 R2, R3, R4 ve R5 birleşik doğrulama testleri."""
from __future__ import annotations

import unittest

from asan_project_proof import execute_bounded_fuzz_harness, synthesize_sanitizer_fuzz_harness
from authz_routes import audit_multilang_route_tenant_authz
from openapi_contract_auditor import audit_graphql_advanced_authorization
from service_trust_graph import correlate_service_graph_with_runtime_traces


class Faz2R2R3R4R5Tests(unittest.TestCase):
    def test_r2_bounded_fuzz_execution_safe_and_crashing_targets(self) -> None:
        safe_src = (
            "def parse_packet(data: bytes) -> bytes:\n"
            "    if not data.startswith(b'PKT:'):\n"
            "        raise ValueError('invalid header')\n"
            "    return data[4:]\n"
        )
        bundle = synthesize_sanitizer_fuzz_harness(
            {"file": "pkg/parser.py", "cwe": "CWE-20"},
            source_snippet=safe_src,
        )
        res_safe = execute_bounded_fuzz_harness(bundle, target_source=safe_src, timeout_sec=5)
        self.assertEqual(res_safe["format"], "sniper-bounded-fuzz-execution/1")
        self.assertEqual(res_safe["language"], "python")
        self.assertTrue(res_safe["target_verified"])
        self.assertFalse(res_safe["crash_reproduced"])
        if not res_safe["runtime_available"]:
            self.assertEqual(res_safe["execution"], "target_verified_runtime_missing")

        crash_src = (
            "def parse_packet(data: bytes) -> bytes:\n"
            "    if data == b'CRASH' or len(data) == 0:\n"
            "        raise IndexError('out of bounds read')\n"
            "    return data\n"
        )
        crash_bundle = synthesize_sanitizer_fuzz_harness(
            {"file": "pkg/parser.py", "cwe": "CWE-125"},
            source_snippet=crash_src,
        )
        res_crash = execute_bounded_fuzz_harness(crash_bundle, target_source=crash_src, timeout_sec=5)
        self.assertTrue(res_crash["target_verified"])
        self.assertTrue(res_crash["crash_reproduced"])
        self.assertEqual(res_crash["execution"], "crash_reproduced")

    def test_r3_graphql_advanced_authorization(self) -> None:
        sdl = """
        type Subscription {
            invoiceUpdated(id: ID!): Invoice
        }
        type Invoice @key(fields: "id") {
            id: ID!
            secretNotes: String
        }
        fragment InvoiceFields on Invoice {
            id
            secretNotes
        }
        """
        resolvers = {
            "invoice_resolver.ts": """
            export const resolvers = {
                Subscription: {
                    invoiceUpdated: (_parent, { id }) => GlobalID.find(id),
                },
                Invoice: {
                    __resolveReference(ref, context) {
                        return InvoiceModel.findById(ref.id);
                    }
                }
            };
            """
        }
        persisted = {
            "sha256:99a1": "mutation PromoteAdmin($id: ID!) { promoteUserToAdmin(id: $id) { id } }"
        }
        report = audit_graphql_advanced_authorization(
            sdl,
            resolvers,
            persisted_Manifest=persisted,
        )
        self.assertEqual(report["format"], "sniper-graphql-advanced-authz/1")
        self.assertEqual(report["finding_count"], 3)
        rule_ids = {f["rule_id"] for f in report["findings"]}
        self.assertEqual(
            rule_ids,
            {"SNIPER-GQL-FRAG-01", "SNIPER-GQL-FED-02", "SNIPER-GQL-PERSIST-03"},
        )

        safe_resolvers = {
            "invoice_resolver.ts": """
            export const resolvers = {
                Subscription: {
                    invoiceUpdated: (_parent, { id }, context) => {
                        authorize(context.user);
                        return InvoiceModel.in_organization(context.tenantId).find(id);
                    },
                },
                Invoice: {
                    __resolveReference(ref, context) {
                        if (!context.tenantId) throw new Error("unauthorized");
                        return InvoiceModel.findById(ref.id, { tenantId: context.tenantId });
                    }
                }
            };
            """
        }
        safe_report = audit_graphql_advanced_authorization(
            sdl,
            safe_resolvers,
            persisted_Manifest=persisted,
        )
        self.assertEqual(safe_report["finding_count"], 0)

    def test_r4_service_graph_runtime_trace_correlation(self) -> None:
        static_graph = {
            "edges": [
                {
                    "consumer": "repo:checkout-web",
                    "producer": "repo:orders-api",
                    "protocol": "http",
                    "operation": "GET /v1/orders/{id}",
                },
                {
                    "consumer": "repo:checkout-web",
                    "producer": "repo:billing-api",
                    "protocol": "http",
                    "operation": "POST /v1/charges",
                    "authenticated": False,
                },
                {
                    "consumer": "repo:analytics-worker",
                    "producer": "repo:orders-api",
                    "protocol": "http",
                    "operation": "GET /v1/exports",
                },
            ]
        }
        traces = [
            {
                "consumer": "checkout-web",
                "producer": "orders-api",
                "method": "GET",
                "path": "/v1/orders/ord_42",
                "status_code": 200,
                "authenticated": True,
            },
            {
                "consumer": "checkout-web",
                "producer": "billing-api",
                "method": "POST",
                "path": "/v1/charges",
                "status_code": 403,
                "authenticated": False,
            },
        ]
        result = correlate_service_graph_with_runtime_traces(static_graph, traces)
        self.assertEqual(result["format"], "sniper-runtime-correlated-service-graph/1")
        self.assertEqual(result["edge_count"], 3)
        self.assertEqual(
            result["counts"],
            {"runtime_confirmed": 1, "contradicted": 1, "static_only": 1},
        )
        states = [e["verification_state"] for e in result["edges"]]
        self.assertEqual(states, ["runtime_confirmed", "contradicted", "static_only"])

    def test_r5_multilang_route_tenant_authz(self) -> None:
        # 1. Spring Boot
        spring_vuln = """
        @RestController
        public class OrderController {
            @GetMapping("/orders/{id}")
            public Order getOrder(@PathVariable Long id) {
                return orderRepository.findById(id).orElseThrow();
            }
        }
        """
        spring_safe = """
        @RestController
        public class OrderController {
            @PreAuthorize("@authz.canAccess(#id, principal)")
            @GetMapping("/orders/{id}")
            public Order getOrder(@PathVariable Long id, Principal principal) {
                return orderRepository.findByIdAndTenantId(id, principal.getName());
            }
        }
        """
        r_spring_v = audit_multilang_route_tenant_authz(spring_vuln, filename="OrderController.java")
        r_spring_s = audit_multilang_route_tenant_authz(spring_safe, filename="OrderController.java")
        self.assertEqual(r_spring_v["finding_count"], 1)
        self.assertEqual(r_spring_v["findings"][0]["rule_id"], "SNIPER-AUTHZ-SPRING-01")
        self.assertEqual(r_spring_s["finding_count"], 0)

        # 2. ASP.NET Core
        aspnet_vuln = """
        public class InvoicesController : ControllerBase {
            [HttpGet("{id}")]
            public async Task<IActionResult> GetInvoice(Guid id) {
                var item = await _context.Invoices.FindAsync(id);
                return Ok(item);
            }
        }
        """
        aspnet_safe = """
        public class InvoicesController : ControllerBase {
            [HttpGet("{id}")]
            public async Task<IActionResult> GetInvoice(Guid id) {
                var tenantId = User.FindFirst("tenant_id")?.Value;
                var item = await _context.Invoices.FirstOrDefaultAsync(x => x.Id == id && x.TenantId == tenantId);
                return Ok(item);
            }
        }
        """
        r_aspnet_v = audit_multilang_route_tenant_authz(aspnet_vuln, filename="InvoicesController.cs")
        r_aspnet_s = audit_multilang_route_tenant_authz(aspnet_safe, filename="InvoicesController.cs")
        self.assertEqual(r_aspnet_v["finding_count"], 1)
        self.assertEqual(r_aspnet_v["findings"][0]["rule_id"], "SNIPER-AUTHZ-ASPNET-02")
        self.assertEqual(r_aspnet_s["finding_count"], 0)

        # 3. Express / NestJS
        nest_vuln = """
        @Controller('projects')
        export class ProjectsController {
            @Get(':id')
            async findOne(@Param('id') id: string) {
                return this.prisma.project.findUnique({ where: { id } });
            }
        }
        """
        nest_safe = """
        @Controller('projects')
        export class ProjectsController {
            @Get(':id')
            async findOne(@Param('id') id: string, @Req() req) {
                return this.prisma.project.findFirst({ where: { id, tenantId: req.user.tenantId } });
            }
        }
        """
        r_nest_v = audit_multilang_route_tenant_authz(nest_vuln, filename="projects.controller.ts")
        r_nest_s = audit_multilang_route_tenant_authz(nest_safe, filename="projects.controller.ts")
        self.assertEqual(r_nest_v["finding_count"], 1)
        self.assertEqual(r_nest_v["findings"][0]["rule_id"], "SNIPER-AUTHZ-NEST-03")
        self.assertEqual(r_nest_s["finding_count"], 0)

        # 4. Django / FastAPI
        py_vuln = """
        def invoice_detail(request, pk):
            invoice = Invoice.objects.get(pk=pk)
            return JsonResponse({"id": invoice.id})
        """
        py_safe = """
        def invoice_detail(request, pk):
            invoice = Invoice.objects.get(pk=pk, user=request.user, organization=request.user.organization)
            return JsonResponse({"id": invoice.id})
        """
        r_py_v = audit_multilang_route_tenant_authz(py_vuln, filename="views.py")
        r_py_s = audit_multilang_route_tenant_authz(py_safe, filename="views.py")
        self.assertEqual(r_py_v["finding_count"], 1)
        self.assertEqual(r_py_v["findings"][0]["rule_id"], "SNIPER-AUTHZ-PY-04")
        self.assertEqual(r_py_s["finding_count"], 0)


if __name__ == "__main__":
    unittest.main()
