"""R5: bounded Spring and ASP.NET route/authorization correlation."""

from __future__ import annotations

from pathlib import Path
import tempfile
import textwrap

import authz_routes as az
import project_analyzer


def _run(files: dict[str, str]):
    return az.analyze_sources(
        [(name, textwrap.dedent(source).lstrip("\n")) for name, source in files.items()]
    )


def _routes(result: dict):
    return {(route.framework, route.path, "/".join(route.methods)): route for route in result["routes"]}


def test_spring_controller_annotations_and_subject_lookup_are_correlated() -> None:
    result = _run({
        "src/main/java/acme/OrderController.java": """
            @RestController
            @RequestMapping("/api/orders")
            @PreAuthorize("isAuthenticated()")
            public class OrderController {
              @GetMapping("/{id}")
              public Order get(@PathVariable Long id) {
                return orders.findById(id).orElseThrow();
              }

              @GetMapping("/mine/{id}")
              public Order mine(@PathVariable Long id, Authentication authentication) {
                return orders.findByIdAndOwnerName(id, authentication.getName());
              }

              @DeleteMapping("/{id}")
              @PreAuthorize("hasRole('ADMIN')")
              public void remove(@PathVariable Long id) { orders.deleteById(id); }

              @GetMapping("/catalog/{id}")
              @PermitAll
              public Order catalog(@PathVariable Long id) { return catalog.findById(id); }
            }
        """
    })
    routes = _routes(result)
    assert routes[("spring", "/api/orders/{id}", "GET")].protection == "annotation:PreAuthorize"
    assert routes[("spring", "/api/orders/catalog/{id}", "GET")].public_mark is True
    idor = [f for f in result["findings"] if f["reference"] == "CWE-639"]
    assert len(idor) == 1
    assert "findById" in idor[0]["evidence"]


def test_spring_dynamic_paths_and_ambiguous_methods_fail_closed() -> None:
    result = _run({
        "src/main/java/acme/DynamicController.java": """
            @RestController
            @RequestMapping(API_PREFIX)
            class DynamicController {
              @GetMapping(path = routeName())
              Object dynamic(Long id) { return repo.findById(id); }
            }
        """
    })
    assert result["routes"] == []
    assert result["findings"] == []


def test_named_route_parameter_annotations_keep_literal_correlation() -> None:
    result = _run({
        "src/InvoiceController.java": """
            @RestController
            @RequestMapping("/invoices")
            @PreAuthorize("isAuthenticated()")
            class InvoiceController {
              @GetMapping(path = "/{invoiceId}")
              Invoice get(@PathVariable("invoiceId") UUID invoiceId) {
                return invoices.findById(invoiceId).orElseThrow();
              }
            }
        """,
        "Api/InvoicesController.cs": """
            [ApiController]
            [Route("api/invoices")]
            [Authorize]
            class InvoicesController : ControllerBase {
              [HttpGet("{invoiceId}")]
              public Invoice Get([FromRoute(Name = "invoiceId")] Guid invoiceId) {
                return db.Invoices.Find(invoiceId);
              }
            }
        """,
    })
    routes = _routes(result)
    assert ("spring", "/invoices/{invoiceId}", "GET") in routes
    assert ("aspnet", "/api/invoices/{invoiceId}", "GET") in routes
    assert len([finding for finding in result["findings"] if finding["reference"] == "CWE-639"]) == 2


def test_aspnet_controller_authorize_policy_and_owner_filter_are_correlated() -> None:
    result = _run({
        "Api/Controllers/DocumentsController.cs": """
            [ApiController]
            [Route("api/documents")]
            [Authorize]
            public sealed class DocumentsController : ControllerBase {
              [HttpGet("{id}")]
              public async Task<Document> Get(Guid id) {
                return await db.Documents.FindAsync(id);
              }

              [HttpGet("mine/{id}")]
              public async Task<Document> Mine(Guid id) {
                return await db.Documents.SingleAsync(x => x.Id == id && x.OwnerId == User.Identity.Name);
              }

              [HttpDelete("{id}")]
              [Authorize(Policy = "DocumentAdministrators")]
              public async Task Delete(Guid id) { await db.Documents.FindAsync(id); }

              [HttpGet("public/{id}")]
              [AllowAnonymous]
              public async Task<Document> Public(Guid id) { return await catalog.FindAsync(id); }
            }
        """
    })
    routes = _routes(result)
    assert routes[("aspnet", "/api/documents/{id}", "GET")].protection == "attribute:Authorize"
    assert routes[("aspnet", "/api/documents/public/{id}", "GET")].public_mark is True
    idor = [f for f in result["findings"] if f["reference"] == "CWE-639"]
    assert len(idor) == 1
    assert "FindAsync" in idor[0]["evidence"]


def test_aspnet_controller_token_inside_literal_route_is_not_misparsed_as_attribute_end() -> None:
    result = _run({
        "Api/DocumentsController.cs": """
            [ApiController]
            [Route("api/[controller]")]
            [Authorize]
            class DocumentsController : ControllerBase {
              [HttpGet("{id}")]
              public Document Get(Guid id) { return db.Documents.Find(id); }
            }
        """
    })
    routes = _routes(result)
    assert ("aspnet", "/api/documents/{id}", "GET") in routes
    assert any(finding["reference"] == "CWE-639" for finding in result["findings"])


def test_aspnet_minimal_api_require_authorization_is_exact_and_bounded() -> None:
    result = _run({
        "Api/Program.cs": """
            app.MapGet("/api/accounts/{id}", async (Guid id, AppDb db) =>
                await db.Accounts.FindAsync(id)).RequireAuthorization();
            app.MapGet(dynamicPath, (Guid id, AppDb db) => db.Accounts.FindAsync(id))
                .RequireAuthorization();
        """
    })
    routes = _routes(result)
    assert list(routes) == [("aspnet-minimal", "/api/accounts/{id}", "GET")]
    assert routes[("aspnet-minimal", "/api/accounts/{id}", "GET")].protection == "RequireAuthorization"
    assert any(f["reference"] == "CWE-639" for f in result["findings"])


def test_java_and_csharp_sources_are_bounded_by_existing_source_limit() -> None:
    oversized = "@RestController class C {" + (" " * az.MAX_SOURCE_BYTES) + "}"
    result = _run({"C.java": oversized, "C.cs": oversized})
    assert result["routes"] == []


def test_project_analyzer_collects_java_and_csharp_authorization_routes() -> None:
    java = """
        @RestController
        @RequestMapping("/api/orders")
        @PreAuthorize("isAuthenticated()")
        class OrdersController {
          @GetMapping("/{id}")
          Order get(Long id) { return orders.findById(id).orElseThrow(); }
        }
    """
    csharp = """
        [ApiController]
        [Route("api/documents")]
        [Authorize]
        class DocumentsController : ControllerBase {
          [HttpGet("{id}")]
          public Document Get(Guid id) { return db.Documents.Find(id); }
        }
    """
    with tempfile.TemporaryDirectory() as raw:
        base = Path(raw)
        root = base / "project"
        (root / "src").mkdir(parents=True)
        (root / "src" / "OrdersController.java").write_text(textwrap.dedent(java), encoding="utf-8")
        (root / "src" / "DocumentsController.cs").write_text(textwrap.dedent(csharp), encoding="utf-8")
        report = project_analyzer.analyze_project(str(root), allowed_roots=(base,))
    assert report["route_inventory"]["summary"]["frameworks"] == {"aspnet": 1, "spring": 1}
    assert sorted(
        finding["reference"] for finding in report["findings"] if finding.get("category") == "authz"
    ) == ["CWE-639", "CWE-639"]

