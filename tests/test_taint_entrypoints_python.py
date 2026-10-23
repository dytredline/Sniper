"""Python taint (9. tur): çatı giriş noktaları kaynaktır — Connexion/OpenAPI ``operationId``, AWS Lambda
``(event, context)`` ve serverless/SAM eşlemesi, Google Cloud Functions, Azure Functions, GraphQL çözücüleri
(graphene, strawberry, ariadne). Dinamik dağıtımlı çatıda çağrılmayan fonksiyonun parametre akışı
"ulaşılamıyor" sayılmaz. Her yetenek için olumlu ve olumsuz örnek."""
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_flow as tf  # noqa: E402


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


def _flows(files, entrypoints=frozenset()):
    results = tf._analyze_python_files_uncached({k: _src(v) for k, v in files.items()}, None, frozenset(entrypoints))
    return {k: sorted((f.sink_kind, f.line) for f in v.flows if f.source_label == "request") for k, v in results.items()}


class ConnexionAndServerlessConfigTests(unittest.TestCase):
    def test_openapi_operation_ids_and_router_controller(self):
        spec = _src("""
            openapi: 3.0.0
            paths:
              /users/{username}:
                get:
                  operationId: api_views.users.get_by_name
              /items:
                get:
                  x-openapi-router-controller: api_views.items
                  operationId: list_items
            """)
        found = tf._entrypoints_from_config(spec)
        self.assertIn("api_views.users:get_by_name", found)
        self.assertIn("api_views.items:list_items", found)
        # OpenAPI/swagger olmayan dosyadaki operationId yok sayılır.
        self.assertEqual(tf._entrypoints_from_config("operationId: a.b.c\n"), set())

    def test_serverless_and_sam_handlers(self):
        found = tf._entrypoints_from_config(_src("""
            functions:
              order:
                handler: backend/functions/order.handle_order
              js:
                handler: src/index.handler
            Resources:
              Fn:
                Properties:
                  Handler: app.lambda_handler
            """))
        self.assertIn("backend.functions.order:handle_order", found)
        self.assertIn("app:lambda_handler", found)
        self.assertIn("src.index:handler", found)  # eşleşen Python modülü yoksa etkisiz

    def test_configured_connexion_handler_params_are_sources(self):
        files = {
            "api_views/users.py": """
                import sqlite3
                from models import user_model
                def get_by_name(username, user, token_info):
                    return user_model.find(username)
                def unrelated(username):
                    return user_model.find(username)
            """,
            "models/user_model.py": """
                from sqlalchemy import text
                from app import db
                def find(username):
                    return db.session.execute(text(f"SELECT * FROM users WHERE username = '{username}'"))
            """,
        }
        self.assertEqual(_flows(files, {"api_views.users:get_by_name"})["models/user_model.py"], [("sql", 4)])
        self.assertEqual(_flows(files)["models/user_model.py"], [])

    def test_connexion_security_params_are_not_sources(self):
        files = {"api.py": """
            import os
            def run(body, user, token_info):
                os.system("echo " + user)
                os.system("echo " + token_info["sub"])
                os.system("echo " + body["cmd"])
        """}
        self.assertEqual(_flows(files, {"api:run"})["api.py"], [("command", 5)])

    def test_project_scan_collects_entrypoints_from_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "openapi").mkdir()
            (root / "openapi" / "spec.yml").write_text("openapi: 3.0.0\npaths:\n  /a:\n    get:\n      operationId: views.main.a\n")
            (root / "serverless.yml").write_text("functions:\n  f:\n    handler: handlers/order.create\n")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "x.yml").write_text("openapi: 3\noperationId: evil.mod.f\n")
            found = tf.collect_python_entrypoints(root, frozenset({"node_modules"}))
        self.assertEqual(found, frozenset({"views.main:a", "handlers.order:create"}))


class ServerlessHeuristicTests(unittest.TestCase):
    def test_lambda_event_is_source_context_is_not(self):
        flows = _flows({"handler.py": """
            import os
            import subprocess
            def lambda_handler(event, context):
                os.system("ping " + event["queryStringParameters"]["host"])
                subprocess.run(context.function_name, shell=True)
            def order_handler(event, context):
                os.system(event["body"])
        """})["handler.py"]
        self.assertEqual(flows, [("command", 4), ("command", 7)])

    def test_event_signature_without_handler_name_is_not_source(self):
        flows = _flows({"gui.py": """
            import os
            def on_click(event, context):
                os.system(event["x"])
            class Handler:
                def handler(self, event, context):
                    os.system(event["x"])
        """})["gui.py"]
        self.assertEqual(flows, [])

    def test_google_cloud_functions(self):
        flows = _flows({"main.py": """
            import functions_framework
            import os
            @functions_framework.http
            def hello(request):
                os.system("echo " + request.args.get("name"))
                os.system("echo " + request.method)
            @functions_framework.cloud_event
            def on_event(cloud_event):
                os.system(cloud_event.data["cmd"])
            def plain(r):
                os.system(r.args.get("name"))
        """})["main.py"]
        self.assertIn(("command", 5), flows)
        self.assertIn(("command", 9), flows)
        self.assertNotIn(("command", 11), flows)

    def test_azure_functions_typed_request(self):
        flows = _flows({"fn/__init__.py": """
            import azure.functions as func
            import os
            def main(req: func.HttpRequest) -> func.HttpResponse:
                name = req.params.get("name")
                os.system("echo " + name)
                return func.HttpResponse("ok")
            def other(req):
                os.system("echo " + req.params.get("name"))
        """})["fn/__init__.py"]
        self.assertEqual(flows, [("command", 5)])


class GraphQLResolverTests(unittest.TestCase):
    def test_graphene_resolvers_and_mutations(self):
        flows = _flows({"schema.py": """
            import graphene
            import os
            class Query(graphene.ObjectType):
                ping = graphene.String(host=graphene.String())
                def resolve_ping(self, info, host):
                    return os.popen("ping " + host).read()
                def resolve_search(root, info, **kwargs):
                    return os.popen("grep " + kwargs.get("q")).read()
                def resolve_me(root, info):
                    return os.popen(root.cmd).read()
                def helper(self, host):
                    return os.popen(host).read()
            class Run(graphene.Mutation):
                def mutate(root, info, cmd):
                    os.system(cmd)
        """})["schema.py"]
        self.assertEqual(flows, [("command", 6), ("command", 8), ("command", 15)])

    def test_resolve_prefix_without_graphene_is_not_source(self):
        flows = _flows({"dns.py": """
            import os
            class Resolver:
                def resolve_host(self, info, host):
                    os.system("dig " + host)
        """})["dns.py"]
        self.assertEqual(flows, [])

    def test_strawberry_fields_and_mutations(self):
        flows = _flows({"schema.py": """
            import strawberry
            import os
            @strawberry.type
            class Query:
                @strawberry.field
                def ping(self, info: strawberry.Info, host: str) -> str:
                    return os.popen("ping " + host).read()
                def helper(self, host: str) -> str:
                    return os.popen(host).read()
            @strawberry.type
            class Mutation:
                @strawberry.mutation
                def run(self, cmd: str) -> bool:
                    os.system(cmd)
                    return True
        """})["schema.py"]
        self.assertEqual(flows, [("command", 7), ("command", 14)])

    def test_ariadne_field_decorator_and_set_field(self):
        flows = _flows({"resolvers.py": """
            from ariadne import QueryType, MutationType
            import os
            query = QueryType()
            mutation = MutationType()
            @query.field("ping")
            def resolve_ping(obj, info, host):
                return os.popen("ping " + host).read()
            def resolve_run(_, info, **kwargs):
                os.system(kwargs["cmd"])
            mutation.set_field("run", resolve_run)
            def helper(obj, info, host):
                os.system(host)
        """})["resolvers.py"]
        self.assertEqual(flows, [("command", 7), ("command", 9)])


class UnknownEntryDowngradeTests(unittest.TestCase):
    def _analysis(self, text):
        return tf._analyze_python_files_uncached({"m.py": _src(text)}, None, frozenset())["m.py"]

    def test_uncalled_param_sink_in_dynamic_framework_module_is_uncertain(self):
        analysis = self._analysis("""
            import connexion
            import os
            def exported(cmd):
                os.system(cmd)
        """)
        self.assertFalse(analysis.is_unreached_sink("command", 4))

    def test_called_or_plain_module_still_unreached(self):
        plain = self._analysis("""
            import os
            def exported(cmd):
                os.system(cmd)
        """)
        self.assertTrue(plain.is_unreached_sink("command", 3))
        called = self._analysis("""
            import connexion
            import os
            def run(cmd):
                os.system(cmd)
            def main():
                run("ls")
        """)
        self.assertTrue(called.is_unreached_sink("command", 4))


if __name__ == "__main__":
    unittest.main()
