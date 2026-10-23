"""Prometheus etiketlerinin sınırlı kardinalitesi (istemci kontrolündeki metod/yol)."""

from __future__ import annotations

import re
import unittest

from exporter import metrics as metrics_module
from exporter.metrics import (
    ALLOWED_METHODS,
    API_RESOURCES,
    MAX_ROUTE_LABELS,
    OTHER_ROUTE,
    Metrics,
    _method,
    _route,
)


def _labels(rendered: str, name: str) -> set[str]:
    return set(re.findall(rf'{name}="((?:[^"\\]|\\.)*)"', rendered))


class MethodLabelTests(unittest.TestCase):
    def test_known_methods_kept_case_insensitive(self) -> None:
        for method in ALLOWED_METHODS:
            self.assertEqual(_method(method), method)
            self.assertEqual(_method(method.lower()), method)

    def test_unknown_methods_collapse_to_other(self) -> None:
        for method in ("PROPFIND", "TRACE", "CONNECT", "X" * 200, "", "GET\n", "ĞET"):
            self.assertEqual(_method(method), "OTHER")


class RouteLabelTests(unittest.TestCase):
    def test_existing_contract_preserved(self) -> None:
        self.assertEqual(_route("/api/scans/scn_123456789/report.json"), "/api/scans/:id/report.json")
        self.assertEqual(_route("/"), "/")
        self.assertEqual(_route("/metrics"), "/metrics")
        self.assertEqual(_route("/api"), "/api")
        self.assertEqual(_route("/api/tools/readiness"), "/api/tools/readiness")

    def test_unknown_api_resource_collapses(self) -> None:
        self.assertEqual(_route("/api/does-not-exist"), "/api/:other")
        self.assertEqual(_route("/api/random123/x/y"), "/api/:other")

    def test_non_api_paths_collapse(self) -> None:
        self.assertEqual(_route("/app.js"), "/:static")
        self.assertEqual(_route("/index.html"), "/:static")
        self.assertEqual(_route("/foo/bar"), OTHER_ROUTE)
        self.assertEqual(_route("/random-spa-path"), OTHER_ROUTE)
        self.assertEqual(_route("/metrics/extra"), OTHER_ROUTE)

    def test_deep_unknown_segments_become_id_and_depth_bounded(self) -> None:
        self.assertEqual(_route("/api/tool-runs/abcdef/k6"), "/api/tool-runs/:id/k6")
        self.assertEqual(_route("/api/tool-runs/abcdef/zzz/qqq/rrr"), "/api/tool-runs/:id/:id")
        self.assertEqual(_route("/api/scans/aaaa/bbbb"), "/api/scans/:id/:id")

    def test_query_string_ignored(self) -> None:
        self.assertEqual(_route("/api/scans?x=1"), "/api/scans")

    def test_random_paths_yield_bounded_label_set(self) -> None:
        routes = set()
        for index in range(5000):
            routes.add(_route(f"/api/scans/id{index}/seg{index}"))
            routes.add(_route(f"/api/r{index}/x"))
            routes.add(_route(f"/p{index}/q"))
            routes.add(_route(f"/p{index}.js"))
        self.assertEqual(routes, {"/api/scans/:id/:id", "/api/:other", OTHER_ROUTE, "/:static"})


class MetricsCardinalityTests(unittest.TestCase):
    def test_rendered_labels_bounded_under_attack(self) -> None:
        metrics = Metrics()
        for index in range(3000):
            metrics.observe_request(f"M{index}", f"/api/x{index}/y{index}", 404, 0.001)
            metrics.observe_request("get", f"/anything/{index}", 200, 0.001)
            metrics.observe_request("POST", f"/api/scans/{index}/z{index}", 404, 0.001)
        rendered = metrics.render(active_scans=0, loaded_plugins=0)
        self.assertLessEqual(_labels(rendered, "method"), set(ALLOWED_METHODS) | {"OTHER"})
        self.assertEqual(_labels(rendered, "route"), {"/api/:other", OTHER_ROUTE, "/api/scans/:id/:id"})

    def test_hard_cap_on_distinct_route_labels(self) -> None:
        metrics = Metrics()
        resources = sorted(API_RESOURCES)
        segments = sorted(metrics_module.ROUTE_SEGMENTS)
        produced = 0
        for resource in resources:
            for segment in segments:
                metrics.observe_request("GET", f"/api/{resource}/{segment}", 200, 0.001)
                produced += 1
        self.assertGreater(produced, MAX_ROUTE_LABELS)
        rendered = metrics.render(active_scans=0, loaded_plugins=0)
        routes = _labels(rendered, "route")
        self.assertLessEqual(len(routes), MAX_ROUTE_LABELS + 1)
        self.assertIn(OTHER_ROUTE, routes)

    def test_status_label_bounded(self) -> None:
        metrics = Metrics()
        metrics.observe_request("GET", "/", 99999, 0.001)
        metrics.observe_request("GET", "/", 204, 0.001)
        rendered = metrics.render(active_scans=0, loaded_plugins=0)
        self.assertEqual(_labels(rendered, "status") - {"completed"}, {"0", "204"})


if __name__ == "__main__":
    unittest.main()
