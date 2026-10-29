from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1]
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import attack_path_correlator
import cli_reports
import cve_submission_pipeline
import project_analyzer


class TestWave4ChainsScopeAndWiring(unittest.TestCase):
    def test_partition_chains_by_branch_constraints_splits_cimd_and_dcr(self) -> None:
        findings = [
            {
                "id": "BACKSTAGE-CIMD-SSRF-1",
                "stage": "entry",
                "cwe": "CWE-918",
                "file": "plugins/auth-backend/src/oidc/service.ts",
                "line": 140,
                "title": "CIMD metadata fetch in resolveCimdClient when isCimdClientId(clientId) is true",
                "evidence": "if (isCimdClientId(clientId)) { return resolveCimdClient(clientId); } // requiresPkce: true",
            },
            {
                "id": "BACKSTAGE-DCR-TOKEN-1",
                "stage": "entry",
                "cwe": "CWE-287",
                "file": "plugins/auth-backend/src/oidc/service.ts",
                "line": 210,
                "title": "DCR token exchange uses resolveDcrClient with requiresPkce: false",
                "evidence": "const client = await resolveDcrClient(clientId); // requiresPkce: false",
            },
            {
                "id": "BACKSTAGE-DCR-REVOKE-2",
                "stage": "impact",
                "cwe": "CWE-639",
                "file": "plugins/auth-backend/src/oidc/service.ts",
                "line": 305,
                "title": "verifyRevocationClient allows cross-client token revocation due to missing oidcClientId check",
                "evidence": "await verifyRevocationClient(req); // missing token.oidcClientId !== client.clientId guard",
            },
        ]

        res = attack_path_correlator.partition_chains_by_branch_constraints(findings)
        self.assertEqual(res["format"], "sniper-branch-constrained-chain-partition/1")
        self.assertEqual(res["partition_count"], 2)
        self.assertGreaterEqual(len(res["mutually_exclusive_splits"]), 1)

        by_branch = {p["branch_constraint"]: p for p in res["partitions"]}
        self.assertIn("cimd", by_branch)
        self.assertIn("dcr_confidential", by_branch)

        cimd_part = by_branch["cimd"]
        dcr_part = by_branch["dcr_confidential"]
        self.assertEqual(cimd_part["finding_count"], 1)
        self.assertEqual(cimd_part["chain_count"], 0)
        self.assertEqual(dcr_part["finding_count"], 2)
        self.assertGreaterEqual(dcr_part["chain_count"], 1)
        for ch in dcr_part["chains"]:
            self.assertEqual(ch["branch_constraint"], "dcr_confidential")
            hop_titles = " ".join(str(h.get("title") or "") for h in ch.get("hops") or [])
            self.assertNotIn("resolveCimdClient", hop_titles)

    def test_classify_program_scopes_and_asset_linkage(self) -> None:
        structured_scopes = [
            {
                "id": "93787",
                "asset_identifier": "Core Backstage source code",
                "instruction": "Core Backstage packages including @backstage/plugin-auth-backend",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            },
            {
                "id": "40427",
                "asset_identifier": "spotify/ios-sdk",
                "instruction": "Spotify iOS SDK",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            },
            {
                "id": "40428",
                "asset_identifier": "spotify/android-sdk",
                "instruction": "Spotify Android SDK",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            },
            {
                "id": "40499",
                "asset_identifier": "spotify/save-to-spotify",
                "instruction": "Hardening only",
                "eligible_for_bounty": False,
                "eligible_for_submission": True,
            },
        ]
        targets = [
            {
                "repo": "backstage/backstage",
                "component": "@backstage/plugin-auth-backend",
                "linkage_to_core_asset": "Direct match to Core Backstage source code (93787)",
            },
            {
                "repo": "spotify/save-to-spotify",
                "component": "save-to-spotify-web",
                "linkage_to_core_asset": "Listed in scope with eligible_for_bounty=False",
            },
            {
                "repo": "spotify/spotify-web-api-ts-sdk",
                "component": "AuthorizationCodeWithPKCEStrategy",
                "linkage_to_core_asset": "Referenced in auth-lib/README.md of spotify/android-sdk (40428)",
            },
            {
                "repo": "spotify/spotify-token-swap-service",
                "component": "spotify_token_swap.rb",
                "linkage_to_core_asset": "Shipped in DemoProjects/spotify_token_swap.rb inside spotify/ios-sdk (40427)",
            },
        ]

        plan = cve_submission_pipeline.classify_program_scopes_and_asset_linkage(
            targets,
            structured_scopes,
            program_handle="spotify",
        )
        self.assertEqual(plan["format"], "sniper-scope-wave-plan/1")
        self.assertEqual(plan["program_handle"], "spotify")
        self.assertEqual(len(plan["wave_1_immediate"]), 1)
        self.assertEqual(plan["wave_1_immediate"][0]["classification"], "WAVE_1_CONFIRMED_BOUNTY")
        self.assertEqual(len(plan["hardening_no_bounty"]), 1)
        self.assertEqual(plan["hardening_no_bounty"][0]["classification"], "HARDENING_ONLY_NO_BOUNTY")
        self.assertEqual(len(plan["wave_2_clarification"]), 2)
        for item in plan["wave_2_clarification"]:
            self.assertEqual(item["classification"], "WAVE_2_NEEDS_SCOPE_CLARIFICATION_WITH_LINKAGE")
        md = plan["scope_clarification_markdown"]
        self.assertIn("spotify/spotify-web-api-ts-sdk", md)
        self.assertIn("40427", md)
        self.assertIn("40428", md)
        self.assertIn("no vulnerability details", md.lower())

    def test_cli_reports_exporters_and_project_analyzer_wiring(self) -> None:
        report_payload = {
            "project_name": "PlaylistsApi.ts",
            "raw_content": "export async function getPlaylist(id: string) { return get(`playlists/${id}`); }\n",
            "findings": [
                {
                    "id": "F-CIMD",
                    "title": "isCimdClientId metadata check",
                    "evidence": "requiresPkce: true",
                },
                {
                    "id": "F-DCR-1",
                    "title": "resolveDcrClient bypass",
                    "evidence": "requiresPkce: false",
                },
                {
                    "id": "F-DCR-2",
                    "title": "verifyRevocationClient missing oidcClientId check",
                    "evidence": "oidcClientId",
                },
            ],
            "targets": [
                {
                    "repo": "backstage/backstage",
                    "component": "@backstage/plugin-auth-backend",
                    "linkage_to_core_asset": "Core Backstage source code",
                }
            ],
            "structured_scopes": [
                {
                    "id": "93787",
                    "asset_identifier": "Core Backstage source code",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                }
            ],
        }

        chains_json = json.loads(cli_reports.export_branch_aware_chains_json(report_payload))
        self.assertEqual(chains_json["format"], "sniper-branch-constrained-chain-partition/1")
        self.assertEqual(chains_json["partition_count"], 2)

        scope_json = json.loads(cli_reports.export_scope_wave_plan_json(report_payload))
        self.assertEqual(scope_json["format"], "sniper-scope-wave-plan/1")
        self.assertEqual(len(scope_json["wave_1_immediate"]), 1)

        if (APP_DIR / "cspt_sdk_auditor.py").is_file():
            cspt_json = json.loads(cli_reports.export_cspt_sdk_audit_json(report_payload))
            self.assertEqual(cspt_json["format"], "sniper-cspt-sdk-url-template-audit/1")

        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmpdir:
            ts_file = Path(tmpdir) / "PlaylistsApi.ts"
            ts_file.write_text(
                "export class PlaylistsApi {\n"
                "  async getPlaylist(playlist_id: string) {\n"
                "    return this.getRequest(`playlists/${playlist_id}`);\n"
                "  }\n"
                "  async verifyRevocationClient(token: any, client: any) {\n"
                "    return token.sub === client.sub;\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
            scan_res = project_analyzer.analyze_project(tmpdir)
            self.assertIsInstance(scan_res.get("findings"), list)


if __name__ == "__main__":
    unittest.main()
