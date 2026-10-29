"""Wave 4 — CSPT SDK URL Şablonu ve İki Aşamalı DNS Rebinding / Metadata Refetch birim testleri."""

from __future__ import annotations

import unittest

from cspt_sdk_auditor import audit_cspt_and_authenticated_url_templates
from http_tls_semantics_auditor import audit_http_redirect_and_tls_semantics


class TestWave4CsptAndDnsRefetch(unittest.TestCase):
    def test_cspt_sdk_unencoded_resource_id_red_and_green(self) -> None:
        vulnerable_ts = """
export class PlaylistsEndpoints extends EndpointsBase {
    public async getPlaylist(playlist_id: string, market?: Market): Promise<Playlist> {
        const params = this.paramsFor({ market });
        return await this.getRequest<Playlist>(`playlists/${playlist_id}${params}`);
    }
}
"""
        red = audit_cspt_and_authenticated_url_templates(
            vulnerable_ts,
            filename="PlaylistsEndpoints.ts",
        )
        self.assertEqual(red["format"], "sniper-cspt-sdk-url-template-audit/1")
        self.assertEqual(red["finding_count"], 1)
        finding = red["findings"][0]
        self.assertEqual(finding["rule_id"], "SNIPER-CSPT-SDK-01")
        self.assertEqual(finding["cwe"], "CWE-22")
        self.assertEqual(finding["reference"], "CWE-22")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["category"], "command_data")
        self.assertEqual(
            finding["title"],
            "Yetkili SDK/İstemci API çağrısında encode edilmemiş kaynak kimliği üzerinden İstemci Tarafı Yol Geçişi (CSPT)",
        )

        remediated_ts = """
export class PlaylistsEndpoints extends EndpointsBase {
    public async getPlaylist(playlist_id: string, market?: Market): Promise<Playlist> {
        const params = this.paramsFor({ market });
        const safeId = encodeURIComponent(playlist_id);
        return await this.getRequest<Playlist>(`playlists/${safeId}${params}`);
    }
}
"""
        green = audit_cspt_and_authenticated_url_templates(
            remediated_ts,
            filename="PlaylistsEndpoints.ts",
        )
        self.assertEqual(green["finding_count"], 0)
        self.assertEqual(green["findings"], [])

    def test_url_template_region_and_firewall_host_red_and_green(self) -> None:
        vulnerable_region_ts = """
export async function fetchDeploymentData(region: string, token: string) {
    const resolved = region || "iad1";
    return await fetch(`https://api-${resolved}.vercel.com/v1/deployments`, {
        headers: { Authorization: `Bearer ${token}` },
    });
}
"""
        red_region = audit_cspt_and_authenticated_url_templates(
            vulnerable_region_ts,
            filename="region-client.ts",
        )
        self.assertEqual(red_region["finding_count"], 1)
        f_region = red_region["findings"][0]
        self.assertEqual(f_region["rule_id"], "SNIPER-URL-TMPL-02")
        self.assertEqual(f_region["cwe"], "CWE-918")
        self.assertEqual(f_region["reference"], "CWE-918")
        self.assertEqual(f_region["severity"], "high")
        self.assertEqual(f_region["category"], "ssrf")
        self.assertEqual(
            f_region["title"],
            "Yetkili giden istekte doğrulanmamış alt-alan adı (region) veya Host başlığı şablonu üzerinden SSRF ve kimlik bilgisi sızıntısı",
        )

        vulnerable_host_ts = """
export async function probeFirewallFlags(firewallHost: string, pathPrefix: string, secret: string) {
    return await fetch(`https://${firewallHost}${pathPrefix}/.well-known/vercel/flags`, {
        headers: { Authorization: `Bearer ${secret}` },
    });
}
"""
        red_host = audit_cspt_and_authenticated_url_templates(
            vulnerable_host_ts,
            filename="firewall-probe.ts",
        )
        self.assertEqual(red_host["finding_count"], 1)
        self.assertEqual(red_host["findings"][0]["rule_id"], "SNIPER-URL-TMPL-02")

        remediated_region_ts = """
export async function fetchDeploymentData(region: string, token: string) {
    const resolved = region || "iad1";
    if (!/^[a-z0-9-]+$/i.test(resolved)) {
        throw new Error("Invalid region format");
    }
    return await fetch(`https://api-${resolved}.vercel.com/v1/deployments`, {
        headers: { Authorization: `Bearer ${token}` },
    });
}
"""
        green_region = audit_cspt_and_authenticated_url_templates(
            remediated_region_ts,
            filename="region-client.ts",
        )
        self.assertEqual(green_region["finding_count"], 0)

    def test_http_dns_rebinding_toctou_red_and_green(self) -> None:
        vulnerable_dns_ts = """
export async function fetchExternalMetadata(targetUrl: string) {
    const parsed = new URL(targetUrl);
    await validateHostNotPrivate(parsed.hostname);
    return await fetch(parsed.toString(), { redirect: "manual" });
}
"""
        red = audit_http_redirect_and_tls_semantics(
            vulnerable_dns_ts,
            filename="metadata-fetcher.ts",
        )
        self.assertEqual(red["finding_count"], 1)
        finding = red["findings"][0]
        self.assertEqual(finding["rule_id"], "SNIPER-HTTP-DNSREBIND-04")
        self.assertEqual(finding["cwe"], "CWE-367")
        self.assertEqual(finding["reference"], "CWE-367")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["category"], "ssrf")
        self.assertEqual(
            finding["title"],
            "DNS doğrulaması (validateHostNotPrivate / lookup) ile IP pinlemesiz fetch çağrısı arasında DNS Rebinding TOCTOU penceresi",
        )

        remediated_dns_ts = """
export async function fetchExternalMetadata(targetUrl: string) {
    const parsed = new URL(targetUrl);
    const { address, family } = await validateHostNotPrivate(parsed.hostname);
    const dispatcher = createPinnedDispatcher(address, family);
    return await fetch(parsed.toString(), { dispatcher, redirect: "manual" });
}
"""
        green = audit_http_redirect_and_tls_semantics(
            remediated_dns_ts,
            filename="metadata-fetcher.ts",
        )
        self.assertEqual(green["finding_count"], 0)

    def test_http_unauthenticated_session_refetch_red_and_green(self) -> None:
        vulnerable_session_ts = """
router.get("/v1/sessions/:sessionId", async (req, res) => {
    const session = await getAuthSession(req.params.sessionId);
    const client = await resolveClient(session.clientId);
    return res.json({ session, client });
});
"""
        red = audit_http_redirect_and_tls_semantics(
            vulnerable_session_ts,
            filename="sessions.ts",
        )
        self.assertEqual(red["finding_count"], 1)
        finding = red["findings"][0]
        self.assertEqual(finding["rule_id"], "SNIPER-HTTP-REFETCH-05")
        self.assertEqual(finding["cwe"], "CWE-367")
        self.assertEqual(finding["reference"], "CWE-367")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["category"], "authz")
        self.assertEqual(
            finding["title"],
            "Kimlik doğrulamasız oturum uç noktasında (getAuthSession / /v1/sessions) redirectUri doğrulamasız tekrarlı metadata refetch ve TOCTOU",
        )

        remediated_session_ts = """
router.get("/v1/sessions/:sessionId", async (req, res) => {
    const session = await getAuthSession(req.params.sessionId);
    const client = await resolveClient(session.clientId, session.redirectUri);
    validateRedirectUri(client, session.redirectUri);
    return res.json({ session, client });
});
"""
        green = audit_http_redirect_and_tls_semantics(
            remediated_session_ts,
            filename="sessions.ts",
        )
        self.assertEqual(green["finding_count"], 0)


if __name__ == "__main__":
    unittest.main()
