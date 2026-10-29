"""Wave-4 Agent 1 — Express/TS Sibling Route & SDK Bridge Parity ve OAuth/OIDC State Machine testleri."""

from __future__ import annotations

import unittest

from auth_protocol_auditor import audit_oauth_oidc_state_machine_and_mobile_callbacks
from sibling_parity_auditor import audit_sibling_security_parity


class TestWave4OAuthAndParity(unittest.TestCase):
    def test_express_router_client_auth_parity_detects_missing_token_auth(self) -> None:
        vulnerable_router = """
router.post('/v1/revoke', async (req, res) => {
  const client = await oidcService.verifyRevocationClient(clientId, clientSecret);
  await oidcService.revokeToken(req.body.token, client.clientId);
  return res.status(200).send();
});

router.post('/v1/token', async (req, res) => {
  if (grant_type === 'authorization_code') {
    const tokens = await oidcService.exchangeCodeForToken(code, code_verifier, redirect_uri);
    return res.json(tokens);
  }
  if (grant_type === 'refresh_token') {
    if (hasCredentials) {
      await oidcService.authenticateClient(clientId, clientSecret);
    }
    const tokens = await oidcService.refreshSession(refresh_token, clientId);
    return res.json(tokens);
  }
});
"""
        result = audit_sibling_security_parity(
            vulnerable_router, filename="oidc.router.ts"
        )
        self.assertGreaterEqual(result["finding_count"], 1)
        route_findings = [
            f
            for f in result["findings"]
            if f["rule_id"] == "SNIPER-PARITY-ROUTE-05"
        ]
        self.assertEqual(len(route_findings), 1)
        finding = route_findings[0]
        self.assertEqual(finding["cwe"], "CWE-306")
        self.assertEqual(finding["reference"], "CWE-306")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["category"], "authz")

    def test_express_router_client_auth_parity_safe_when_enforced(self) -> None:
        safe_router = """
router.post('/v1/revoke', async (req, res) => {
  const client = await oidcService.verifyRevocationClient(clientId, clientSecret);
  await oidcService.revokeToken(req.body.token, client.clientId);
  return res.status(200).send();
});

router.post('/v1/token', async (req, res) => {
  const client = await oidcService.verifyRevocationClient(clientId, clientSecret);
  if (grant_type === 'authorization_code') {
    const tokens = await oidcService.exchangeCodeForToken(code, code_verifier, redirect_uri, client.clientId);
    return res.json(tokens);
  }
  if (grant_type === 'refresh_token') {
    const tokens = await oidcService.refreshSession(refresh_token, client.clientId);
    return res.json(tokens);
  }
});
"""
        result = audit_sibling_security_parity(safe_router, filename="oidc.router.ts")
        route_findings = [
            f
            for f in result["findings"]
            if f["rule_id"] == "SNIPER-PARITY-ROUTE-05"
        ]
        self.assertEqual(len(route_findings), 0)

    def test_sdk_postmessage_bridge_parity_detects_wildcard_origin(self) -> None:
        vulnerable_bridge = """
export class EmbeddedSdkBridge {
  private targetOrigin: string = '*';

  constructor(options?: { targetOrigin?: string }) {
    this.targetOrigin = options?.targetOrigin ?? '*';
  }

  private isAllowedOrigin(origin: string): boolean {
    if (this.targetOrigin === '*') {
      return true;
    }
    return origin === this.targetOrigin;
  }

  public send(payload: unknown): void {
    window.parent.postMessage(payload, this.targetOrigin);
  }
}
"""
        result = audit_sibling_security_parity(
            vulnerable_bridge, filename="EmbeddedSdkBridge.ts"
        )
        bridge_findings = [
            f
            for f in result["findings"]
            if f["rule_id"] == "SNIPER-PARITY-BRIDGE-06"
        ]
        self.assertEqual(len(bridge_findings), 1)
        finding = bridge_findings[0]
        self.assertEqual(finding["cwe"], "CWE-346")
        self.assertEqual(finding["reference"], "CWE-346")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["category"], "authz")

    def test_sdk_postmessage_bridge_parity_safe_with_explicit_origin(self) -> None:
        safe_bridge = """
export class EmbeddedSdkBridge {
  private readonly targetOrigin: string;

  constructor(options: { targetOrigin: string }) {
    this.targetOrigin = new URL(options.targetOrigin).origin;
  }

  private isAllowedOrigin(origin: string): boolean {
    return origin === this.targetOrigin;
  }

  public send(payload: unknown): void {
    window.parent.postMessage(payload, this.targetOrigin);
  }
}
"""
        result = audit_sibling_security_parity(
            safe_bridge, filename="EmbeddedSdkBridge.ts"
        )
        bridge_findings = [
            f
            for f in result["findings"]
            if f["rule_id"] == "SNIPER-PARITY-BRIDGE-06"
        ]
        self.assertEqual(len(bridge_findings), 0)

    def test_oidc_dcr_detects_missing_client_binding_and_optional_refresh_check(
        self,
    ) -> None:
        vulnerable_oidc = """
export class OidcService {
  async registerClient(meta: ClientMetadata) {
    return this.repo.save({
      ...meta,
      requiresPkce: false,
    });
  }

  async exchangeCodeForToken(code: string, codeVerifier?: string, redirectUri?: string) {
    const session = await this.sessionRepo.findByCode(code);
    if (session.redirectUri !== redirectUri) {
      throw new Error('Invalid redirect_uri');
    }
    return this.issueTokens(session);
  }

  async refreshSession(refreshToken: string, clientId?: string) {
    const session = await this.sessionRepo.findByRefreshToken(refreshToken);
    if (clientId && session.oidcClientId && clientId !== session.oidcClientId) {
      throw new Error('Client mismatch');
    }
    return this.issueTokens(session);
  }
}
"""
        result = audit_oauth_oidc_state_machine_and_mobile_callbacks(
            vulnerable_oidc, filename="OidcService.ts"
        )
        self.assertEqual(
            result["format"], "sniper-oauth-oidc-state-machine-audit/1"
        )
        self.assertGreaterEqual(result["finding_count"], 1)
        dcr_findings = [
            f
            for f in result["findings"]
            if f["rule_id"] == "SNIPER-OIDC-DCR-04"
        ]
        self.assertEqual(len(dcr_findings), 1)
        finding = dcr_findings[0]
        self.assertEqual(finding["cwe"], "CWE-287")
        self.assertEqual(finding["reference"], "CWE-287")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["category"], "authentication")

    def test_oidc_dcr_safe_when_strict_client_binding_enforced(self) -> None:
        safe_oidc = """
export class OidcService {
  async exchangeCodeForToken(code: string, codeVerifier: string, redirectUri: string, clientId: string) {
    const session = await this.sessionRepo.findByCode(code);
    if (!clientId || session.oidcClientId !== clientId) {
      throw new Error('Client mismatch');
    }
    if (session.redirectUri !== redirectUri) {
      throw new Error('Invalid redirect_uri');
    }
    return this.issueTokens(session);
  }

  async refreshSession(refreshToken: string, clientId: string) {
    const session = await this.sessionRepo.findByRefreshToken(refreshToken);
    if (!clientId || session.oidcClientId !== clientId) {
      throw new Error('Client mismatch');
    }
    return this.issueTokens(session);
  }
}
"""
        result = audit_oauth_oidc_state_machine_and_mobile_callbacks(
            safe_oidc, filename="OidcService.ts"
        )
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["findings"], [])

    def test_oauth_state_detects_premature_reset_session_and_weak_pkce(self) -> None:
        vulnerable_callback = """
func handleRedirectURL(_ url: URL) -> Bool {
    resetSession()
    guard let state = queryParameters["state"], state == expectedState else {
        return false
    }
    return true
}
"""
        result = audit_oauth_oidc_state_machine_and_mobile_callbacks(
            vulnerable_callback, filename="OAuthManager.swift"
        )
        state_findings = [
            f
            for f in result["findings"]
            if f["rule_id"] == "SNIPER-OAUTH-STATE-05"
        ]
        self.assertEqual(len(state_findings), 1)
        finding = state_findings[0]
        self.assertEqual(finding["cwe"], "CWE-352")
        self.assertEqual(finding["reference"], "CWE-352")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["category"], "authentication")

        vulnerable_android_and_pkce = """
if (response.getType() == AuthorizationResponse.Type.TOKEN) {
    swapCodeForToken(response.getCode());
}
const verifier = Array.from({ length: 43 }, () => Math.floor(Math.random() * 36).toString(36)).join('');
"""
        result2 = audit_oauth_oidc_state_machine_and_mobile_callbacks(
            vulnerable_android_and_pkce, filename="AuthCallbackActivity.java"
        )
        self.assertEqual(result2["finding_count"], 1)
        self.assertEqual(
            result2["findings"][0]["rule_id"], "SNIPER-OAUTH-STATE-05"
        )

    def test_oauth_state_safe_when_state_verified_first_and_csprng_used(self) -> None:
        safe_callback = """
func handleRedirectURL(_ url: URL) -> Bool {
    guard let state = queryParameters["state"], state == expectedState else {
        return false
    }
    resetSession()
    return true
}

if (expectedState.equals(response.getState()) && response.getType() == AuthorizationResponse.Type.TOKEN) {
    swapCodeForToken(response.getCode());
}
"""
        result = audit_oauth_oidc_state_machine_and_mobile_callbacks(
            safe_callback, filename="OAuthManager.swift"
        )
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
