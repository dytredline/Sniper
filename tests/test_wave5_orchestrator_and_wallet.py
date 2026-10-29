from __future__ import annotations

from container_orchestrator_auditor import audit_programmatic_container_orchestration
from crypto_wallet_signing_auditor import audit_wallet_signing_and_domain_separation


def test_orch_port_01_and_mount_02_red_winarena_cli_py() -> None:
    vulnerable_cli_py = '''
import subprocess

def start_winarena_container(args, setup_path: str) -> None:
    cmd = [
        "docker",
        "run",
        "--name", "winarena",
        "--cap-add=NET_ADMIN",
        "--device=/dev/kvm",
        "-p", f"{args.browser_port}:8006",
        "-p", f"{args.rdp_port}:3389",
        "-v", f"{setup_path}:/shared",
        "trycua/winarena:latest",
    ]
    subprocess.run(cmd, check=True)
'''
    res = audit_programmatic_container_orchestration(
        vulnerable_cli_py,
        filename="winarena_adapter/cli.py",
    )
    assert res["format"] == "sniper-container-orchestrator-audit/1"
    assert res["filename"] == "winarena_adapter/cli.py"
    assert res["finding_count"] >= 2

    by_id = {f["control_id"]: f for f in res["findings"]}
    assert "SNIPER-ORCH-PORT-01" in by_id
    assert "SNIPER-ORCH-MOUNT-02" in by_id

    port_f = by_id["SNIPER-ORCH-PORT-01"]
    assert port_f["cwe"] == "CWE-668"
    assert port_f["reference"] == "CWE-668"
    assert port_f["severity"] == "high"
    assert port_f["category"] == "container"
    assert (
        port_f["title"]
        == "Programatik konteyner/VM başlatıcısında (docker run) 0.0.0.0 arayüzüne açık hassas port bağlaması"
    )

    mount_f = by_id["SNIPER-ORCH-MOUNT-02"]
    assert mount_f["cwe"] == "CWE-732"
    assert mount_f["reference"] == "CWE-732"
    assert mount_f["severity"] == "high"
    assert mount_f["category"] == "container"
    assert (
        mount_f["title"]
        == "Programatik konteyner/VM başlatıcısında konak kurulum/betik dizininin yazılabilir (:rw) bağlanması"
    )


def test_orch_port_01_and_mount_02_red_cuabotd_ts() -> None:
    vulnerable_cuabotd_ts = '''
import { spawn } from "child_process";

export function launchSandboxContainer(port: number, browser_port: number, setup_path: string, scripts_dir: string) {
    const args = [
        "run",
        "-d",
        "--privileged",
        "-p", `0.0.0.0:${port}:10000`,
        `-p ${browser_port}:8006`,
        "-v", `${setup_path}:/shared`,
        `-v ${scripts_dir}:/scripts`,
        "trycua/cuabot:latest",
    ];
    return spawn("docker", args);
}
'''
    res = audit_programmatic_container_orchestration(
        vulnerable_cuabotd_ts,
        filename="cuabotd.ts",
    )
    assert res["finding_count"] >= 2
    control_ids = {f["control_id"] for f in res["findings"]}
    assert "SNIPER-ORCH-PORT-01" in control_ids
    assert "SNIPER-ORCH-MOUNT-02" in control_ids


def test_orch_port_01_and_mount_02_green_patched_loopback_and_readonly() -> None:
    patched_cli_py = '''
import subprocess

def start_winarena_container(args, setup_path: str) -> None:
    cmd = [
        "docker",
        "run",
        "--name", "winarena",
        "--cap-add=NET_ADMIN",
        "--device=/dev/kvm",
        "-p", f"127.0.0.1:{args.browser_port}:8006",
        "-p", f"127.0.0.1:{args.rdp_port}:3389",
        "-v", f"{setup_path}:/shared:ro",
        "trycua/winarena:latest",
    ]
    subprocess.run(cmd, check=True)
'''
    res_py = audit_programmatic_container_orchestration(
        patched_cli_py,
        filename="winarena_adapter/cli.py",
    )
    assert res_py["finding_count"] == 0
    assert res_py["findings"] == []

    patched_cuabotd_ts = '''
import { spawn } from "child_process";

export function launchSandboxContainer(port: number, browser_port: number, setup_path: string, scripts_dir: string) {
    const args = [
        "run",
        "-d",
        "--privileged",
        "-p", `127.0.0.1:${port}:10000`,
        `-p 127.0.0.1:${browser_port}:8006`,
        "-v", `${setup_path}:/shared:ro`,
        `-v ${scripts_dir}:/scripts:ro`,
        "trycua/cuabot:latest",
    ];
    return spawn("docker", args);
}
'''
    res_ts = audit_programmatic_container_orchestration(
        patched_cuabotd_ts,
        filename="cuabotd.ts",
    )
    assert res_ts["finding_count"] == 0
    assert res_ts["findings"] == []


def test_wallet_spend_01_red_chia_take_offer_implicit_coin_spend() -> None:
    vulnerable_wallet_py = '''
class WalletRpcApi:
    async def take_offer(self, request: dict) -> dict:
        solver = request.get("solver", {})
        coins = await self.wallet_state_manager.main_wallet.select_coins(
            amount=solver.get("amount", 0)
        )
        spend_bundle = await self.wallet_state_manager.sign_coin_spends(
            coin_spends=solver["spends"],
            selected_coins=coins,
        )
        return {"spend_bundle": spend_bundle}
'''
    res = audit_wallet_signing_and_domain_separation(
        vulnerable_wallet_py,
        filename="wallet_rpc_api.py",
    )
    assert res["format"] == "sniper-wallet-signing-domain-audit/1"
    assert res["filename"] == "wallet_rpc_api.py"
    assert res["finding_count"] == 1

    f = res["findings"][0]
    assert f["control_id"] == "SNIPER-WALLET-SPEND-01"
    assert f["cwe"] == "CWE-863"
    assert f["reference"] == "CWE-863"
    assert f["severity"] == "high"
    assert f["category"] == "authz"
    assert (
        f["title"]
        == "Cüzdan/Teklif imzalama akışında örtük coin seçimi ve aşım kontrolsüz harcama yetkisi (Implicit Coin Spend)"
    )


def test_wallet_spend_01_green_explicit_user_spend_cap() -> None:
    patched_wallet_py = '''
class WalletRpcApi:
    async def take_offer(self, request: dict, max_authorized_amount: int) -> dict:
        solver = request.get("solver", {})
        verify_max_send_amount(solver, max_authorized_amount=max_authorized_amount)
        coins = await self.wallet_state_manager.main_wallet.select_coins(
            amount=solver.get("amount", 0)
        )
        assert_spend_within_user_cap(coins, max_authorized_amount)
        spend_bundle = await self.wallet_state_manager.sign_coin_spends(
            coin_spends=solver["spends"],
            selected_coins=coins,
        )
        return {"spend_bundle": spend_bundle}
'''
    res = audit_wallet_signing_and_domain_separation(
        patched_wallet_py,
        filename="wallet_rpc_api.py",
    )
    assert res["finding_count"] == 0
    assert res["findings"] == []


def test_crypto_domain_02_red_raw_bls_sign_without_domain_separation() -> None:
    vulnerable_bls_py = '''
from blspy import AugSchemeMPL

def sign_governance_payload(sk, payload_hash: bytes):
    signature = AugSchemeMPL.sign(sk, payload_hash)
    return signature
'''
    res = audit_wallet_signing_and_domain_separation(
        vulnerable_bls_py,
        filename="signer.py",
    )
    assert res["finding_count"] == 1
    f = res["findings"][0]
    assert f["control_id"] == "SNIPER-CRYPTO-DOMAIN-02"
    assert f["cwe"] == "CWE-347"
    assert f["reference"] == "CWE-347"
    assert f["severity"] == "high"
    assert f["category"] == "crypto"
    assert (
        f["title"]
        == "Kriptografik imzalama/doğrulama çağrısında alan ayrımı (Domain Separation / Genesis Challenge / ChainID) eksikliği"
    )


def test_crypto_domain_02_green_with_genesis_challenge_domain_separation() -> None:
    patched_bls_py = '''
from blspy import AugSchemeMPL

def sign_governance_payload(sk, payload_hash: bytes, GENESIS_CHALLENGE: bytes):
    domain_bound_msg = payload_hash + GENESIS_CHALLENGE + AGG_SIG_ME_ADDITIONAL_DATA
    signature = AugSchemeMPL.sign(sk, domain_bound_msg)
    return signature
'''
    res = audit_wallet_signing_and_domain_separation(
        patched_bls_py,
        filename="signer.py",
    )
    assert res["finding_count"] == 0
    assert res["findings"] == []
