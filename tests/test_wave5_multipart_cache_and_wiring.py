"""Wave 5 — Multipart Upload Delete, P2P State Cache Poisoning ve Uçtan Uca Bağlantı Testleri."""

from __future__ import annotations

import json
from pathlib import Path
import sys

APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import cli_reports  # noqa: E402
import multipart_and_cache_auditor  # noqa: E402
import project_analyzer  # noqa: E402


def test_multipart_upload_unconditional_delete_red_vs_green() -> None:
    red_rust = """
    pub async fn handle_upload(&self, method: &str, key: &str, params: &HashMap<String, String>) -> Result<(), Error> {
        let _safe_key = self.object_path(key)?;
        match method {
            "DELETE" => {
                let id = params.get("uploadId").cloned().unwrap_or_default();
                self.uploads.write().await.remove(&id);
                let upload_dir = self.root.join("uploads").join(&id);
                let _ = tokio::fs::remove_dir_all(&upload_dir).await;
                Ok(())
            }
            _ => Ok(()),
        }
    }
    """
    res_red = multipart_and_cache_auditor.audit_multipart_upload_and_state_cache(
        red_rust, filename="objectstore.rs"
    )
    assert res_red["format"] == "sniper-multipart-and-cache-audit/1"
    assert res_red["finding_count"] == 1
    finding = res_red["findings"][0]
    assert finding["control_id"] == "SNIPER-UPLOAD-DEL-01"
    assert finding["cwe"] == "CWE-22"
    assert finding["severity"] == "high"
    assert finding["category"] == "command_data"

    green_rust = """
    fn upload_dir(&self, id: &str) -> Result<PathBuf, Error> {
        if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::InvalidUploadId);
        }
        Ok(self.root.join("uploads").join(id))
    }

    pub async fn handle_upload(&self, method: &str, key: &str, params: &HashMap<String, String>) -> Result<(), Error> {
        let _safe_key = self.object_path(key)?;
        match method {
            "DELETE" => {
                let id = params.get("uploadId").cloned().unwrap_or_default();
                let dir = self.upload_dir(&id)?;
                let removed = self.uploads.write().await.remove(&id);
                if removed.is_some() {
                    let _ = tokio::fs::remove_dir_all(&dir).await;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    """
    res_green = multipart_and_cache_auditor.audit_multipart_upload_and_state_cache(
        green_rust, filename="objectstore.rs"
    )
    assert res_green["finding_count"] == 0
    assert res_green["findings"] == []


def test_p2p_state_cache_poisoning_red_vs_green() -> None:
    red_py = """
    async def new_peak(self, msg: NewPeakMessage) -> None:
        self.peak_cache[msg.header_hash] = {"weight": msg.weight, "sub_epoch": None}
        if not self.verify_proof(msg):
            return
    """
    res_red = multipart_and_cache_auditor.audit_multipart_upload_and_state_cache(
        red_py, filename="full_node.py"
    )
    assert res_red["finding_count"] == 1
    finding = res_red["findings"][0]
    assert finding["control_id"] == "SNIPER-P2P-CACHE-02"
    assert finding["cwe"] == "CWE-400"
    assert finding["severity"] == "high"
    assert finding["category"] == "dos"

    green_py = """
    async def new_peak(self, msg: NewPeakMessage) -> None:
        if not self.verify_proof(msg) or not self.validate_weight(msg):
            return
        if msg.header_hash not in self.peak_cache:
            self.peak_cache[msg.header_hash] = {"weight": msg.weight, "sub_epoch": msg.sub_epoch}
    """
    res_green = multipart_and_cache_auditor.audit_multipart_upload_and_state_cache(
        green_py, filename="full_node.py"
    )
    assert res_green["finding_count"] == 0
    assert res_green["findings"] == []


def test_wave5_cli_reports_json_exporters() -> None:
    orch_json = cli_reports.export_container_orchestrator_audit_json(
        {
            "project_name": "cli.py",
            "raw_content": 'cmd = ["docker", "run", "-p", "8006:8006", "-v", f"{host_dir}:/shared", "vm:latest"]',
        }
    )
    orch_payload = json.loads(orch_json)
    assert orch_payload["format"] == "sniper-container-orchestrator-audit/1"
    assert orch_payload["finding_count"] >= 2

    wallet_json = cli_reports.export_wallet_signing_audit_json(
        {
            "project_name": "wallet_rpc_api.py",
            "raw_content": (
                "async def sign_coin_spends(self, req):\n"
                "    coins = await self.select_coins(req.amount)\n"
                "    sig = AugSchemeMPL.sign(sk, msg)\n"
                "    return await self.generate_signed_transaction(coins)\n"
            ),
        }
    )
    wallet_payload = json.loads(wallet_json)
    assert wallet_payload["format"] == "sniper-wallet-signing-domain-audit/1"
    assert wallet_payload["finding_count"] >= 2

    mpc_json = cli_reports.export_multipart_cache_audit_json(
        {
            "project_name": "objectstore.rs",
            "raw_content": (
                'let id = params.get("uploadId").unwrap();\n'
                'let dir = self.root.join("uploads").join(&id);\n'
                "let _ = tokio::fs::remove_dir_all(&dir).await;\n"
            ),
        }
    )
    mpc_payload = json.loads(mpc_json)
    assert mpc_payload["format"] == "sniper-multipart-and-cache-audit/1"
    assert mpc_payload["finding_count"] == 1
    assert mpc_payload["findings"][0]["control_id"] == "SNIPER-UPLOAD-DEL-01"


def test_project_analyzer_wave5_end_to_end_wiring() -> None:
    import tempfile

    cache_root = Path.home() / ".cache"
    cache_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=cache_root) as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "cli.py").write_text(
            'def launch(host_dir: str):\n'
            '    return ["docker", "run", "-p", "8006:8006", "-v", f"{host_dir}:/shared"]\n',
            encoding="utf-8",
        )
        (tmp_path / "wallet_rpc_api.py").write_text(
            "async def take_offer(self, req):\n"
            "    coins = await self.select_coins(req.amount)\n"
            "    sig = AugSchemeMPL.sign(self.sk, req.msg)\n"
            "    return await self.sign_coin_spends(coins, sig)\n",
            encoding="utf-8",
        )
        (tmp_path / "objectstore.rs").write_text(
            "pub async fn abort_upload(&self, uploadId: String) {\n"
            '    let upload_dir = self.root.join("uploads").join(&uploadId);\n'
            "    let _ = tokio::fs::remove_dir_all(&upload_dir).await;\n"
            "}\n",
            encoding="utf-8",
        )
        (tmp_path / "frame_parser.rs").write_text(
            "pub fn parse_packet(data: &[u8]) -> &[u8] {\n"
            "    let len = u16::from_be_bytes([data[0], data[1]]) as usize;\n"
            "    &data[2..2 + len]\n"
            "}\n",
            encoding="utf-8",
        )

        report = project_analyzer.analyze_project(str(tmp_path), allowed_roots=(tmp_path.parent,))
        references = {f["reference"] for f in report["findings"]}
        assert "CWE-668" in references or "CWE-732" in references
        assert "CWE-863" in references or "CWE-347" in references
        assert "CWE-22" in references
        assert "CWE-248" in references
