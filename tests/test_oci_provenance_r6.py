"""Local OCI/Sigstore-style DSSE provenance contracts (R6)."""

from __future__ import annotations

import base64
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile

import pytest

import container_scan


IDENTITY = "https://builder.example/workflows/release"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_ARTIFACT = "application/vnd.oci.artifact.manifest.v1+json"
DSSE_MEDIA = "application/vnd.dsse.envelope.v1+json"


def _layer() -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        data = b"ID=alpine\nVERSION_ID=3.19\n"
        info = tarfile.TarInfo("etc/os-release")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return out.getvalue()


def _statement(subject_hex: str, identity: str = IDENTITY) -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "image", "digest": {"sha256": subject_hex}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"runDetails": {"builder": {"id": identity}}},
    }


def _pae(payload_type: str, payload: bytes) -> bytes:
    return (
        b"DSSEv1 " + str(len(payload_type.encode())).encode() + b" " + payload_type.encode()
        + b" " + str(len(payload)).encode() + b" " + payload
    )


def _oci(base: Path, *, identity: str = IDENTITY, wrong_subject: bool = False,
         signer=None, tamper_payload: bool = False, oversized: bool = False) -> tuple[Path, str]:
    blobs: dict[str, bytes] = {}

    def add(data: bytes) -> tuple[str, int]:
        digest = hashlib.sha256(data).hexdigest()
        blobs[digest] = data
        return digest, len(data)

    layer = _layer()
    layer_digest, layer_size = add(layer)
    image_manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": "sha256:" + layer_digest,
            "size": layer_size,
        }],
    }, sort_keys=True, separators=(",", ":")).encode()
    image_digest, image_size = add(image_manifest)

    subject = "0" * 64 if wrong_subject else image_digest
    statement = _statement(subject, identity)
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    if oversized:
        payload = json.dumps({**statement, "padding": "x" * (container_scan.MAX_OCI_PROVENANCE_BYTES + 1)}).encode()
    payload_type = "application/vnd.in-toto+json"
    signatures = []
    if signer is not None:
        signature = signer.sign(_pae(payload_type, payload))
        signatures = [{"keyid": "local-root", "sig": base64.b64encode(signature).decode()}]
    envelope = json.dumps({
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode(),
        "signatures": signatures,
    }, sort_keys=True, separators=(",", ":")).encode()
    payload_digest, payload_size = add(envelope)

    artifact_manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": OCI_ARTIFACT,
        "artifactType": "application/vnd.in-toto+json",
        "subject": {"mediaType": OCI_MANIFEST, "digest": "sha256:" + image_digest, "size": image_size},
        "blobs": [{"mediaType": DSSE_MEDIA, "digest": "sha256:" + payload_digest, "size": payload_size}],
    }, sort_keys=True, separators=(",", ":")).encode()
    artifact_digest, artifact_size = add(artifact_manifest)

    index = json.dumps({
        "schemaVersion": 2,
        "manifests": [
            {"mediaType": OCI_MANIFEST, "digest": "sha256:" + image_digest, "size": image_size},
            {
                "mediaType": OCI_ARTIFACT,
                "artifactType": "application/vnd.in-toto+json",
                "digest": "sha256:" + artifact_digest,
                "size": artifact_size,
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": "sha256:" + image_digest,
                },
            },
        ],
    }, sort_keys=True, separators=(",", ":")).encode()

    if tamper_payload:
        blobs[payload_digest] = envelope + b" "

    target = base / "image.tar"
    with tarfile.open(target, "w") as archive:
        for name, data in [("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'), ("index.json", index)]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        for digest, data in blobs.items():
            info = tarfile.TarInfo("blobs/sha256/" + digest)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return target, image_digest


def _scan(path: Path, base: Path, **kwargs) -> dict:
    return container_scan.scan_image(str(path), allowed_roots=(base,), **kwargs)


def test_structural_subject_identity_and_lineage_are_reported_without_crypto_claim() -> None:
    with tempfile.TemporaryDirectory() as raw:
        base = Path(raw)
        image, digest = _oci(base)
        result = _scan(image, base, expected_provenance_identity=IDENTITY)

    provenance = result["container"]["provenance"]
    assert provenance["status"] == "structural_only"
    assert provenance["subject"] == "sha256:" + digest
    assert provenance["subject_status"] == "matched"
    assert provenance["identity_status"] == "matched"
    assert provenance["artifact_lineage"] == "matched"
    assert provenance["builder_identity_sha256"] == hashlib.sha256(IDENTITY.encode()).hexdigest()
    assert provenance["cryptographic_verification"] == {
        "status": "not_run",
        "method": None,
        "trust_root_sha256": None,
    }


def test_real_dsse_ed25519_signature_with_exact_local_trust_root_is_verified() -> None:
    cryptography = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    del cryptography
    with tempfile.TemporaryDirectory() as raw:
        base = Path(raw)
        private = Ed25519PrivateKey.generate()
        public_pem = private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_key = base / "provenance-root.pem"
        public_key.write_bytes(public_pem)
        public_sha = hashlib.sha256(public_pem).hexdigest()
        image, _digest = _oci(base, signer=private)

        result = _scan(
            image,
            base,
            expected_provenance_identity=IDENTITY,
            provenance_public_key_path=str(public_key),
            provenance_public_key_sha256=public_sha,
        )

    provenance = result["container"]["provenance"]
    assert provenance["status"] == "verified"
    assert provenance["cryptographic_verification"] == {
        "status": "verified",
        "method": "dsse-ed25519-local-trust-root",
        "trust_root_sha256": public_sha,
    }


def test_tampered_payload_wrong_subject_and_wrong_identity_fail_closed_without_leak() -> None:
    with tempfile.TemporaryDirectory() as raw:
        base = Path(raw)
        tampered, _digest = _oci(base, tamper_payload=True)
        with pytest.raises(container_scan.ContainerScanError, match="özeti"):
            _scan(tampered, base, expected_provenance_identity=IDENTITY)

    for wrong_subject, expected_identity in ((True, IDENTITY), (False, "https://wrong.example/builder")):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            image, _digest = _oci(base, wrong_subject=wrong_subject)
            result = _scan(image, base, expected_provenance_identity=expected_identity)
        provenance = result["container"]["provenance"]
        assert provenance["status"] == "invalid"
        finding = next(item for item in result["findings"] if item.get("control_id") == "SNIPER-OCI-PROVENANCE-01")
        rendered = json.dumps(finding, sort_keys=True)
        assert IDENTITY not in rendered
        assert expected_identity not in rendered
        assert "payload" not in rendered.casefold()
        assert "token" not in rendered.casefold()


def test_oversized_attestation_and_symlinked_trust_root_are_rejected() -> None:
    with tempfile.TemporaryDirectory() as raw:
        base = Path(raw)
        image, _digest = _oci(base, oversized=True)
        with pytest.raises(container_scan.ContainerScanError, match="provenance.*büyük"):
            _scan(image, base, expected_provenance_identity=IDENTITY)

    with tempfile.TemporaryDirectory() as raw:
        base = Path(raw)
        image, _digest = _oci(base)
        real_key = base / "real.pem"
        real_key.write_bytes(b"not-a-key")
        with pytest.raises(container_scan.ContainerScanError, match="SHA-256"):
            _scan(
                image,
                base,
                expected_provenance_identity=IDENTITY,
                provenance_public_key_path=str(real_key),
                provenance_public_key_sha256="0" * 64,
            )
        link = base / "link.pem"
        link.symlink_to(real_key)
        with pytest.raises(container_scan.ContainerScanError, match="güven kökü"):
            _scan(
                image,
                base,
                expected_provenance_identity=IDENTITY,
                provenance_public_key_path=str(link),
                provenance_public_key_sha256=hashlib.sha256(real_key.read_bytes()).hexdigest(),
            )

