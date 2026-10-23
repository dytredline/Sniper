#!/usr/bin/env python3

"""SNIPER 2.0 proje denetimlerini listele, dışa aktar ve çalıştır."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
from pathlib import Path
import secrets
import stat
import sys

from nuclei_aggregate_history import AggregateHistoryError, AggregateHistoryJournal


LIVE_SNIPER_ROOT = Path.home() / ".local" / "share" / "sniper"
LIVE_DIR = LIVE_SNIPER_ROOT / "app"
DATA_DIR = LIVE_SNIPER_ROOT / "data"
DB_PATH = Path(os.environ.get("SNIPER_DB_PATH", str(DATA_DIR / "sniper.db"))).expanduser()
# Bu dosyanın bulunduğu checkout; aday kopyası kurulu sürüme sabit yolla bağlanmaz.
APP_DIR = Path(__file__).resolve().parent
CANDIDATE_DIR = APP_DIR


class LiveDatabaseGuard(SystemExit):
    """Aday checkout'un canlı veritabanına açık izin olmadan bağlanmasını engeller."""


def resolve_db_path(db_path: Path | None = None) -> Path:
    """Komut satırı için veritabanı yolunu güvenli biçimde seç.

    Sıra: açık `--db` > `SNIPER_DB_PATH` > kurulu sürümün canlı veritabanı.
    Kurulu dizin dışındaki bir checkout (ör. aday çalışma alanı) açık yol
    vermeden canlı veritabanına bağlanamaz; sentetik veri sınırı korunur.
    """
    if db_path is not None:
        return Path(db_path).expanduser()
    if os.environ.get("SNIPER_DB_PATH"):
        return Path(os.environ["SNIPER_DB_PATH"]).expanduser()
    if APP_DIR != LIVE_DIR.resolve() and os.environ.get("SNIPER_ALLOW_LIVE_DB") != "1":
        raise LiveDatabaseGuard(
            "Bu komut kurulu Sniper dizini dışından çalışıyor; canlı veritabanı korunuyor. "
            "Sentetik bir veritabanı için --db yolu verin veya SNIPER_DB_PATH ayarlayın."
        )
    return DATA_DIR / "sniper.db"


def _read_new_password(from_stdin: bool) -> str:
    import getpass
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("Yeni parola: ")
    if getpass.getpass("Parola (tekrar): ") != first:
        raise SystemExit("Parolalar eşleşmiyor.")
    return first


def manage_users(args, *, db_path: Path | None = None) -> None:
    """Yerel kullanıcı yönetimi. Parola hiçbir zaman yazdırılmaz; işlemler denetim kaydına yazılır."""
    if str(APP_DIR) not in sys.path:
        sys.path.insert(0, str(APP_DIR))
    import auth

    data_dir = Path(args.data_dir).expanduser() if args.data_dir else resolve_db_path(db_path).parent
    manager = auth.AuthManager(data_dir)
    action = args.action
    try:
        if action == "list":
            if not manager.path.is_file():
                print("Giriş kurulmamış (kimlik doğrulama kapalı).")
                return
            print(f"Giriş: {'etkin' if manager.enabled() else 'kapalı'} ({manager.path})")
            for user in manager.list_users():
                flags = [user["role_label"]] + (["kapalı"] if user["disabled"] else []) + (["kilitli"] if user["locked"] else []) \
                    + (["2FA"] if user["totp_enabled"] else [])
                print(f"  {user['username']:<24} {user['id']}  {', '.join(flags)}")
            return
        if action == "disable-auth":
            manager.disable_auth()
            _store(db_path).log("auth.disabled", "auth", {"method": "cli"})
            print("Giriş kapatıldı; tüm oturumlar düşürüldü. Sniper yine yalnız yerel/tünel erişimiyle korunur.")
            return
        if action == "enable-auth":
            manager.enable_auth()
            _store(db_path).log("auth.enabled", "auth", {"method": "cli"})
            print("Giriş etkinleştirildi.")
            return
        if action == "totp-key-status":
            print(json.dumps(manager.totp_field_key_status(), ensure_ascii=False, indent=1, sort_keys=True))
            return
        if action == "rotate-totp-key":
            result = manager.rotate_totp_field_key()
            _store(db_path).log("auth.totp_key_rotated", "auth", {
                "old_key_id": result["old_key_id"],
                "active_key_id": result["active_key_id"],
                "fields_reencrypted": result["fields_reencrypted"],
                "method": "cli",
            })
            print(json.dumps(result, ensure_ascii=False, indent=1, sort_keys=True))
            return
        if action == "totp-migration-status":
            print(json.dumps(manager.totp_legacy_migration_status(), ensure_ascii=False, indent=1, sort_keys=True))
            return
        if action == "open-totp-migration":
            result = manager.open_totp_legacy_migration_window(args.migration_seconds)
            _store(db_path).log("auth.totp_legacy_migration_opened", "auth", {
                "legacy_fields": result["legacy_fields"], "deadline": result["deadline"], "method": "cli",
            })
            print(json.dumps(result, ensure_ascii=False, indent=1, sort_keys=True))
            return
        if not args.username:
            raise SystemExit("--username gerekli.")
        if action == "create-admin":
            user = manager.create_admin_and_enable(args.username, _read_new_password(args.password_stdin))
            _store(db_path).log("auth.user_created", user["id"], {"username": user["username"], "role": "admin", "method": "cli"})
            print(f"Yönetici oluşturuldu ve giriş etkinleştirildi: {user['username']} ({manager.path})")
            return
        user_id = manager.find_user_id(args.username)
        if not user_id:
            raise SystemExit("Kullanıcı bulunamadı.")
        if action == "reset-password":
            manager.update_user(user_id, password=_read_new_password(args.password_stdin), unlock=True)
            _store(db_path).log("auth.user_updated", user_id, {"password_reset": True, "method": "cli"})
            print("Parola sıfırlandı; kullanıcının oturumları düşürüldü.")
        elif action == "unlock":
            manager.update_user(user_id, unlock=True)
            print("Hesap kilidi açıldı.")
    except auth.AuthError as exc:
        raise SystemExit(str(exc)) from None


def _store(db_path: Path | None = None):
    if str(APP_DIR) not in sys.path:
        sys.path.insert(0, str(APP_DIR))
    from storage import Store

    return Store(resolve_db_path(db_path))


def _write_private_file(path: Path, text: str) -> None:
    """0600, sembolik bağ izlemeden yaz (paket kod parçaları, belirteç sır içerir)."""
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o600)


def triage_cli(args, *, db_path: Path | None = None) -> int:
    """25. tur: dış ajan (Claude Code, Codex) ile dosya üzerinden triyaj, proje izni, otomatik uygulama ve MCP belirteci.

    Belirteç hiçbir zaman ekrana yazılmaz; yalnız 0600 dosyaya yazılır."""
    if str(APP_DIR) not in sys.path:
        sys.path.insert(0, str(APP_DIR))
    import ai_triage

    store = _store(db_path)
    data_dir = ai_triage.data_dir_of(store)
    actor = {"id": None, "username": "cli"}
    action = args.triage_action
    try:
        if action == "export":
            packet = ai_triage.build_packet(store, args.project, status=None if args.all else "active",
                                            severity=args.severity, untriaged_only=args.untriaged, limit=args.limit,
                                            context_bytes=args.context_bytes, strip_comments=args.strip_comments)
            _write_private_file(args.out, json.dumps(packet, ensure_ascii=False, indent=1))
            store.log("ai_triage.exported", packet["project_path"], {"findings": len(packet["findings"]), "method": "cli"})
            print(f"{len(packet['findings'])} bulgu pakete yazıldı: {args.out} (0600). Ajana verin; sonuç dosyasını "
                  "'triage import' ile içe aktarın. Uyarı: paket kod parçaları içerir.")
        elif action == "import":
            raw = Path(args.results).expanduser()
            if raw.stat().st_size > 20_000_000:
                raise ai_triage.TriageError("Sonuç dosyası çok büyük.")
            data = json.loads(raw.read_text(encoding="utf-8"))
            report = ai_triage.import_results(store, data, agent=args.agent or "", model=args.model or "", actor=actor)
            print(f"{report['imported']} öneri kaydedildi (analist onayı bekler); {len(report['errors'])} öğe reddedildi.")
            for error in report["errors"][:20]:
                print(f"  #{error['index']} {error.get('finding_id') or '-'}: {error['error']}")
            return 0 if not report["errors"] else 1
        elif action == "consent":
            project_path = ai_triage.resolve_project(store, args.project)
            ai_triage.set_project_consent(data_dir, project_path, args.state == "on", "cli")
            store.log("ai_triage.consent_changed", project_path, {"external_agents": args.state == "on", "method": "cli"})
            print(f"Dış ajana izin {'AÇIK' if args.state == 'on' else 'KAPALI'}: {project_path}")
            if args.state == "on":
                print("Uyarı: dış ajan kullanıldığında kod parçaları ajanın model sağlayıcısına gider (çevrimdışı ilke dışı).")
        elif action == "auto-apply":
            per_agent = None
            global_conf = args.min_confidence
            if args.agent:  # 26. tur: ajan başına eşik (--min-confidence bu durumda ajana uygulanır)
                key = ai_triage.agent_key(args.agent)
                if args.agent_reset:
                    per_agent = {key: None}
                else:
                    entry = {}
                    if args.min_confidence is not None:
                        entry["min_confidence"] = args.min_confidence
                    if args.agent_state:
                        entry["enabled"] = args.agent_state == "on"
                    if not entry:
                        raise ai_triage.TriageError("--agent ile --min-confidence, --agent-state ya da --agent-reset verin.")
                    per_agent = {key: entry}
                global_conf = None
            elif args.agent_state or args.agent_reset:
                raise ai_triage.TriageError("--agent-state/--agent-reset için --agent verin.")
            consensus = {None: None, "on": True, "off": False, "auto": "auto"}[args.consensus]
            policy = ai_triage.set_auto_apply(data_dir, args.state == "on", global_conf, "cli", per_agent=per_agent,
                                              require_consensus=consensus,
                                              consensus_min_confidence=args.consensus_min_confidence)
            store.log("ai_triage.policy_changed", "auto_apply", {**policy["auto_apply"], "method": "cli"})
            auto = policy["auto_apply"]
            mode = {True: "açık", False: "kapalı", "auto": "otomatik (≥2 ajan varsa)"}[auto["require_consensus"]]
            print(f"Otomatik uygulama {'AÇIK' if auto['enabled'] else 'KAPALI'} (genel eşik {auto['min_confidence']}; "
                  f"uzlaşı {mode}, uzlaşı eşiği {auto['consensus_min_confidence']}).")
            for key, entry in sorted(auto["per_agent"].items()):
                print(f"  {key:<12} {'açık' if entry['enabled'] else 'KAPALI':<7} eşik {entry['min_confidence']}")
        elif action == "suggestions":
            project_path = ai_triage.resolve_project(store, args.project)
            for item in ai_triage.list_suggestions(store, project_path=project_path, decision=args.decision, limit=args.limit):
                print(f"{item['id']}  {item['tracked_id']}  {item['verdict']:<12} {item['confidence']:.2f}  "
                      f"{item['decision']:<12} {item['agent'] or item['source']}  {item['finding_title'][:60]}")
        elif action == "mcp-token":
            if args.token_action == "revoke":
                if not args.token_id:
                    raise ai_triage.TriageError("Belirteç kimliği (mct_…) verin.")
                removed = ai_triage.revoke_token(data_dir, args.token_id)
                store.log("ai_triage.mcp_token_revoked", args.token_id, {"removed": removed, "method": "cli"})
                print("Belirteç iptal edildi." if removed else "Belirteç bulunamadı.")
                return 0 if removed else 1
            if args.token_action == "list":
                data = ai_triage._read_json_file(data_dir / ai_triage.TOKENS_FILE, {})
                for record in data.get("tokens", []) if isinstance(data, dict) else []:
                    print(f"{record.get('id')}  {record.get('username')}  {record.get('role')}  {record.get('created_at')}  "
                          f"{record.get('label') or ''}")
                return 0
            if not args.out:
                raise ai_triage.TriageError("Belirteç dosyası için --out verin (ör. ~/.config/sniper/mcp-token).")
            import auth

            manager = auth.manager_for(data_dir)
            if manager.enabled():
                if not args.username:
                    raise ai_triage.TriageError("Giriş etkin: --username ile bir Sniper kullanıcısı verin.")
                user_id = manager.find_user_id(args.username)
                user = manager.get_user(user_id) if user_id else None
                if not user or user.get("disabled"):
                    raise ai_triage.TriageError("Kullanıcı bulunamadı ya da devre dışı.")
                user_id, username, role = user["id"], user["username"], user["role"]
            else:
                user_id, username, role = None, args.username or "yerel", args.role
            token, record = ai_triage.create_token(data_dir, user_id=user_id, username=username, role=role, label=args.label or "")
            _write_private_file(args.out, token + "\n")
            store.log("ai_triage.mcp_token_created", record["id"], {"username": username, "role": role, "method": "cli"})
            print(f"MCP belirteci {record['id']} ({username}, {role}) dosyaya yazıldı: {args.out} (0600). "
                  "Belirteç ekrana yazılmaz; sniper-mcp --token-file ile kullanın.")
        return 0
    except ai_triage.ConsentError as exc:
        raise SystemExit(f"İzin yok: {exc} ('triage consent <proje> on' ile açılabilir.)") from None
    except (ai_triage.TriageError, LookupError, ValueError, OSError) as exc:
        raise SystemExit(str(exc)) from None


def generate_dependency_sbom(project_path: str, output: Path, *, db_path: Path | None = None,
                             fmt: str = "cyclonedx") -> dict:
    """Proje SBOM'u: CycloneDX 1.5 kaydedilir; ``fmt="spdx"`` ise dosyaya SPDX 2.3 JSON yazılır (20. tur)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from dependency_security import generate_cyclonedx_sbom

    document = generate_cyclonedx_sbom(project_path)
    resolved = str(Path(os.path.expandvars(project_path)).expanduser().resolve(strict=True))
    saved = _store(db_path).save_dependency_sbom(resolved, document)
    out_doc = dict(document)
    out_doc["metadata"] = {**document.get("metadata", {}), "timestamp": saved.get("created_at") or ""}
    if fmt == "spdx":
        import sbom_formats

        out_doc = sbom_formats.cyclonedx_to_spdx(out_doc, created=saved.get("created_at"), namespace_seed=saved["id"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(out_doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    label = "SPDX 2.3" if fmt == "spdx" else "CycloneDX"
    print(f"{label} SBOM kaydedildi: {output} ({saved['component_count']} bileşen)")
    return saved


def scan_sbom_file(sbom_path: str, *, view: str = "table", save: bool = False, vex: str | None = None,
                   vex_out: Path | None = None, osv_root: Path | None = None, fail_on: str | None = None,
                   db_path: Path | None = None) -> int:
    """Dış SBOM dosyasını (CycloneDX JSON/XML, SPDX JSON/tag-value) çevrimdışı OSV ile tarar (20. tur)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import sbom_scan

    try:
        result = sbom_scan.scan_sbom(sbom_path, osv_root=osv_root)
    except sbom_scan.SbomScanError as exc:
        print(f"SBOM taraması başarısız: {exc}", file=sys.stderr)
        return 2
    if save:
        saved = _store(db_path).create_project_audit(result)
        print(f"Kaydedildi: {saved['id']}", file=sys.stderr)
    if vex:
        if vex_out is None:
            print("--vex için --vex-out gerekli.", file=sys.stderr)
            return 2
        document = sbom_scan.vex_for_audit(result, vex, author=os.environ.get("USER", ""))["document"]
        vex_out.parent.mkdir(parents=True, exist_ok=True)
        vex_out.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"VEX ({vex}) kaydedildi: {vex_out}", file=sys.stderr)
    info = result["sbom"]
    if view == "json":
        print(json.dumps({key: result[key] for key in ("project_name", "score", "grade", "finding_counts", "warnings",
                                                         "findings")} | {"sbom": {k: v for k, v in info.items()
                                                                                  if k != "dependency_findings"}},
                         ensure_ascii=False, indent=2))
    else:
        print(f"SBOM: {result['project_name']} ({info['source_format']} {info['spec_version']}) · bileşen "
              f"{info['component_count']} · eşlenen {info['matched_components']} · bulgu {len(result['findings'])} · "
              f"puan {result['score']} ({result['grade']})")
        for warning in result["warnings"]:
            print(f"Uyarı: {warning}")
        for finding in result["findings"][:200]:
            package = finding.get("package") or {}
            fix = finding.get("fixed_version") or "düzeltme yok"
            print(f"  [{finding['severity'].upper():8}] {finding.get('reference', '')}  {package.get('source', '')} "
                  f"{package.get('installed_version', '')} → {fix}")
        if len(result["findings"]) > 200:
            print(f"  … {len(result['findings']) - 200} bulgu daha (--view json)")
    if fail_on:
        order = ("low", "medium", "high", "critical")
        threshold = order.index(fail_on)
        if any(f["severity"] in order and order.index(f["severity"]) >= threshold for f in result["findings"]):
            return 1
    return 0


def export_dependency_vex(project_path: str, output: Path, fmt: str = "openvex", *, db_path: Path | None = None,
                          dev_not_affected: bool = False) -> dict:
    """Kayıtlı bağımlılık bulgularından VEX (OpenVEX / CycloneDX VEX) üretir; denetim kaydına yazar."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import vex_export

    store = _store(db_path)
    result = vex_export.generate_for_project(store, project_path, fmt, author=os.environ.get("USER", ""),
                                             dev_not_affected=dev_not_affected)
    store.log("dependency_vex.exported", result["project_name"][:120],
              {"format": fmt, "statements": result["summary"]["total"], "statuses": result["summary"]["statuses"], "method": "cli"})
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result["document"], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    counts = ", ".join(f"{vex_export.STATUS_LABELS[k]} {v}" for k, v in result["summary"]["statuses"].items())
    print(f"VEX ({fmt}) kaydedildi: {output} — {result['summary']['total']} ifade ({counts})")
    return result


def scan_container_image(image_path: str, *, view: str = "table", sbom: Path | None = None, save: bool = False,
                         ignore_unfixed: bool = False, osv_root: Path | None = None, fail_on: str | None = None,
                         dockerfile_path: str | None = None, db_path: Path | None = None) -> int:
    """Konteyner imajı / rootfs işletim sistemi paket taraması (Docker daemon yok, ağ yok). Çıkış kodu: --fail-on
    verilirse o önemde ya da üstünde bulgu varsa 1."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import container_scan

    try:
        result = container_scan.scan_image(
            image_path,
            osv_root=osv_root,
            ignore_unfixed=ignore_unfixed,
            dockerfile_path=dockerfile_path,
        )
    except container_scan.ContainerScanError as exc:
        print(f"Konteyner taraması başarısız: {exc}", file=sys.stderr)
        return 2
    if save:
        saved = _store(db_path).create_project_audit(result)
        print(f"Kaydedildi: {saved['id']}", file=sys.stderr)
    if sbom is not None:
        sbom.parent.mkdir(parents=True, exist_ok=True)
        sbom.write_text(json.dumps(container_scan.cyclonedx_sbom(result), ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
        print(f"CycloneDX SBOM kaydedildi: {sbom}", file=sys.stderr)
    container = result["container"]
    if view == "json":
        print(json.dumps({key: result[key] for key in ("project_name", "score", "grade", "finding_counts", "warnings",
                                                         "container", "findings")}, ensure_ascii=False, indent=2))
    else:
        os_info = container["os"]
        print(f"İmaj: {result['project_name']} ({container['image']['format']}, {container['image']['layers']} katman)")
        print(f"İşletim sistemi: {os_info['pretty_name'] or os_info['id']} → OSV {os_info['ecosystem'] or '-'}")
        print(f"Paket: {container['package_count']} · dil paketi: {container['language_components']} · "
              f"bulgu: {len(result['findings'])} (düzeltmesi olan {container['fixable_findings']}) · "
              f"puan {result['score']} ({result['grade']})")
        for warning in result["warnings"]:
            print(f"Uyarı: {warning}")
        for finding in result["findings"][:200]:
            package = finding.get("package") or {}
            fix = finding.get("fixed_version") or "düzeltme yok"
            print(f"  [{finding['severity'].upper():8}] {finding.get('reference', '')}  {package.get('source', '')} "
                  f"{package.get('installed_version', '')} → {fix}")
        if len(result["findings"]) > 200:
            print(f"  … {len(result['findings']) - 200} bulgu daha (--view json)")
    if fail_on:
        order = ["info", "low", "medium", "high", "critical"]
        threshold = order.index(fail_on)
        if any(order.index(f["severity"]) >= threshold for f in result["findings"]):
            return 1
    return 0


def import_dependency_report(
    report_path: str,
    project_path: str,
    source: str = "auto",
    *,
    db_path: Path | None = None,
) -> dict:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from dependency_security import import_report

    result = _store(db_path).import_dependency_findings(import_report(report_path, project_path, source))
    state = "önceden içe aktarılmış" if result.get("deduplicated") else "içe aktarıldı"
    print(f"{result['source'].upper()} raporu {state}: {result['finding_count']} bulgu")
    return result


def list_dependency_findings(view: str = "table", *, db_path: Path | None = None) -> list[dict]:
    report = _store(db_path).dependency_security()
    rows = report["findings"]
    if view == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return rows
    if not rows:
        print("Bağımlılık Bulguları: Henüz veri yok.")
        return rows
    print("-" * 110)
    print(f"{'Kimlik':<15} {'CVE/OSV':<22} {'Paket':<28} {'Sürüm':<14} {'Önem':<10} {'Durum':<16}")
    print("-" * 110)
    for row in rows:
        print(
            f"{row['id'][:13]:<15} {row['vulnerability_id'][:21]:<22} {row['package_name'][:27]:<28} "
            f"{row['installed_version'][:13]:<14} {row['severity'][:9]:<10} {row['status'][:15]:<16}"
        )
    print("-" * 110)
    return rows


def export_dependency_report(output: Path, *, db_path: Path | None = None) -> Path:
    report = _store(db_path).dependency_security(limit=2_000)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Bağımlılık güvenliği raporu kaydedildi: {output}")
    return output


def scan_osv_offline(project_path: str, *, db_path: Path | None = None, save: bool = True) -> dict:
    """18. tur: kilit dosyalarını yerel (çevrimdışı) OSV veritabanıyla tüm ekosistemlerde eşle; ağ yok."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import osv_offline

    report = osv_offline.scan_project(project_path)
    for item in report["coverage"]:
        if item.get("status") == "unavailable":
            print(f"  {item['ecosystem']}: {item['components']} bileşen — {item.get('detail', 'veritabanı yok')}")
        else:
            print(f"  {item['ecosystem']}: {item['components']} bileşen, {item.get('affected_packages', 0)} açıklı paket, "
                  f"{item.get('vulnerabilities', 0)} açık (veri {item.get('db_retrieved_utc', '?')[:10]})")
    for warning in report["warnings"]:
        print(f"Uyarı: {warning}")
    if not save:
        print(f"Toplam {len(report['findings'])} bulgu (kaydedilmedi).")
        return report
    result = _store(db_path).import_dependency_findings({k: report[k] for k in (
        "source", "source_path", "source_timestamp", "document_hash", "project_path", "findings")})
    state = "önceden kaydedilmiş" if result.get("deduplicated") else "kaydedildi"
    print(f"Çevrimdışı OSV taraması {state}: {len(report['findings'])} bulgu")
    return result


def query_osv_online(project_path: str, output: Path) -> Path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from dependency_security import discover_components, query_osv_batch_via_tor

    _root, components = discover_components(project_path)
    response = query_osv_batch_via_tor(components)
    if not isinstance(response.get("results"), list) or len(response.get("results")) != len(components):
        raise ValueError("OSV toplu yanıtı sorgulanan her bileşen için tam olarak bir sonuç içermeli")
    scanner_results = []
    for component, result in zip(components, response.get("results", [])):
        if not isinstance(result, dict):
            raise ValueError("OSV toplu sonuç öğesi bir sözlük olmalı")
        vulnerabilities = result.get("vulns", [])
        scanner_results.append({"packages": [{
            "package": {"name": component["name"], "version": component["version"], "ecosystem": component["ecosystem"]},
            "vulnerabilities": vulnerabilities,
        }]})
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"results": scanner_results}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Tor üzerinden OSV sonucu kaydedildi: {output}")
    return output


def _csv_safe(value: object) -> object:
    # Preserve numeric types (int, float) exactly as they are, including negatives
    if isinstance(value, (int, float)):
        return value

    # Convert non-numeric objects to string for inspection
    text = str(value)

    # Check if already prefixed to avoid double-prefixing
    if text.startswith("'"):
        return value

    # Strip leading whitespace to find the first significant character
    stripped = text.lstrip()

    # Define dangerous characters including full-width variants
    dangerous_chars = ("=", "+", "-", "@", "＝", "＋", "－", "＠")

    # Check if the first non-whitespace character is dangerous
    if stripped and stripped[0] in dangerous_chars:
        return "'" + text

    # Neutralize cells beginning with tab, carriage return, or line feed
    # by prefixing an apostrophe if the original text starts with these
    if text and text[0] in ("\t", "\r", "\n"):
        return "'" + text

    return value


def list_projects(limit: int = 50, view: str = "table", *, db_path: Path | None = None) -> None:
    rows = _store(db_path).list_project_audits(limit)
    if not rows:
        if view == "json":
            print("[]")
        else:
            print("Proje Analizleri: Henüz veri yok.")
        return
    if view == "table":
        print("-" * 90)
        print(f"{'ID':<16} {'Proje':<40} {'Skor':>6} {'Derece':>8} {'Tarih':<20}")
        print("-" * 90)
        for row in rows:
            print(
                f"{str(row['id'])[:12]:<16} {str(row['project_name'])[:39]:<40} "
                f"{str(row['score']):>6} {str(row['grade']):>8} {str(row['created_at'])[:19]:<20}"
            )
        print("-" * 90)
        return
    if view == "flat":
        for row in rows:
            print(
                f"{row['project_name']} | Skor: {row['score']} Derece: {row['grade']} "
                f"| ID: {str(row['id'])[:12]}..."
            )
        return
    if view == "json":
        sys.stdout.write(json.dumps(rows, ensure_ascii=False) + "\n")


def compare_scans(
    previous_scan_id: str,
    current_scan_id: str,
    *,
    output: Path | None = None,
    view: str = "json",
    db_path: Path | None = None,
    include_details: bool = True,
    severity_filter: str | None = None,
) -> dict | None:
    """İki taramayı karşılaştır ve çıktı yaz; sonucu döndür (hata durumunda çıkış kodu 1).

    Args:
        severity_filter: Seçilen önem derecesine göre filtrele (critical, high, medium, low, info)
    """
    sys.path.insert(0, str(APP_DIR))
    from scan_diff import create_scan_diff

    scanner_diff = create_scan_diff(_store(db_path))

    try:
        result = scanner_diff.compare_scans(previous_scan_id, current_scan_id, include_details=include_details)
        if severity_filter is not None:
            result = _filter_by_severity(result, severity_filter)

        if view == "table":
            _print_diff_table(result)
        else:
            if view == "html":
                from report_renderers import render_diff_report

                store = _store(db_path)
                output_text = render_diff_report(
                    result, store.get_scan(previous_scan_id) or {}, store.get_scan(current_scan_id) or {},
                )
            elif view == "csv":
                from report_renderers import render_diff_csv

                output_text = render_diff_csv(result)
            else:
                output_text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"

            if output:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(output_text, encoding="utf-8")
                print(f"Karşılaştırma kaydedildi: {output}")
            else:
                print(output_text, end="")
        return result
    except ValueError as exc:
        print(f"Hata: {exc}", file=sys.stderr)
        sys.exit(1)


def resolve_latest_pair(reference: str, *, db_path: Path | None = None) -> tuple[str, str]:
    """Hedefin son iki tamamlanmış taramasını (eski, yeni) bul; yoksa çıkış kodu 1 ile bitir."""
    store = _store(db_path)
    try:
        target = store.find_target(reference)
    except ValueError as exc:
        print(f"Hata: {exc}", file=sys.stderr)
        sys.exit(1)
    if not target:
        print(f"Hata: Hedef bulunamadı: {reference}", file=sys.stderr)
        sys.exit(1)
    pair = store.latest_completed_pair(target["id"])
    if pair is None:
        print(f"Hata: {target.get('hostname') or target['id']} için karşılaştırılacak iki tamamlanmış tarama yok.", file=sys.stderr)
        sys.exit(1)
    print(f"Hedef: {target.get('hostname') or target['id']} · önceki {pair[0]} → sonraki {pair[1]}", file=sys.stderr)
    return pair


def _filter_by_severity(result: dict, severity_filter: str) -> dict:
    """Filter Scan Diff findings and counts while preserving summary metadata."""
    selected = severity_filter.strip().lower()
    valid_severities = {"critical", "high", "medium", "low", "info"}
    if selected not in valid_severities:
        valid = ", ".join(sorted(valid_severities))
        raise ValueError(f"Geçersiz önem derecesi: {severity_filter}. Geçerli değerler: {valid}")

    summary = result["summary"]
    filtered_summary = dict(summary)
    for category in ("new", "resolved", "persistent"):
        by_severity_key = f"{category}_by_severity"
        count = summary[by_severity_key].get(selected, 0)
        filtered_summary[f"{category}_count"] = count
        filtered_summary[by_severity_key] = {selected: count}

    filtered_result = dict(result)
    filtered_result["summary"] = filtered_summary
    for key in ("new_findings", "resolved_findings", "persistent_findings"):
        if key in result:
            filtered_result[key] = [
                finding for finding in result[key]
                if str(finding.get("severity") or "info").strip().lower() == selected
            ]
    return filtered_result


def _print_diff_table(result: dict) -> None:
    """Karşılaştırma sonucunu tablo formatında yazdır."""
    summary = result["summary"]

    print("-" * 80)
    print("SNIPER 2.0 - Tarama Karşılaştırması")
    print("-" * 80)
    target = summary.get("target_hostname") or summary.get("target_id")
    if target:
        print(f"Hedef: {target}")
    print(f"Önceki Tarama: {summary['scan_1_id']} (Skor: {summary['scan_1_score']}/100)")
    print(f"Sonraki Tarama: {summary['scan_2_id']} (Skor: {summary['scan_2_score']}/100)")
    score_delta = summary.get("score_delta")
    score_text = f"{score_delta:+d} puan" if isinstance(score_delta, int) else "—"
    first_finished = str(summary.get("scan_1_finished_at") or "—")[:19]
    second_finished = str(summary.get("scan_2_finished_at") or "—")[:19]
    print(f"Skor Değişimi: {score_text}")
    print(f"Zaman Aralığı: {first_finished} → {second_finished}")
    print("-" * 80)
    new_by = summary.get("new_by_severity", {})
    resolved_by = summary.get("resolved_by_severity", {})
    persistent_by = summary.get("persistent_by_severity", {})
    print(f"Yeni Bulgular:   {summary['new_count']} (Kritik: {new_by.get('critical', 0)}, Yüksek: {new_by.get('high', 0)}, Orta: {new_by.get('medium', 0)}, Düşük: {new_by.get('low', 0)}, Bilgi: {new_by.get('info', 0)})")
    print(f"Giderilmiş:      {summary['resolved_count']} (Kritik: {resolved_by.get('critical', 0)}, Yüksek: {resolved_by.get('high', 0)}, Orta: {resolved_by.get('medium', 0)}, Düşük: {resolved_by.get('low', 0)}, Bilgi: {resolved_by.get('info', 0)})")
    print(f"Devam Eden:      {summary['persistent_count']} (Kritik: {persistent_by.get('critical', 0)}, Yüksek: {persistent_by.get('high', 0)}, Orta: {persistent_by.get('medium', 0)}, Düşük: {persistent_by.get('low', 0)}, Bilgi: {persistent_by.get('info', 0)})")
    print("-" * 80)
    for label, key in (("YENİ", "new_findings"), ("GİDERİLMİŞ", "resolved_findings"), ("DEVAM EDEN", "persistent_findings")):
        findings = result.get(key)
        if not findings:
            continue
        print(f"{label}:")
        for finding in findings:
            severity = str(finding.get("severity") or "info").upper()
            print(f"  [{severity:<8}] {str(finding.get('title') or finding.get('id') or '—')[:70]}")
        print("-" * 80)


def _write_export_text(export_dir: Path, filename: str, text: str) -> Path:
    """Write one report atomically without ever following the destination symlink."""
    if not filename or filename in {".", ".."} or "/" in filename or "\\" in filename:
        raise OSError("Geçersiz dışa aktarım dosya adı.")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(export_dir, directory_flags)
    temporary_name = ""
    try:
        try:
            current = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and not stat.S_ISREG(current.st_mode):
            raise OSError("Dışa aktarım hedefi sembolik bağ veya düzenli olmayan dosya.")
        for _attempt in range(20):
            temporary_name = ".sniper-export-" + secrets.token_hex(12)
            try:
                fd = os.open(
                    temporary_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory_fd,
                )
                break
            except FileExistsError:
                continue
        else:
            raise OSError("Güvenli geçici dışa aktarım dosyası oluşturulamadı.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            temporary_name = ""
            try:
                os.fsync(directory_fd)
            except OSError:
                pass
        finally:
            if temporary_name:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except OSError:
                    pass
    finally:
        os.close(directory_fd)
    return export_dir / filename


def export_project(
    audit_id: str,
    output_format: str = "json",
    target_dir: Path | None = None,
    *,
    db_path: Path | None = None,
) -> Path | None:
    row = _store(db_path).get_project_audit(audit_id)
    if not row:
        print(f"Hata: Proje analizi bulunamadı (ID: {audit_id})")
        return None
    project_name = str(row["project_name"])
    clean_name = "".join(c for c in project_name if c.isalnum() or c in "_-")[:50] or "audit"
    export_dir = target_dir or Path.cwd() / "sniper_exports"
    export_dir.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        out_path = _write_export_text(
            export_dir,
            f"{clean_name}_{row['id']}_report.json",
            json.dumps(row, indent=2, ensure_ascii=False) + "\n",
        )
    elif output_format == "sarif":
        sys.path.insert(0, str(APP_DIR))
        from project_audit_diff import render_project_audit_sarif

        sarif_doc = render_project_audit_sarif(row)
        out_path = _write_export_text(
            export_dir,
            f"{clean_name}_{row['id']}_report.sarif.json",
            json.dumps(sarif_doc, indent=2, ensure_ascii=False) + "\n",
        )
    elif output_format == "html":
        sys.path.insert(0, str(APP_DIR))
        from project_audit_diff import render_project_audit_html

        out_path = _write_export_text(
            export_dir,
            f"{clean_name}_{row['id']}_report.html",
            render_project_audit_html(row),
        )
    else:
        csv_buffer = io.StringIO(newline="")
        writer = csv.writer(csv_buffer)
        writer.writerow(("ID", "Project", "Grade", "Score", "Files", "CreatedAt"))
        writer.writerow(
            _csv_safe(value)
            for value in (
                row["id"], project_name, row["grade"], row["score"],
                row["file_count"], row["created_at"],
            )
        )
        out_path = _write_export_text(
            export_dir,
            f"{clean_name}_{row['id']}_report.csv",
            csv_buffer.getvalue(),
        )
    print(f"{output_format.upper()} rapor kaydedildi: {out_path}")
    return out_path


def _cli_scope(args) -> dict | None:
    """``scan`` komutunun --include / --max-*-mb seçeneklerini API kapsam nesnesine çevir."""
    include = set(args.include or [])
    scope: dict = {}
    if "all" in include:
        scope["preset"] = "all"
    dirs = sorted(include & {"tests", "vendor", "packages", "build"})
    if dirs:
        scope["include_dirs"] = dirs
    if "generated" in include:
        scope["include_generated"] = True
    if "non-utf8" in include:
        scope["include_non_utf8"] = True
    if args.max_file_mb is not None:
        scope["max_file_mb"] = args.max_file_mb
    if args.max_total_mb is not None:
        scope["max_total_mb"] = args.max_total_mb
    if getattr(args, "changed_since", None):
        scope["changed_only"] = True
        scope["base_ref"] = args.changed_since
    return scope or None


def run_ci_gate(args, *, db_path: Path | None = None) -> int:
    """ci komutu: politika kapısı (ci_gate). Proje yolunu operatör açıkça verdiği için izinli kök, projenin
    üst dizinidir (CI çalışma dizinleri kullanıcı dizini dışında olabilir: /builds, /home/community-user/work …)."""
    sys.path.insert(0, str(APP_DIR))
    import ci_gate

    try:
        project = Path(os.path.expandvars(os.path.expanduser(args.project_path))).resolve(strict=True)
    except (OSError, RuntimeError):
        print("HATA: Proje dizini bulunamadı.")
        return ci_gate.EXIT_ERROR
    options = ci_gate.CiOptions(
        project=str(project), policy_path=args.policy, sarif=args.sarif, gitlab_dir=args.gitlab_dir,
        summary=args.summary, baseline_sarif=args.baseline_sarif, baseline_audit=args.baseline_audit,
        baseline_ref=args.baseline_ref, sca=not args.no_sca, store=args.store, db_path=db_path,
        allowed_roots=(project.parent,) if project.parent != project else None, max_files=args.limit,
    )
    code, report = ci_gate.run(options)
    for line in ci_gate.console_lines(code, report):
        print(line)
    if args.json is not None and "error" not in report:
        safe = {k: v for k, v in report.items() if k != "summary_markdown"}
        safe["decision"] = dict(safe["decision"], failing=[{k: v for k, v in f.items() if not k.startswith("_kind")}
                                                          for f in safe["decision"]["failing"]])
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(safe, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    return code


def _bulk_slug(repo: Path, root: Path) -> str:
    """Depo başına çıktı dosyası adı: göreli yol + kısa özet (aynı adlı iki depo çakışmaz)."""
    import hashlib
    import re

    rel = "kok" if repo == root else repo.relative_to(root).as_posix()
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", rel).strip("-")[:60] or "depo"
    return f"{base}-{hashlib.sha256(str(repo).encode()).hexdigest()[:6]}"


def _bulk_markdown(root: Path, rows: list[dict], code: int) -> str:
    """Toplu CI özeti (Markdown): depo başına sonuç, bulgu ve kapıyı geçmeyen bulgu sayısı."""
    labels = {0: "✅ geçti", 1: "❌ politika ihlali", 2: "⚠️ yapılandırma hatası", 3: "⚠️ analiz hatası", None: "⏭️ atlandı"}
    lines = [f"## Sniper toplu CI — {root.name}", "",
             f"{len(rows)} depo · sonuç: {'GEÇTİ' if code == 0 else 'BAŞARISIZ'} (çıkış kodu {code})", "",
             "| Depo | Sonuç | Bulgu | Kapıyı geçmeyen | SARIF |", "|---|---|---:|---:|---|"]
    for row in rows:
        name = str(row["rel"]).replace("|", "\\|")
        lines.append(f"| {name} | {labels.get(row.get('code'), str(row.get('code')))}{' — ' + row['error'] if row.get('error') else ''} "
                     f"| {row.get('finding_count', '—')} | {row.get('failing', '—')} | {row.get('sarif') or '—'} |")
    return "\n".join(lines) + "\n"


def run_bulk(args, *, db_path: Path | None = None) -> int:
    """bulk komutu (25. tur): kök dizindeki depoları keşfet; --dry-run yalnız listeler. Aksi halde her depo için
    ``ci`` kapısı ayrı süreçte (en çok --parallel eşzamanlı) çalışır; depo başına SARIF ve tek Markdown özet yazılır.
    Çıkış kodu depoların en kötüsüdür (0 geçti · 1 politika · 2 yapılandırma · 3 analiz hatası)."""
    sys.path.insert(0, str(APP_DIR))
    from concurrent.futures import ThreadPoolExecutor
    import subprocess
    import tempfile

    import bulk_scan
    from project_analyzer import ProjectRejected

    try:
        root = Path(os.path.expandvars(os.path.expanduser(args.root))).resolve(strict=True)
        found = bulk_scan.discover(str(root), max_depth=args.max_depth, max_repos=args.max_repos,
                                   allowed_roots=(root.parent,) if root.parent != root else None)
    except (OSError, RuntimeError, ProjectRejected, bulk_scan.BulkScanError) as exc:
        print(f"HATA: {exc}" if isinstance(exc, ValueError) else "HATA: Kök dizin bulunamadı.")
        return 2
    candidates = [item for item in found["candidates"] if item["selected"] or args.include_large]
    print(f"Kök: {found['root']} · {found['count']} depo bulundu, {len(candidates)} taranacak"
          + (f" · sınır: {', '.join(found['truncated'])}" if found["truncated"] else ""))
    state_data: dict = {}
    if args.state is not None and args.state.is_file():
        try:
            state_data = json.loads(args.state.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            state_data = {}
    state_data = state_data if isinstance(state_data, dict) else {}
    for item in found["candidates"]:
        langs = ", ".join(f"{lang['name']} {lang['files']}" for lang in item["languages"][:3]) or "—"
        remote = (item.get("remote") or {}).get("name") or "—"
        commit = (item.get("commit") or "")[:8] or item.get("git_error") or "git yok"
        flags = []
        if item["too_large"]:
            flags.append("büyük: " + ",".join(item["too_large"]))
        if item.get("commit") and state_data.get(item["path"]) == item["commit"]:
            flags.append("commit değişmedi")
        print(f"  {'•' if item in candidates else '–'} {item['rel']:<40} {item['kind']:<8} {commit:<10} {remote:<30} "
              f"{item['file_count']:>6} dosya  {langs}{'  [' + '; '.join(flags) + ']' if flags else ''}")
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
    if args.dry_run:
        if args.json is not None:
            args.json.write_text(json.dumps(found, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("Kuru çalıştırma: hiçbir depo taranmadı.")
        return 0
    if not candidates:
        print("Taranacak depo yok.")
        return 0
    if args.sarif_dir is not None:
        args.sarif_dir.mkdir(parents=True, exist_ok=True)
    env = {key: value for key, value in os.environ.items() if key != "GITHUB_STEP_SUMMARY"}  # tek özet bu komutta

    def scan(item: dict) -> dict:
        repo = Path(item["path"])
        row = {"rel": item["rel"], "path": item["path"], "commit": item.get("commit")}
        if args.state is not None and item.get("commit") and state_data.get(item["path"]) == item["commit"]:
            row.update(code=None, skipped="unchanged")
            return row
        slug = _bulk_slug(repo, root)
        with tempfile.TemporaryDirectory(prefix="sniper-bulk-") as tmp:
            report_path = Path(tmp) / "report.json"
            command = [sys.executable, str(APP_DIR / "cli_reports.py"), "ci", str(repo), "--json", str(report_path)]
            if args.sarif_dir is not None:
                row["sarif"] = f"{slug}.sarif"
                command += ["--sarif", str(args.sarif_dir / row["sarif"])]
            if args.no_sca:
                command.append("--no-sca")
            if args.store:
                command.append("--store")
            if args.policy is not None:
                command += ["--policy", str(args.policy)]
            if db_path is not None:
                command += ["--db", str(db_path)]
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout, env=env, check=False)
                row["code"] = completed.returncode if completed.returncode in (0, 1, 2, 3) else 3
                if row["code"] >= 2:
                    errors = [line[5:].strip() for line in completed.stdout.splitlines() if line.startswith("HATA:")]
                    row["error"] = (errors[-1] if errors else "analiz başarısız")[:200]
            except subprocess.TimeoutExpired:
                row.update(code=3, error=f"süre aşımı ({args.timeout} sn)")
            if report_path.is_file():
                try:
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                    row["finding_count"] = report.get("finding_count")
                    row["failing"] = len((report.get("decision") or {}).get("failing") or [])
                except (OSError, ValueError):
                    pass
        if row.get("sarif") and not (args.sarif_dir / row["sarif"]).is_file():
            row["sarif"] = None
        return row

    with ThreadPoolExecutor(max_workers=max(1, min(args.parallel, bulk_scan.MAX_PARALLEL))) as pool:
        rows = list(pool.map(scan, candidates))
    codes = [row["code"] for row in rows if row.get("code") is not None]
    code = max(codes) if codes else 0
    for row in rows:
        status = "atlandı (commit değişmedi)" if row.get("code") is None else f"çıkış {row['code']}"
        print(f"  {row['rel']}: {status}" + (f" · {row.get('finding_count')} bulgu" if row.get("finding_count") is not None else "")
              + (f" · {row['error']}" if row.get("error") else ""))
    markdown = _bulk_markdown(root, rows, code)
    summary_path = args.summary or (Path(os.environ["GITHUB_STEP_SUMMARY"]) if os.environ.get("GITHUB_STEP_SUMMARY") else None)
    if summary_path is not None:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with open(summary_path, "a" if args.summary is None else "w", encoding="utf-8") as handle:
            handle.write(markdown)
    if args.json is not None:
        args.json.write_text(json.dumps({"root": found["root"], "exit_code": code, "repos": rows}, ensure_ascii=False, indent=2)
                             + "\n", encoding="utf-8")
    if args.state is not None:
        for row in rows:
            if row.get("code") in (0, 1) and row.get("commit"):
                state_data[row["path"]] = row["commit"]  # analiz tamamlandı (politika sonucu ne olursa olsun)
        args.state.parent.mkdir(parents=True, exist_ok=True)
        args.state.write_text(json.dumps(state_data, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Toplu sonuç: {'GEÇTİ' if code == 0 else 'BAŞARISIZ'} (çıkış kodu {code})")
    return code


def auto_scan_project(
    path: str,
    limit: int = 500,
    *,
    db_path: Path | None = None,
    scope: dict | None = None,
    sarif: Path | None = None,
    fail_on: str | None = None,
    store: bool = True,
) -> dict:
    """Projeyi analiz et. ``fail_on`` verilirse eşik aşıldığında ``result["gate_failed"]`` True olur
    (yalnız değişenler modunda yalnız YENİ bulgular sayılır); çıkış kodunu çağıran belirler."""
    sys.path.insert(0, str(APP_DIR))
    from project_analyzer import analyze_project
    import scan_scope

    print(f"Taranıyor: {path}")
    parsed = scan_scope.parse_scope(scope)
    if parsed.changed_only and parsed.base_ref.startswith("prj_"):
        import changed_scan

        base_audit = _store(db_path).get_project_audit(parsed.base_ref)
        if not base_audit:
            raise SystemExit(f"Karşılaştırılacak analiz bulunamadı: {parsed.base_ref}")
        result = changed_scan.analyze_against_audit(path, base_audit, max_files=limit, scope=parsed)
    else:
        result = analyze_project(path, max_files=limit, scope=parsed)
    for warning in result.get("warnings", []):
        print(f"Uyarı: {warning}")
    saved = _store(db_path).create_project_audit(result) if store else dict(result, id="(kaydedilmedi)")
    print(f"Kaydedildi: ID={saved['id']} Skor={saved['score']} Derece={saved['grade']}" if store
          else f"Kaydedilmedi (--no-store). Skor={saved['score']} Derece={saved['grade']}")
    print(f"Dosyalar: {saved['file_count']} Boyut: {saved['bytes_scanned']:,} bayt")
    if sarif is not None:
        from project_audit_diff import render_project_audit_sarif

        sarif.parent.mkdir(parents=True, exist_ok=True)
        sarif.write_text(json.dumps(render_project_audit_sarif(saved), ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"SARIF: {sarif}")
    if fail_on:
        import changed_scan

        failing = changed_scan.gate_findings(saved, fail_on)
        compared = bool((saved.get("changed_scan") or {}).get("compared"))
        label = "yeni " if compared else ""
        for finding in failing[:20]:
            print(f"  [{finding.get('severity')}] {finding.get('file')}:{finding.get('line')} {finding.get('title')}")
        print(f"Eşik ({fail_on} ve üstü): {len(failing)} {label}bulgu → {'BAŞARISIZ' if failing else 'GEÇTİ'}")
        saved["gate_failed"] = bool(failing)
    return saved


def compare_project_audits_cli(
    audit_1_id: str,
    audit_2_id: str,
    *,
    view: str = "json",
    output: Path | None = None,
    db_path: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from project_audit_diff import compare_project_audits

    result = compare_project_audits(_store(db_path), audit_1_id, audit_2_id)
    if view == "table":
        lines = [
            "-" * 80,
            f"SNIPER 2.0 - Proje Denetimi Karşılaştırması ({result['project_name']})",
            "-" * 80,
            f"Önceki Denetim: {result['audit_1_id']} (Skor: {result['score_1']} / {result['grade_1']})",
            f"Sonraki Denetim: {result['audit_2_id']} (Skor: {result['score_2']} / {result['grade_2']})",
            f"Skor Değişimi:  {result['score_delta']:+d}",
            f"Yeni Bulgular:  {result['new_count']} | Giderilen: {result['resolved_count']} | Devam Eden: {result['persistent_count']}",
            "-" * 80,
        ]
        rendered = "\n".join(lines) + "\n"
    else:
        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return result


def run_quality_gate_cli(
    *,
    target_ref: str | None = None,
    project_audit_id: str | None = None,
    engagement_id: str | None = None,
    min_score: int = 80,
    max_critical: int = 0,
    max_high: int = 0,
    max_medium: int | None = None,
    max_overdue: int = 0,
    min_wstg_coverage: int = 0,
    fail_on_new_findings: bool = False,
    view: str = "json",
    output: Path | None = None,
    db_path: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from quality_gate import evaluate_quality_gate

    result = evaluate_quality_gate(
        _store(db_path),
        target_ref=target_ref,
        project_audit_id=project_audit_id,
        engagement_id=engagement_id,
        min_score=min_score,
        max_critical=max_critical,
        max_high=max_high,
        max_medium=max_medium,
        max_overdue=max_overdue,
        min_wstg_coverage=min_wstg_coverage,
        fail_on_new_findings=fail_on_new_findings,
    )
    if view == "table":
        status_label = "GEÇTİ (PASSED)" if result["passed"] else "KALDI (FAILED)"
        lines = [
            "-" * 80,
            f"SNIPER 2.0 - Güvenlik Kalite Kapısı (Quality Gate): {status_label}",
            "-" * 80,
        ]
        for chk in result.get("checks", []):
            mark = "OK" if chk.get("passed") else "FAIL"
            lines.append(f"[{mark:<4}] {chk.get('title')}: {chk.get('detail')}")
        lines.append("-" * 80)
        rendered = "\n".join(lines) + "\n"
    else:
        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return result


def run_compliance_cli(
    *,
    engagement_id: str | None = None,
    project_audit_id: str | None = None,
    view: str = "json",
    output: Path | None = None,
    db_path: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from compliance_crosswalk import build_compliance_crosswalk

    store = _store(db_path)
    engagement = None
    project_audit = None
    if engagement_id:
        if engagement_id == "latest":
            engs = store.list_engagements()
            if engs:
                engagement = store.get_engagement(engs[0]["id"])
        else:
            engagement = store.get_engagement(engagement_id)
            if engagement is None:
                raise ValueError(f"Manuel denetim bulunamadı: {engagement_id}")
    if project_audit_id:
        if project_audit_id == "latest":
            audits = store.list_project_audits(limit=1)
            if audits:
                project_audit = store.get_project_audit(audits[0]["id"]) or audits[0]
        else:
            project_audit = store.get_project_audit(project_audit_id)
            if project_audit is None:
                raise ValueError(f"Proje denetimi bulunamadı: {project_audit_id}")
    if engagement is None and project_audit is None:
        engs = store.list_engagements()
        if engs:
            engagement = store.get_engagement(engs[0]["id"])
        audits = store.list_project_audits(limit=1)
        if audits:
            project_audit = store.get_project_audit(audits[0]["id"]) or audits[0]

    result = build_compliance_crosswalk(engagement=engagement, project_audit=project_audit)
    if view == "table":
        lines = [
            "-" * 80,
            f"SNIPER 2.0 - Uyumluluk Matrisi (Genel Hazırlık: %{result['overall_readiness_percent']})",
            "-" * 80,
        ]
        for fw in result.get("frameworks", []):
            lines.append(
                f"{fw['name']} ({fw['id']}): %{fw['readiness_percent']} "
                f"(Uyumlu: {fw['compliant_count']}, Uyumsuz: {fw['non_compliant_count']}, İnceleme: {fw['needs_review_count']})"
            )
        lines.append("-" * 80)
        rendered = "\n".join(lines) + "\n"
    else:
        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return result


def _render_mobile_audit_markdown(result: dict) -> str:
    target_label = (
        result.get("project_name")
        or result.get("package_name")
        or result.get("filename")
        or result.get("project_path")
        or "Mobil Uygulama"
    )
    lines = [
        f"# SNIPER 2.0 - Mobil Güvenlik Denetim Raporu ({target_label})",
        "",
        f"- **Format:** `{result.get('format', 'sniper-mobile-security-audit-v1')}`",
        f"- **Hedef / Varlık:** `{target_label}`",
        f"- **Uygulama Profili:** `{result.get('app_profile', 'all')}`",
        f"- **Güvenlik Puanı:** **{result.get('score', 100)}/100** (Derece: **{result.get('grade', 'A')}**)",
        f"- **Toplam Bulgu:** **{result.get('finding_count', len(result.get('findings') or []))}**",
        "",
    ]
    masvs_rows = result.get("masvs_summary") or []
    if masvs_rows:
        lines.extend([
            "## OWASP MASVS v2.1.0 Kontrol Özeti",
            "",
            "| Kontrol | Başlık | Durum | Bulgu Sayısı |",
            "| --- | --- | --- | --- |",
        ])
        for row in masvs_rows:
            lines.append(
                f"| `{row.get('id', '')}` | {row.get('title', '')} | **{row.get('status', '')}** | {row.get('finding_count', 0)} |"
            )
        lines.append("")

    top10_rows = result.get("mobile_top10_summary") or []
    if top10_rows:
        lines.extend([
            "## OWASP Mobile Top 10 (2024) Özeti",
            "",
            "| Kategori | Başlık | Durum | Bulgu Sayısı |",
            "| --- | --- | --- | --- |",
        ])
        for row in top10_rows:
            lines.append(
                f"| `{row.get('id', '')}` | {row.get('title', '')} | **{row.get('status', '')}** | {row.get('finding_count', 0)} |"
            )
        lines.append("")

    findings = result.get("findings") or []
    lines.append("## Bulgular")
    lines.append("")
    if not findings:
        lines.append("Bu denetimde açık mobil güvenlik bulgusu tespit edilmedi.")
    else:
        for idx, f in enumerate(findings, 1):
            sev = str(f.get("severity") or "info").upper()
            title = f.get("title") or "Bulgu"
            masvs = f.get("masvs") or ""
            m10 = f.get("mobile_top10") or ""
            cwe = f.get("cwe") or ""
            loc = f"{f.get('file', '')}:{f.get('line', 1)}" if f.get("file") else "Genel"
            lines.extend([
                f"### {idx}. [{sev}] {title}",
                f"- **Kural / Kontrol:** `{f.get('control_id', '')}` ({masvs} · {m10} · {cwe})",
                f"- **Konum:** `{loc}`",
                f"- **Kanıt:** `{f.get('evidence', '')}`",
                f"- **Öneri:** {f.get('recommendation', '')}",
                "",
            ])
    return "\n".join(lines).rstrip() + "\n"


def _render_mobile_audit_csv(result: dict) -> str:
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow((
        "id",
        "control_id",
        "severity",
        "masvs",
        "mobile_top10",
        "cwe",
        "title",
        "file",
        "line",
        "evidence",
        "recommendation",
    ))
    for f in result.get("findings") or []:
        if not isinstance(f, dict):
            continue
        writer.writerow([
            _csv_safe(f.get("id", "")),
            _csv_safe(f.get("control_id", "")),
            _csv_safe(f.get("severity", "")),
            _csv_safe(f.get("masvs", "")),
            _csv_safe(f.get("mobile_top10", "")),
            _csv_safe(f.get("cwe", "")),
            _csv_safe(f.get("title", "")),
            _csv_safe(f.get("file", "")),
            _csv_safe(f.get("line", 1)),
            _csv_safe(f.get("evidence", "")),
            _csv_safe(f.get("recommendation", "")),
        ])
    return buf.getvalue()


def run_mobile_audit_cli(
    *,
    project_path: str | Path | None = None,
    package_path: str | Path | None = None,
    manifest_file: str | Path | None = None,
    app_profile: str = "all",
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from mobile_security_auditor import (
        SUPPORTED_APP_PROFILES,
        audit_mobile_manifest_inline,
        audit_mobile_package_archive,
        audit_mobile_project,
    )

    profile = (app_profile or "all").strip().lower()
    if profile in {"standard", "default", "general", ""}:
        profile = "all"
    if profile not in SUPPORTED_APP_PROFILES:
        raise ValueError(f"Desteklenmeyen uygulama profili: {app_profile}")

    result: dict | None = None
    if project_path:
        proj_File = Path(os.path.expandvars(os.path.expanduser(str(project_path)))).resolve()
        result = audit_mobile_project(
            str(proj_File),
            app_profile=profile,
            allowed_roots=(proj_File.parent, Path.home().resolve(), Path("/tmp").resolve()),
        )
    if package_path:
        pkg_file = Path(os.path.expandvars(os.path.expanduser(str(package_path)))).resolve()
        pkg_res = audit_mobile_package_archive(
            str(pkg_file),
            allowed_roots=(pkg_file.parent, Path.home().resolve(), Path("/tmp").resolve()),
        )
        if result is None:
            result = pkg_res
        else:
            result["package_audit"] = pkg_res
            existing_ids = {f.get("id") for f in result.get("findings", []) if isinstance(f, dict)}
            for pf in pkg_res.get("findings", []):
                if isinstance(pf, dict) and pf.get("id") not in existing_ids:
                    result.setdefault("findings", []).append(pf)
            result["finding_count"] = len(result.get("findings", []))
    if manifest_file:
        man_path = Path(os.path.expandvars(os.path.expanduser(str(manifest_file)))).resolve(strict=True)
        raw_content = man_path.read_text(encoding="utf-8", errors="ignore")
        man_res = audit_mobile_manifest_inline(
            raw_content,
            filename=man_path.name,
            app_profile=profile,
        )
        if result is None:
            result = man_res
        else:
            result["manifest_audit"] = man_res
            existing_ids = {f.get("id") for f in result.get("findings", []) if isinstance(f, dict)}
            for mf in man_res.get("findings", []):
                if isinstance(mf, dict) and mf.get("id") not in existing_ids:
                    result.setdefault("findings", []).append(mf)
            result["finding_count"] = len(result.get("findings", []))

    if result is None:
        raise ValueError(
            "mobile-audit için --project-path, --package-path veya --manifest-file seçeneklerinden en az biri gereklidir."
        )

    fmt = (output_format or "json").strip().lower()
    if fmt == "markdown":
        rendered = _render_mobile_audit_markdown(result)
    elif fmt == "csv":
        rendered = _render_mobile_audit_csv(result)
    else:
        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"

    if output is not None:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return result


def _write_or_print_cli_output(result: dict, *, output_format: str = "json", output: Path | None = None) -> None:
    fmt = (output_format or "json").strip().lower()
    if fmt == "markdown" and isinstance(result.get("markdown_report"), str):
        rendered = result["markdown_report"]
    elif fmt == "mermaid" and isinstance(result.get("mermaid_diagram") or result.get("mermaid_dfd"), str):
        rendered = str(result.get("mermaid_diagram") or result.get("mermaid_dfd")).rstrip() + "\n"
    elif fmt == "modsecurity" and isinstance(result.get("combined_modsecurity_conf"), str):
        rendered = result["combined_modsecurity_conf"].rstrip() + "\n"
    elif fmt == "sigma" and isinstance(result.get("combined_sigma_yaml"), str):
        rendered = result["combined_sigma_yaml"].rstrip() + "\n"
    elif fmt == "nginx" and isinstance(result.get("nginx_waf_snippet"), str):
        rendered = result["nginx_waf_snippet"].rstrip() + "\n"
    elif fmt == "diff" and isinstance(result.get("patches"), list):
        blocks = [str(p.get("unified_diff") or "").rstrip() for p in result["patches"] if isinstance(p, dict)]
        rendered = ("\n\n".join(b for b in blocks if b) + "\n") if blocks else ""
    elif fmt == "markdown":
        lines = [
            f"# SNIPER 2.0 Denetim Raporu (`{result.get('format', 'sniper-audit-v1')}`)",
            "",
            f"- **Puan:** **{result.get('score', 100)}/100**",
            f"- **Toplam Bulgu:** **{result.get('finding_count', len(result.get('findings') or []))}**",
            "",
            "## Bulgular",
            "",
        ]
        for idx, f in enumerate(result.get("findings") or [], 1):
            if not isinstance(f, dict):
                continue
            lines.extend(
                [
                    f"### {idx}. [{str(f.get('severity') or 'info').upper()}] {f.get('title', 'Bulgu')}",
                    f"- **Kategori / Referans:** `{f.get('category', '')}` · `{f.get('reference', f.get('cwe', ''))}`",
                    f"- **Kanıt:** `{f.get('evidence', '')}`",
                    f"- **Öneri:** {f.get('recommendation', '')}",
                    "",
                ]
            )
        rendered = "\n".join(lines).rstrip() + "\n"
    else:
        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"

    if output is not None:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


def run_ai_llm_audit_cli(
    *,
    project_path: str | Path | None = None,
    file_path: str | Path | None = None,
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from ai_llm_security_auditor import audit_ai_llm_inline, audit_ai_llm_project

    if project_path:
        proj_dir = Path(os.path.expandvars(os.path.expanduser(str(project_path)))).resolve()
        result = audit_ai_llm_project(
            str(proj_dir),
            allowed_roots=(proj_dir.parent, Path.home().resolve(), Path("/tmp").resolve()),
        )
    elif file_path:
        target_f = Path(os.path.expandvars(os.path.expanduser(str(file_path)))).resolve(strict=True)
        raw = target_f.read_text(encoding="utf-8", errors="ignore")
        result = audit_ai_llm_inline(raw, filename=target_f.name)
    else:
        raise ValueError("ai-llm-audit için --project-path veya --file seçeneklerinden biri gereklidir.")

    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_cloud_iam_audit_cli(
    *,
    project_path: str | Path | None = None,
    file_path: str | Path | None = None,
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from cloud_iam_rbac_auditor import audit_cloud_iam_and_k8s_rbac, audit_cloud_iam_project

    if project_path:
        proj_dir = Path(os.path.expandvars(os.path.expanduser(str(project_path)))).resolve()
        result = audit_cloud_iam_project(
            str(proj_dir),
            allowed_roots=(proj_dir.parent, Path.home().resolve(), Path("/tmp").resolve()),
        )
    elif file_path:
        target_f = Path(os.path.expandvars(os.path.expanduser(str(file_path)))).resolve(strict=True)
        raw = target_f.read_text(encoding="utf-8", errors="ignore")
        result = audit_cloud_iam_and_k8s_rbac(raw, filename=target_f.name)
    else:
        raise ValueError("cloud-iam-audit için --project-path veya --file seçeneklerinden biri gereklidir.")

    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_desktop_audit_cli(
    *,
    project_path: str | Path | None = None,
    protocol_file: str | Path | None = None,
    protocol_type: str = "auto",
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from desktop_protocol_security_auditor import (
        audit_desktop_app_project,
        audit_realtime_and_binary_protocols,
    )

    if project_path:
        proj_dir = Path(os.path.expandvars(os.path.expanduser(str(project_path)))).resolve()
        result = audit_desktop_app_project(
            str(proj_dir),
            allowed_roots=(proj_dir.parent, Path.home().resolve(), Path("/tmp").resolve()),
        )
    elif protocol_file:
        target_f = Path(os.path.expandvars(os.path.expanduser(str(protocol_file)))).resolve(strict=True)
        raw = target_f.read_text(encoding="utf-8", errors="ignore")
        result = audit_realtime_and_binary_protocols(raw, protocol_type=protocol_type, filename=target_f.name)
    else:
        raise ValueError("desktop-audit için --project-path veya --protocol-file seçeneklerinden biri gereklidir.")

    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_auth_protocol_audit_cli(
    *,
    artifact: str | None = None,
    file_path: str | Path | None = None,
    artifact_type: str = "auto",
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from auth_protocol_auditor import audit_auth_artifact

    if artifact:
        raw = artifact
    elif file_path:
        target_f = Path(os.path.expandvars(os.path.expanduser(str(file_path)))).resolve(strict=True)
        raw = target_f.read_text(encoding="utf-8", errors="ignore")
    else:
        raise ValueError("auth-protocol-audit için --artifact veya --file seçeneklerinden biri gereklidir.")

    result = audit_auth_artifact(raw, artifact_type=artifact_type)
    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_attack_paths_cli(
    *,
    scan_id: str | None = None,
    project_audit_id: str | None = None,
    engagement_id: str | None = None,
    output_format: str = "json",
    output: Path | None = None,
    db_path: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from attack_path_correlator import correlate_attack_paths

    store = _store(db_path)
    result = correlate_attack_paths(
        store,
        scan_id=scan_id,
        project_audit_id=project_audit_id,
        engagement_id=engagement_id,
    )
    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_auto_patch_cli(
    *,
    scan_id: str | None = None,
    project_audit_id: str | None = None,
    target_stack: str = "auto",
    output_format: str = "json",
    output: Path | None = None,
    db_path: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from auto_remediation_patcher import generate_remediation_patches

    store = _store(db_path)
    scan_obj = None
    proj_obj = None
    if scan_id:
        if scan_id == "latest":
            scans = store.list_scans(limit=1) if hasattr(store, "list_scans") else []
            if scans:
                scan_obj = store.get_scan(scans[0]["id"]) or scans[0]
        else:
            scan_obj = store.get_scan(scan_id)
    if project_audit_id:
        if project_audit_id == "latest":
            audits = store.list_project_audits(limit=1)
            if audits:
                proj_obj = store.get_project_audit(audits[0]["id"]) or audits[0]
        else:
            proj_obj = store.get_project_audit(project_audit_id)
    if scan_obj is None and proj_obj is None:
        audits = store.list_project_audits(limit=1)
        if audits:
            proj_obj = store.get_project_audit(audits[0]["id"]) or audits[0]

    result = generate_remediation_patches(
        scan=scan_obj,
        project_audit=proj_obj,
        target_stack=target_stack,
    )
    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_executive_report_cli(
    *,
    engagement_id: str | None = None,
    project_audit_id: str | None = None,
    scan_id: str | None = None,
    include_patches: bool = True,
    output_format: str = "json",
    output: Path | None = None,
    db_path: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from executive_pentest_report import build_executive_pentest_report

    store = _store(db_path)
    result = build_executive_pentest_report(
        store,
        engagement_id=engagement_id,
        project_audit_id=project_audit_id,
        scan_id=scan_id,
        include_patches=include_patches,
    )
    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_business_logic_audit_cli(
    *,
    project_path: str | Path | None = None,
    file_path: str | Path | None = None,
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from business_logic_auditor import audit_business_logic_inline, audit_business_logic_project

    if project_path:
        proj_dir = Path(os.path.expandvars(os.path.expanduser(str(project_path)))).resolve()
        result = audit_business_logic_project(
            str(proj_dir),
            allowed_roots=(proj_dir.parent, Path.home().resolve(), Path("/tmp").resolve()),
        )
    elif file_path:
        target_f = Path(os.path.expandvars(os.path.expanduser(str(file_path)))).resolve(strict=True)
        raw = target_f.read_text(encoding="utf-8", errors="ignore")
        result = audit_business_logic_inline(raw, filename=target_f.name)
    else:
        raise ValueError("business-logic-audit için --project-path veya --file seçeneklerinden biri gereklidir.")

    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_db_schema_audit_cli(
    *,
    project_path: str | Path | None = None,
    file_path: str | Path | None = None,
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from database_rls_schema_auditor import audit_database_schema_inline, audit_database_schema_project

    if project_path:
        proj_dir = Path(os.path.expandvars(os.path.expanduser(str(project_path)))).resolve()
        result = audit_database_schema_project(
            str(proj_dir),
            allowed_roots=(proj_dir.parent, Path.home().resolve(), Path("/tmp").resolve()),
        )
    elif file_path:
        target_f = Path(os.path.expandvars(os.path.expanduser(str(file_path)))).resolve(strict=True)
        raw = target_f.read_text(encoding="utf-8", errors="ignore")
        result = audit_database_schema_inline(raw, filename=target_f.name)
    else:
        raise ValueError("db-schema-audit için --project-path veya --file seçeneklerinden biri gereklidir.")

    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_crypto_cbom_audit_cli(
    *,
    project_path: str | Path | None = None,
    file_path: str | Path | None = None,
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from crypto_cbom_pqc_auditor import audit_crypto_pqc_inline, audit_crypto_pqc_project

    if project_path:
        proj_dir = Path(os.path.expandvars(os.path.expanduser(str(project_path)))).resolve()
        result = audit_crypto_pqc_project(
            str(proj_dir),
            allowed_roots=(proj_dir.parent, Path.home().resolve(), Path("/tmp").resolve()),
        )
    elif file_path:
        target_f = Path(os.path.expandvars(os.path.expanduser(str(file_path)))).resolve(strict=True)
        raw = target_f.read_text(encoding="utf-8", errors="ignore")
        result = audit_crypto_pqc_inline(raw, filename=target_f.name)
    else:
        raise ValueError("crypto-cbom-audit için --project-path veya --file seçeneklerinden biri gereklidir.")

    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_web3_iot_audit_cli(
    *,
    project_path: str | Path | None = None,
    file_path: str | Path | None = None,
    target_type: str = "auto",
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from web3_iot_firmware_auditor import (
        audit_iot_firmware_inline,
        audit_smart_contract_inline,
        audit_web3_and_iot_project,
    )

    if project_path:
        proj_dir = Path(os.path.expandvars(os.path.expanduser(str(project_path)))).resolve()
        result = audit_web3_and_iot_project(
            str(proj_dir),
            allowed_roots=(proj_dir.parent, Path.home().resolve(), Path("/tmp").resolve()),
        )
    elif file_path:
        target_f = Path(os.path.expandvars(os.path.expanduser(str(file_path)))).resolve(strict=True)
        raw = target_f.read_text(encoding="utf-8", errors="ignore")
        ttype = (target_type or "auto").strip().lower()
        if ttype == "firmware" or (ttype == "auto" and target_f.suffix.lower() in {".c", ".cpp", ".h", ".hpp", ".sh", ".conf", ".service", ".ini"}):
            result = audit_iot_firmware_inline(raw, filename=target_f.name)
        else:
            result = audit_smart_contract_inline(raw, filename=target_f.name)
    else:
        raise ValueError("web3-iot-audit için --project-path veya --file seçeneklerinden biri gereklidir.")

    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_threat_model_cli(
    *,
    project_path: str | Path | None = None,
    scan_id: str | None = None,
    project_audit_id: str | None = None,
    engagement_id: str | None = None,
    output_format: str = "json",
    output: Path | None = None,
    db_path: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from threat_model_generator import generate_threat_model

    store = _store(db_path) if (db_path or scan_id or project_audit_id or engagement_id) else None
    resolved_proj: str | None = None
    allowed_roots: tuple[Path, ...] | None = None
    if project_path:
        proj_dir = Path(os.path.expandvars(os.path.expanduser(str(project_path)))).resolve()
        resolved_proj = str(proj_dir)
        allowed_roots = (proj_dir.parent, Path.home().resolve(), Path("/tmp").resolve())

    result = generate_threat_model(
        store,
        project_path=resolved_proj,
        scan_id=scan_id,
        project_audit_id=project_audit_id,
        engagement_id=engagement_id,
        allowed_roots=allowed_roots,
    )
    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_supply_chain_slsa_cli(
    *,
    project_path: str | Path | None = None,
    workflow_file: str | Path | None = None,
    license_policy: str = "commercial",
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from supply_chain_slsa_auditor import audit_supply_chain_slsa

    resolved_proj: str | None = None
    allowed_roots: tuple[Path, ...] | None = None
    if project_path:
        proj_dir = Path(os.path.expandvars(os.path.expanduser(str(project_path)))).resolve()
        resolved_proj = str(proj_dir)
        allowed_roots = (proj_dir.parent, Path.home().resolve(), Path("/tmp").resolve())

    wf_content: str | None = None
    if workflow_file:
        wf_path = Path(os.path.expandvars(os.path.expanduser(str(workflow_file)))).resolve(strict=True)
        wf_content = wf_path.read_text(encoding="utf-8", errors="ignore")

    if not resolved_proj and wf_content is None:
        raise ValueError("supply-chain-slsa için --project-path veya --workflow-file seçeneklerinden biri gereklidir.")

    result = audit_supply_chain_slsa(
        resolved_proj,
        workflow_content=wf_content,
        license_policy=license_policy,
        allowed_roots=allowed_roots,
    )
    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_blue_team_rules_cli(
    *,
    scan_id: str | None = None,
    project_audit_id: str | None = None,
    target_domain: str = "app.example.com",
    output_format: str = "json",
    output: Path | None = None,
    db_path: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from blue_team_rule_synthesizer import synthesize_blue_team_rules

    scan_obj = None
    proj_obj = None
    if db_path or scan_id or project_audit_id:
        store = _store(db_path)
        if scan_id:
            if scan_id == "latest":
                scans = store.list_scans(limit=1) if hasattr(store, "list_scans") else []
                if scans:
                    scan_obj = store.get_scan(scans[0]["id"]) or scans[0]
            else:
                scan_obj = store.get_scan(scan_id)
        if project_audit_id:
            if project_audit_id == "latest":
                audits = store.list_project_audits(limit=1)
                if audits:
                    proj_obj = store.get_project_audit(audits[0]["id"]) or audits[0]
            else:
                proj_obj = store.get_project_audit(project_audit_id)

    result = synthesize_blue_team_rules(
        scan=scan_obj,
        project_audit=proj_obj,
        target_domain=target_domain,
    )
    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def _resolve_cli_project(project_path: str | Path) -> tuple[str, tuple[Path, ...]]:
    proj_dir = Path(os.path.expandvars(os.path.expanduser(str(project_path)))).resolve()
    return str(proj_dir), (proj_dir.parent, Path.home().resolve(), Path("/tmp").resolve())


def _read_cli_input_file(input_path: str | Path, filename: str | None = None) -> tuple[str, str]:
    target_f = Path(os.path.expandvars(os.path.expanduser(str(input_path)))).resolve(strict=True)
    raw = target_f.read_text(encoding="utf-8", errors="ignore")
    name = filename.strip() if isinstance(filename, str) and filename.strip() else target_f.name
    return raw, name


def _require_single_source(command: str, *sources: object, labels: str = "--project veya --input") -> None:
    provided = [s for s in sources if s]
    if len(provided) != 1:
        raise ValueError(f"{command} için {labels} seçeneklerinden yalnızca biri gereklidir.")


def _run_project_or_inline_cli(
    command: str,
    *,
    project_path: str | Path | None,
    input_path: str | Path | None,
    filename: str | None,
    project_fn,
    inline_fn,
    output_format: str,
    output: Path | None,
) -> dict:
    _require_single_source(command, project_path, input_path)
    if project_path:
        resolved, roots = _resolve_cli_project(project_path)
        result = project_fn(resolved, allowed_roots=roots)
    else:
        raw, name = _read_cli_input_file(input_path, filename)  # type: ignore[arg-type]
        result = inline_fn(raw, filename=name)
    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_secret_intel_cli(
    *,
    project_path: str | Path | None = None,
    input_path: str | Path | None = None,
    filename: str | None = None,
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from secret_intelligence_auditor import audit_secrets_inline, audit_secrets_project

    return _run_project_or_inline_cli(
        "secret-intel",
        project_path=project_path,
        input_path=input_path,
        filename=filename,
        project_fn=audit_secrets_project,
        inline_fn=audit_secrets_inline,
        output_format=output_format,
        output=output,
    )


def run_privacy_dataflow_cli(
    *,
    project_path: str | Path | None = None,
    input_path: str | Path | None = None,
    filename: str | None = None,
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from privacy_dataflow_auditor import audit_privacy_inline, audit_privacy_project

    return _run_project_or_inline_cli(
        "privacy-dataflow",
        project_path=project_path,
        input_path=input_path,
        filename=filename,
        project_fn=audit_privacy_project,
        inline_fn=audit_privacy_inline,
        output_format=output_format,
        output=output,
    )


def run_host_cis_cli(
    *,
    project_path: str | Path | None = None,
    input_path: str | Path | None = None,
    filename: str | None = None,
    config_type: str | None = None,
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from host_cis_hardening_auditor import audit_host_config_inline, audit_host_config_project

    _require_single_source("host-cis", project_path, input_path)
    if project_path:
        resolved, roots = _resolve_cli_project(project_path)
        result = audit_host_config_project(resolved, allowed_roots=roots)
    else:
        raw, name = _read_cli_input_file(input_path, filename)  # type: ignore[arg-type]
        result = audit_host_config_inline(raw, filename=name, config_type=(config_type or "auto"))
    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_dos_resilience_cli(
    *,
    project_path: str | Path | None = None,
    input_path: str | Path | None = None,
    filename: str | None = None,
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from dos_resilience_redos_auditor import audit_dos_resilience_inline, audit_dos_resilience_project

    return _run_project_or_inline_cli(
        "dos-resilience",
        project_path=project_path,
        input_path=input_path,
        filename=filename,
        project_fn=audit_dos_resilience_project,
        inline_fn=audit_dos_resilience_inline,
        output_format=output_format,
        output=output,
    )


def run_audit_logging_cli(
    *,
    project_path: str | Path | None = None,
    input_path: str | Path | None = None,
    filename: str | None = None,
    verify_chain: str | Path | None = None,
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from audit_logging_integrity_auditor import (
        audit_logging_inline,
        audit_logging_project,
        verify_hash_chained_log,
    )

    _require_single_source(
        "audit-logging", project_path, input_path, verify_chain, labels="--project, --input veya --verify-chain"
    )
    if verify_chain:
        chain_path = Path(os.path.expandvars(os.path.expanduser(str(verify_chain)))).resolve(strict=True)
        entries = json.loads(chain_path.read_text(encoding="utf-8", errors="strict"))
        if isinstance(entries, dict) and isinstance(entries.get("entries"), list):
            entries = entries["entries"]
        if not isinstance(entries, list):
            raise ValueError("--verify-chain dosyası bir JSON listesi (veya 'entries' listesi içeren nesne) olmalıdır.")
        result = verify_hash_chained_log(entries)
        _write_or_print_cli_output(result, output_format=output_format, output=output)
        return result
    return _run_project_or_inline_cli(
        "audit-logging",
        project_path=project_path,
        input_path=input_path,
        filename=filename,
        project_fn=audit_logging_project,
        inline_fn=audit_logging_inline,
        output_format=output_format,
        output=output,
    )


def _is_service_worker_name(name: str) -> bool:
    base = Path(name).name.lower()
    stem = base.rsplit(".", 1)[0]
    return (
        stem in {"sw", "service-worker", "service_worker", "serviceworker"}
        or base.startswith(("sw.", "sw-", "sw_"))
        or "service-worker" in base
        or "service_worker" in base
        or "serviceworker" in base
    )


def run_extension_pwa_cli(
    *,
    project_path: str | Path | None = None,
    input_path: str | Path | None = None,
    filename: str | None = None,
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from browser_extension_pwa_auditor import (
        audit_extension_manifest_inline,
        audit_extension_pwa_project,
        audit_extension_script_inline,
        audit_service_worker_inline,
    )

    _require_single_source("extension-pwa", project_path, input_path)
    if project_path:
        resolved, roots = _resolve_cli_project(project_path)
        result = audit_extension_pwa_project(resolved, allowed_roots=roots)
    else:
        raw, name = _read_cli_input_file(input_path, filename)  # type: ignore[arg-type]
        if name.lower().endswith("manifest.json"):
            result = audit_extension_manifest_inline(raw, filename=name)
        elif _is_service_worker_name(name):
            result = audit_service_worker_inline(raw, filename=name)
        else:
            result = audit_extension_script_inline(raw, filename=name)
    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def run_zero_trust_mesh_cli(
    *,
    project_path: str | Path | None = None,
    input_path: str | Path | None = None,
    filename: str | None = None,
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from zero_trust_mesh_auditor import audit_zero_trust_inline, audit_zero_trust_project

    return _run_project_or_inline_cli(
        "zero-trust-mesh",
        project_path=project_path,
        input_path=input_path,
        filename=filename,
        project_fn=audit_zero_trust_project,
        inline_fn=audit_zero_trust_inline,
        output_format=output_format,
        output=output,
    )


def run_cvss_ssvc_cli(
    *,
    input_path: str | Path | None = None,
    vector: str | None = None,
    exposure: str = "internet",
    mission_prevalence: str = "support",
    exploitation: str = "none",
    discovered_at: str | None = None,
    now: str | None = None,
    output_format: str = "json",
    output: Path | None = None,
) -> dict:
    sys.path.insert(0, str(APP_DIR))
    from cvss40 import compute_cvss40
    from cvss_ssvc_prioritizer import (
        CVSS40_NOTE,
        build_cvss40_vector,
        compute_cvss31,
        prioritize_findings,
    )

    _require_single_source("cvss-ssvc", input_path, vector, labels="--input veya --vector")
    if vector and vector.strip().startswith("CVSS:4.0/"):
        result = compute_cvss40(vector)
        result["format"] = "sniper-cvss40-score-v1"
    elif vector:
        result = compute_cvss31(vector)
        result["format"] = "sniper-cvss31-score-v1"
        cvss40 = compute_cvss40(build_cvss40_vector(result["vector"]))
        result["cvss40_vector"] = cvss40["vector"]
        result["cvss40_score"] = cvss40["score"]
        result["cvss40_severity"] = cvss40["severity"]
        result["cvss40_note"] = CVSS40_NOTE
    else:
        raw, _name = _read_cli_input_file(input_path)  # type: ignore[arg-type]
        payload = json.loads(raw)
        if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
            payload = payload["findings"]
        if not isinstance(payload, list):
            raise ValueError("cvss-ssvc --input dosyası bir bulgu listesi veya 'findings' listesi içeren nesne olmalıdır.")
        result = prioritize_findings(
            payload,
            exposure=exposure,
            mission_prevalence=mission_prevalence,
            exploitation=exploitation,
            discovered_at=discovered_at,
            now=now,
        )
    _write_or_print_cli_output(result, output_format=output_format, output=output)
    return result


def list_nuclei_history(data_dir: Path | None = None) -> list[dict]:
    """Read only the owner's bounded, redacted Nuclei aggregate journal."""
    if data_dir is None:
        # A copied checkout must never silently inspect the installed service's data.
        if APP_DIR != LIVE_DIR.resolve():
            raise AggregateHistoryError("açık bir veri dizini gerekli")
        data_dir = DATA_DIR
    data_dir = Path(data_dir).expanduser()
    if not data_dir.is_absolute() or data_dir.resolve(strict=True) != data_dir:
        raise AggregateHistoryError("güvensiz geçmiş dizini")
    directory = data_dir.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid()
            or stat.S_IMODE(directory.st_mode) & 0o077):
        raise AggregateHistoryError("güvensiz geçmiş dizini")
    journal = AggregateHistoryJournal(data_dir)
    return [{"job_id": job_id, **aggregate} for job_id, aggregate in journal.load()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniper-report",
        description="SNIPER 2.0 komut satırı raporlama aracı",
    )
    db_help = "SQLite veritabanı yolu (varsayılan: SNIPER_DB_PATH veya kurulu sürümün canlı veritabanı)"
    parser.add_argument("--db", type=Path, default=None, help=db_help)
    # Aynı seçenek alt komuttan sonra da kabul edilir (`scan-diff A B --db x.db`);
    # SUPPRESS sayesinde alt komut verilmediğinde genel değerin üzerine yazmaz.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", type=Path, default=argparse.SUPPRESS, help=db_help)
    subparsers = parser.add_subparsers(dest="command", help="Komutlar")

    # Arayüz girişi / kullanıcılar (yerel kurtarma yolu da burada)
    users_parser = subparsers.add_parser("users", parents=[common], help="Arayüz girişi ve kullanıcılar (yerel)")
    users_parser.add_argument(
        "action",
        choices=("create-admin", "reset-password", "disable-auth", "enable-auth", "list", "unlock",
                 "totp-key-status", "rotate-totp-key", "totp-migration-status", "open-totp-migration"),
        help=("create-admin: yönetici oluştur + girişi etkinleştir; reset-password; disable-auth; enable-auth; "
              "list; unlock; totp-key-status; rotate-totp-key; totp-migration-status; open-totp-migration"),
    )
    users_parser.add_argument("--username", "-u", help="Kullanıcı adı")
    users_parser.add_argument("--password-stdin", action="store_true", help="Parolayı standart girdiden tek satır oku")
    users_parser.add_argument("--data-dir", type=Path, default=None, help="Sniper veri dizini (varsayılan: veritabanının dizini)")
    users_parser.add_argument("--migration-seconds", type=int, default=900,
                              help="open-totp-migration geçiş penceresi (60–3600 saniye; varsayılan 900)")


    # 25. tur: dış ajan triyajı (Claude Code / Codex): dosya paketi, proje izni, otomatik uygulama, MCP belirteci
    triage_parser = subparsers.add_parser("triage", parents=[common], help="AI/ajan triyajı (paket, izin, MCP belirteci)")
    triage_sub = triage_parser.add_subparsers(dest="triage_action", required=True)
    t_export = triage_sub.add_parser("export", parents=[common], help="Ajan için triyaj paketi (hazır istem + şema + bulgular)")
    t_export.add_argument("project", help="Proje yolu ya da prj_… analiz kimliği")
    t_export.add_argument("--out", "-o", type=Path, required=True, help="Paket dosyası (0600 yazılır)")
    t_export.add_argument("--all", action="store_true", help="Yalnız etkin değil, tüm durumlardaki bulgular")
    t_export.add_argument("--severity", choices=("critical", "high", "medium", "low", "info"))
    t_export.add_argument("--untriaged", action="store_true", help="Yalnız önerisi olmayan bulgular")
    t_export.add_argument("--limit", type=int, default=200)
    t_export.add_argument("--context-bytes", type=int, default=None,
                          help="Bulgu başına bağlam sınırı (bayt; varsayılan 4096 ya da SNIPER_TRIAGE_CONTEXT_BYTES; 0 = bağlam yok)")
    t_export.add_argument("--strip-comments", action="store_true",
                          help="Kod parçası ve bağlamdaki tam satır yorumları çıkar (satır numaraları korunur)")
    t_import = triage_sub.add_parser("import", parents=[common], help="Ajan sonuç dosyasını öneri olarak içe aktar")
    t_import.add_argument("results", help="Sonuç JSON dosyası (sniper-triage-results/1)")
    t_import.add_argument("--agent", help="Ajan adı (dosyadakini geçersiz kılar)")
    t_import.add_argument("--model", help="Model adı (dosyadakini geçersiz kılar)")
    t_consent = triage_sub.add_parser("consent", parents=[common], help="Projede dış ajana izin (varsayılan kapalı)")
    t_consent.add_argument("project", help="Proje yolu ya da prj_… analiz kimliği")
    t_consent.add_argument("state", choices=("on", "off"))
    t_auto = triage_sub.add_parser("auto-apply", parents=[common], help="Yüksek güvenli likely_false önerilerini otomatik uygula")
    t_auto.add_argument("state", choices=("on", "off"))
    t_auto.add_argument("--min-confidence", type=float, default=None,
                        help="Eşik (0,5–1). --agent ile o ajanın eşiği; yoksa genel eşik (verilmezse mevcut korunur)")
    t_auto.add_argument("--agent", help="Ajan anahtarı (ör. claude, codex; 'claude-code' → claude)")
    t_auto.add_argument("--agent-state", choices=("on", "off"), help="Ajan için otomatik uygulamayı aç/kapat")
    t_auto.add_argument("--agent-reset", action="store_true", help="Ajan ayarını kaldır (varsayılan/genel eşiğe dön)")
    t_auto.add_argument("--consensus", choices=("on", "off", "auto"),
                        help="Uzlaşı modu: on = her zaman, off = tek ajan, auto (varsayılan) = projede son 30 günde ≥2 "
                             "etkin ajan varsa; uzlaşıda iki farklı ajan likely_false demeli")
    t_auto.add_argument("--consensus-min-confidence", type=float, default=None,
                        help="Uzlaşı modunda iki ajanın da geçmesi gereken güven (0,5–1; varsayılan 0,70)")
    t_sugg = triage_sub.add_parser("suggestions", parents=[common], help="Projedeki AI/ajan önerilerini listele")
    t_sugg.add_argument("project", help="Proje yolu ya da prj_… analiz kimliği")
    t_sugg.add_argument("--decision", choices=("pending", "accepted", "rejected", "auto_applied", "reverted"))
    t_sugg.add_argument("--limit", type=int, default=200)
    t_token = triage_sub.add_parser("mcp-token", parents=[common], help="MCP oturum belirteci (Sniper kullanıcısına bağlı)")
    t_token.add_argument("token_action", choices=("create", "list", "revoke"))
    t_token.add_argument("token_id", nargs="?", help="revoke için mct_… kimliği")
    t_token.add_argument("--out", "-o", type=Path, help="create: belirteç dosyası (0600; belirteç ekrana yazılmaz)")
    t_token.add_argument("--username", "-u", help="Bağlanacak Sniper kullanıcısı (giriş etkinse zorunlu)")
    t_token.add_argument("--role", choices=("reader", "analyst", "admin"), default="analyst",
                         help="Giriş kapalıyken belirteç rolü (varsayılan analyst)")
    t_token.add_argument("--label", help="Kısa etiket (ör. claude-code)")

    # Scan Diff komutu
    diff_parser = subparsers.add_parser("scan-diff", parents=[common], help="İki taramayı karşılaştır")
    diff_parser.add_argument("previous", nargs="?", help="Önceki (eski) tarama ID (--latest ile gerekmez)")
    diff_parser.add_argument("current", nargs="?", help="Sonraki (yeni) tarama ID (--latest ile gerekmez)")
    diff_parser.add_argument("--latest", metavar="HEDEF", help="Hedef kimliği, URL veya hostname: son iki tamamlanmış taramayı karşılaştır")
    diff_parser.add_argument("--out", "-o", type=Path, help="Çıktı dosyası (varsayılan: stdout)")
    diff_parser.add_argument("--view", "-v", choices=("json", "table", "html", "csv"), default="json", help="Çıktı formatı")
    diff_parser.add_argument("--summary-only", action="store_true", help="Yalnız özet; bulgu listelerini atla")
    diff_parser.add_argument("--severity", "-s", choices=("critical", "high", "medium", "low", "info"), help="Bulguları önem derecesine göre filtrele")

    list_parser = subparsers.add_parser("list", parents=[common], help="Son proje denetimlerini listele")
    list_parser.add_argument("--limit", type=int, default=50, help="En fazla sonuç sayısı")
    list_parser.add_argument("--view", "-v", choices=("table", "flat", "json"), default="table")

    export_parser = subparsers.add_parser("export", parents=[common], help="Bir proje denetimini dışa aktar")
    export_parser.add_argument("audit_id", help="Proje denetimi kimliği")
    export_parser.add_argument("--format", "-f", choices=("json", "csv", "sarif", "html"), default="json")
    export_parser.add_argument("--out", "-o", type=Path, help="Çıktı dizini")

    pdiff_parser = subparsers.add_parser("project-diff", parents=[common], help="İki proje denetimini karşılaştır")
    pdiff_parser.add_argument("previous", help="Önceki proje denetimi kimliği")
    pdiff_parser.add_argument("current", help="Sonraki proje denetimi kimliği")
    pdiff_parser.add_argument("--view", "-v", choices=("json", "table"), default="json", help="Çıktı görünümü")
    pdiff_parser.add_argument("--out", "-o", type=Path, help="Çıktı dosyası (varsayılan: stdout)")

    qgate_parser = subparsers.add_parser("quality-gate", parents=[common], help="CI/CD güvenlik kalite kapısını değerlendir")
    qgate_parser.add_argument("--target", help="Hedef kimliği, URL, hostname veya tarama kimliği")
    qgate_parser.add_argument("--project-audit", dest="project_audit", help="Proje denetimi kimliği (veya 'latest')")
    qgate_parser.add_argument("--engagement", help="Manuel denetim kimliği (veya 'latest')")
    qgate_parser.add_argument("--min-score", type=int, default=80, help="Minimum güvenlik puanı eşiği (varsayılan: 80)")
    qgate_parser.add_argument("--max-critical", type=int, default=0, help="İzin verilen maksimum kritik bulgu sayısı")
    qgate_parser.add_argument("--max-high", type=int, default=0, help="İzin verilen maksimum yüksek bulgu sayısı")
    qgate_parser.add_argument("--max-medium", type=int, default=None, help="İzin verilen maksimum orta bulgu sayısı")
    qgate_parser.add_argument("--max-overdue", type=int, default=0, help="İzin verilen maksimum süresi geçmiş bulgu sayısı")
    qgate_parser.add_argument("--min-wstg-coverage", type=int, default=0, help="Minimum OWASP WSTG kapsam yüzdesi")
    qgate_parser.add_argument("--fail-on-new-findings", action="store_true", help="Yeni bulgu (regresyon) varsa başarısız say")
    qgate_parser.add_argument("--view", "-v", choices=("json", "table"), default="json", help="Çıktı görünümü")
    qgate_parser.add_argument("--out", "-o", type=Path, help="Çıktı dosyası (varsayılan: stdout)")

    comp_parser = subparsers.add_parser("compliance", parents=[common], help="9 çerçeveli (OWASP, ASVS, PCI-DSS, ISO 27001, MASVS, KVKK, GDPR, DORA, NIS2) uyumluluk raporu üret")
    comp_parser.add_argument("--engagement", help="Manuel denetim kimliği (veya 'latest')")
    comp_parser.add_argument("--project-audit", dest="project_audit", help="Proje denetimi kimliği (veya 'latest')")
    comp_parser.add_argument("--view", "-v", choices=("json", "table"), default="json", help="Çıktı görünümü")
    comp_parser.add_argument("--out", "-o", type=Path, help="Çıktı dosyası (varsayılan: stdout)")

    mob_parser = subparsers.add_parser(
        "mobile-audit",
        parents=[common],
        help="OWASP MASVS v2.1.0 ve Mobile Top 10 (2024) mobil güvenlik denetimi çalıştır",
    )
    mob_parser.add_argument("--project-path", dest="project_path", help="Mobil kaynak kodu proje dizini")
    mob_parser.add_argument("--package-path", dest="package_path", help="Mobil paket arşivi (.apk, .aab, .ipa) yolu")
    mob_parser.add_argument("--manifest-file", dest="manifest_file", help="Manifest veya yapılandırma dosyası (AndroidManifest.xml, Info.plist vb.) yolu")
    mob_parser.add_argument(
        "--app-profile",
        dest="app_profile",
        default="all",
        help="Uygulama sektörel profili (all, finance, ecommerce, health, social, enterprise, gaming)",
    )
    mob_parser.add_argument(
        "--format",
        "-f",
        dest="output_format",
        choices=("json", "markdown", "csv"),
        default="json",
        help="Rapor çıktı formatı (json, markdown, csv)",
    )
    mob_parser.add_argument(
        "--output",
        "--out",
        "-o",
        dest="output",
        type=Path,
        help="Çıktı dosyası yolu (varsayılan: stdout)",
    )

    ai_parser = subparsers.add_parser(
        "ai-llm-audit",
        parents=[common],
        help="OWASP Top 10 for LLM Applications (2025) yapay zeka / RAG / MCP güvenlik denetimi çalıştır",
    )
    ai_parser.add_argument("--project-path", dest="project_path", help="Yerel proje dizini")
    ai_parser.add_argument("--file", dest="file_path", help="Tekil Python/JS/JSON/YAML/Dockerfile dosyası")
    ai_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "markdown"), default="json")
    ai_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    iam_parser = subparsers.add_parser(
        "cloud-iam-audit",
        parents=[common],
        help="AWS/GCP/Azure IAM politikaları ve Kubernetes RBAC / PodSecurity denetimi çalıştır",
    )
    iam_parser.add_argument("--project-path", dest="project_path", help="Yerel proje dizini")
    iam_parser.add_argument("--file", dest="file_path", help="Tekil IAM / RBAC / Terraform dosyası")
    iam_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "markdown"), default="json")
    iam_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    desk_parser = subparsers.add_parser(
        "desktop-audit",
        parents=[common],
        help="Electron / Tauri masaüstü uygulaması ve gRPC / WebSocket / Webhook protokol denetimi çalıştır",
    )
    desk_parser.add_argument("--project-path", dest="project_path", help="Masaüstü proje dizini")
    desk_parser.add_argument("--protocol-file", "--file", dest="protocol_file", help="Protokol şeması veya kaynak dosyası (.proto, .ts, .py vb.)")
    desk_parser.add_argument("--protocol-type", dest="protocol_type", choices=("auto", "grpc", "websocket", "webhook"), default="auto")
    desk_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "markdown"), default="json")
    desk_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    auth_parser = subparsers.add_parser(
        "auth-protocol-audit",
        parents=[common],
        help="JWT, OAuth2 / OIDC ve SAML 2.0 kimlik doğrulama artefaktlarını denetle",
    )
    auth_parser.add_argument("--artifact", help="Ham JWT token, OIDC JSON veya SAML XML dizgesi")
    auth_parser.add_argument("--file", dest="file_path", help="Artefakt içeren dosya yolu")
    auth_parser.add_argument("--type", "--artifact-type", dest="artifact_type", choices=("auto", "jwt", "oauth", "oidc", "saml"), default="auto")
    auth_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "markdown"), default="json")
    auth_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    apath_parser = subparsers.add_parser(
        "attack-paths",
        parents=[common],
        help="Çok adımlı saldırı zincirlerini (Attack Path) korele et ve Mermaid grafiği üret",
    )
    apath_parser.add_argument("--scan", dest="scan_id", help="Tarama kimliği")
    apath_parser.add_argument("--project-audit", dest="project_audit", help="Proje denetimi kimliği")
    apath_parser.add_argument("--engagement", help="Manuel denetim kimliği")
    apath_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "mermaid", "markdown"), default="json")
    apath_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    patch_parser = subparsers.add_parser(
        "auto-patch",
        parents=[common],
        help="Bulgular için deterministik unified diff güvenlik yamaları üret",
    )
    patch_parser.add_argument("--scan", dest="scan_id", help="Tarama kimliği (veya 'latest')")
    patch_parser.add_argument("--project-audit", dest="project_audit", help="Proje denetimi kimliği (veya 'latest')")
    patch_parser.add_argument("--stack", dest="target_stack", default="auto", help="Hedef teknoloji yığını (auto, nginx, fastapi, express, dockerfile, kubernetes)")
    patch_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "diff", "markdown"), default="json")
    patch_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    exec_parser = subparsers.add_parser(
        "executive-report",
        parents=[common],
        help="CISO / Yönetim Kurulu sızma testi, saldırı zinciri ve 9 çerçeveli uyumluluk raporu üret",
    )
    exec_parser.add_argument("--engagement", help="Manuel denetim kimliği (veya 'latest')")
    exec_parser.add_argument("--project-audit", dest="project_audit", help="Proje denetimi kimliği (veya 'latest')")
    exec_parser.add_argument("--scan", dest="scan_id", help="Tarama kimliği (veya 'latest')")
    exec_parser.add_argument("--no-patches", action="store_true", help="Otomatik iyileştirme yamalarını dahil etme")
    exec_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "markdown"), default="json")
    exec_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    busl_parser = subparsers.add_parser(
        "business-logic-audit",
        parents=[common],
        help="İş mantığı, yarış durumu (TOCTOU) ve finansal bütünlük denetimi çalıştır",
    )
    busl_parser.add_argument("--project-path", dest="project_path", help="Yerel proje dizini")
    busl_parser.add_argument("--file", dest="file_path", help="Tekil kaynak kodu dosyası")
    busl_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "markdown"), default="json")
    busl_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    db_parser = subparsers.add_parser(
        "db-schema-audit",
        parents=[common],
        help="SQL / ORM şeması, PostgreSQL RLS ve PII şifreleme güvenlik denetimi çalıştır",
    )
    db_parser.add_argument("--project-path", dest="project_path", help="Yerel proje dizini")
    db_parser.add_argument("--file", dest="file_path", help="Tekil SQL / Prisma / migration dosyası")
    db_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "markdown"), default="json")
    db_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    cbom_parser = subparsers.add_parser(
        "crypto-cbom-audit",
        parents=[common],
        help="CycloneDX CBOM kriptografik envanter ve Post-Quantum (PQC / NIST) hazırlık denetimi çalıştır",
    )
    cbom_parser.add_argument("--project-path", dest="project_path", help="Yerel proje dizini")
    cbom_parser.add_argument("--file", dest="file_path", help="Tekil kaynak veya yapılandırma dosyası")
    cbom_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "markdown"), default="json")
    cbom_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    w3_parser = subparsers.add_parser(
        "web3-iot-audit",
        parents=[common],
        help="Web3 akıllı kontrat (Solidity) ve IoT / gömülü sistem firmware güvenlik denetimi çalıştır",
    )
    w3_parser.add_argument("--project-path", dest="project_path", help="Yerel proje dizini")
    w3_parser.add_argument("--file", dest="file_path", help="Tekil akıllı kontrat (.sol) veya firmware (.c/.h/.sh) dosyası")
    w3_parser.add_argument("--type", dest="target_type", choices=("auto", "smart-contract", "firmware"), default="auto")
    w3_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "markdown"), default="json")
    w3_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    tmodel_parser = subparsers.add_parser(
        "threat-model",
        parents=[common],
        help="STRIDE + LINDDUN tehdit modeli ve Mermaid Veri Akış Diyagramı (DFD) üret",
    )
    tmodel_parser.add_argument("--project-path", dest="project_path", help="Yerel proje dizini")
    tmodel_parser.add_argument("--scan", dest="scan_id", help="Tarama kimliği")
    tmodel_parser.add_argument("--project-audit", dest="project_audit", help="Proje denetimi kimliği")
    tmodel_parser.add_argument("--engagement", help="Manuel denetim kimliği")
    tmodel_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "mermaid", "markdown"), default="json")
    tmodel_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    slsa_parser = subparsers.add_parser(
        "supply-chain-slsa",
        parents=[common],
        help="SLSA v1.0 derleme bütünlüğü, typosquatting ve açık kaynak lisans uyumluluğu denetimi çalıştır",
    )
    slsa_parser.add_argument("--project-path", dest="project_path", help="Yerel proje dizini")
    slsa_parser.add_argument("--workflow-file", "--file", dest="workflow_file", help="CI/CD iş akışı dosyası (.yml)")
    slsa_parser.add_argument("--license-policy", dest="license_policy", choices=("commercial", "saas", "internal", "open_source"), default="commercial")
    slsa_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "markdown"), default="json")
    slsa_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    bteam_parser = subparsers.add_parser(
        "blue-team-rules",
        parents=[common],
        help="Bulgulardan ModSecurity WAF, Sigma SIEM, Suricata IDS ve Nginx savunma kuralları sentezle",
    )
    bteam_parser.add_argument("--scan", dest="scan_id", help="Tarama kimliği (veya 'latest')")
    bteam_parser.add_argument("--project-audit", dest="project_audit", help="Proje denetimi kimliği (veya 'latest')")
    bteam_parser.add_argument("--domain", dest="target_domain", default="app.example.com", help="Hedef alan adı")
    bteam_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "modsecurity", "sigma", "nginx", "markdown"), default="json")
    bteam_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    def _add_project_input_parser(command: str, help_text: str) -> argparse.ArgumentParser:
        sub = subparsers.add_parser(command, parents=[common], help=help_text)
        sub.add_argument("--project", "--project-path", dest="project_path", help="Yerel proje dizini")
        sub.add_argument("--input", "--file", dest="input_path", help="Tekil girdi dosyası")
        sub.add_argument("--filename", dest="filename", help="Raporda kullanılacak dosya adı (varsayılan: girdi dosyasının adı)")
        sub.add_argument("--format", "-f", dest="output_format", choices=("json", "markdown"), default="json")
        sub.add_argument("--output", "--out", "-o", dest="output", type=Path)
        return sub

    _add_project_input_parser(
        "secret-intel",
        "Gizli anahtar / kimlik bilgisi istihbaratı (entropi, sağlayıcı kalıpları) denetimi çalıştır",
    )
    _add_project_input_parser(
        "privacy-dataflow",
        "KVKK / GDPR kişisel veri akışı (PII kaynak→hedef) gizlilik denetimi çalıştır",
    )
    host_parser = _add_project_input_parser(
        "host-cis",
        "CIS ana makine sertleştirme (sshd, sysctl, sudoers vb.) yapılandırma denetimi çalıştır",
    )
    host_parser.add_argument("--config-type", dest="config_type", default=None, help="Yapılandırma türü (varsayılan: auto)")
    _add_project_input_parser(
        "dos-resilience",
        "DoS dayanıklılığı ve ReDoS (felaket geri izleme) düzenli ifade denetimi çalıştır",
    )
    logging_parser = _add_project_input_parser(
        "audit-logging",
        "Denetim günlüğü bütünlüğü (OWASP A09, günlük enjeksiyonu, hash zinciri) denetimi çalıştır",
    )
    logging_parser.add_argument("--verify-chain", dest="verify_chain", help="Hash zincirli günlük JSON dosyasını doğrula")
    _add_project_input_parser(
        "extension-pwa",
        "Tarayıcı eklentisi (Manifest V3) ve PWA / Service Worker güvenlik denetimi çalıştır",
    )
    _add_project_input_parser(
        "zero-trust-mesh",
        "Sıfır güven: Kubernetes NetworkPolicy, Istio / Linkerd / Envoy mesh yapılandırma denetimi çalıştır",
    )
    cvss_parser = subparsers.add_parser(
        "cvss-ssvc",
        parents=[common],
        help="Bulguları CVSS 3.1 (+ CVSS 4.0 vektör ve puanı) ve CISA SSVC ile önceliklendir, SLA tarihleri üret",
    )
    cvss_parser.add_argument("--input", "--file", dest="input_path", help="Bulgu listesi JSON dosyası (liste veya 'findings' anahtarlı nesne)")
    cvss_parser.add_argument("--vector", dest="vector", help="Tek bir CVSS:3.1 veya CVSS:4.0 vektörünün puanını hesapla")
    cvss_parser.add_argument("--exposure", dest="exposure", choices=("internet", "internal", "local"), default="internet")
    cvss_parser.add_argument("--mission", dest="mission_prevalence", choices=("minimal", "support", "essential"), default="support")
    cvss_parser.add_argument("--exploitation", dest="exploitation", choices=("none", "poc", "active"), default="none")
    cvss_parser.add_argument("--discovered-at", dest="discovered_at", default=None, help="Varsayılan keşif tarihi (YYYY-MM-DD)")
    cvss_parser.add_argument("--now", dest="now", default=None, help="Değerlendirme tarihi (YYYY-MM-DD; varsayılan: bugün UTC)")
    cvss_parser.add_argument("--format", "-f", dest="output_format", choices=("json", "markdown"), default="json")
    cvss_parser.add_argument("--output", "--out", "-o", dest="output", type=Path)

    scan_parser = subparsers.add_parser("auto-scan", parents=[common], help="Projeyi analiz et ve veritabanına kaydet")
    scan_parser.add_argument("path", help="Proje yolu")
    scan_parser.add_argument("--limit", "-n", type=int, default=500, help="En fazla analiz edilecek dosya")
    scan_parser.add_argument("--include", action="append", default=[], metavar="GRUP",
                             choices=["tests", "vendor", "packages", "build", "generated", "non-utf8", "all"],
                             help="Varsayılan atlananları dahil et (tekrarlanabilir): tests, vendor, packages, build, generated, non-utf8, all")
    scan_parser.add_argument("--max-file-mb", type=int, default=None, help="Tek dosya sınırı (MB, en çok 20)")
    scan_parser.add_argument("--max-total-mb", type=int, default=None, help="Toplam boyut bütçesi (MB, en çok 1000)")
    scan_parser.add_argument("--changed-since", metavar="REF", default=None,
                             help="Yalnız değişenler: git başvurusu (HEAD, HEAD~1, origin/main) ya da prj_… analiz kimliğine göre")
    scan_parser.add_argument("--sarif", type=Path, default=None, help="SARIF 2.1.0 çıktı dosyası")
    scan_parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default=None,
                             help="Bu önem ve üstünde (yalnız değişenler modunda YENİ) bulgu varsa çıkış kodu 1")
    scan_parser.add_argument("--no-store", action="store_true", help="Sonucu veritabanına kaydetme (CI)")

    sbom_parser = subparsers.add_parser(
        "sbom", parents=[common],
        help="SBOM: 'sbom export <proje> -o dosya [--format cyclonedx|spdx]' ya da 'sbom scan <sbom-dosyası>' "
             "(eski kullanım 'sbom <proje> -o dosya' da geçerli)")
    sbom_parser.add_argument("action_or_path", help="export | scan | (eski) proje yolu")
    sbom_parser.add_argument("path", nargs="?", help="export: proje yolu · scan: CycloneDX/SPDX dosyası")
    sbom_parser.add_argument("--out", "-o", type=Path, help="export: SBOM çıktı yolu")
    sbom_parser.add_argument("--format", choices=("cyclonedx", "spdx"), default="cyclonedx", help="export biçimi")
    sbom_parser.add_argument("--view", choices=("table", "json"), default="table", help="scan çıktısı")
    sbom_parser.add_argument("--save", action="store_true", help="scan: sonucu analiz olarak kaydet (bulgu takibi)")
    sbom_parser.add_argument("--vex", choices=("openvex", "cyclonedx"), help="scan: VEX belgesi üret")
    sbom_parser.add_argument("--vex-out", type=Path, help="scan: VEX çıktı yolu")
    sbom_parser.add_argument("--osv-root", type=Path, help="Çevrimdışı OSV veri dizini")
    sbom_parser.add_argument("--fail-on", choices=("low", "medium", "high", "critical"), help="scan: çıkış kodu 1 eşiği")

    dependency_import = subparsers.add_parser("import-dependencies", parents=[common], help="Trivy veya OSV JSON raporunu içe aktar")
    dependency_import.add_argument("report_path", help="Yerel JSON raporu")
    dependency_import.add_argument("project_path", help="Raporun ait olduğu proje yolu")
    dependency_import.add_argument("--source", choices=("auto", "trivy", "osv"), default="auto")

    image_parser = subparsers.add_parser("image", parents=[common],
                                         help="Konteyner imajı (docker save / OCI) ya da rootfs için işletim sistemi paket taraması")
    image_parser.add_argument("image_path", help="docker save tar'ı, OCI düzeni (dizin/tar) ya da açılmış rootfs dizini")
    image_parser.add_argument("--view", choices=("table", "json"), default="table")
    image_parser.add_argument("--sbom", type=Path, help="CycloneDX SBOM çıktı yolu")
    image_parser.add_argument("--save", action="store_true", help="Sonucu proje analizi olarak kaydet (bulgu takibi, portföy)")
    image_parser.add_argument("--ignore-unfixed", action="store_true", help="Dağıtımın düzeltme yayımlamadığı açıkları gösterme")
    image_parser.add_argument("--osv-root", type=Path, help="Çevrimdışı OSV veri dizini (varsayılan ~/.local/state/sniper/osv-db)")
    image_parser.add_argument(
        "--dockerfile",
        dest="dockerfile_path",
        help="Son aşamadaki paketleri imaj envanteriyle eşlemek için yerel Dockerfile yolu",
    )
    image_parser.add_argument("--fail-on", choices=("low", "medium", "high", "critical"), help="Bu önemde bulgu varsa çıkış kodu 1")

    vex_parser = subparsers.add_parser("vex", parents=[common], help="Kayıtlı bağımlılık bulgularından VEX (OpenVEX / CycloneDX) üret")
    vex_parser.add_argument("project_path", help="Proje yolu (bulguların içe aktarıldığı yol)")
    vex_parser.add_argument("--out", "-o", type=Path, required=True, help="VEX JSON çıktı yolu")
    vex_parser.add_argument("--format", choices=("openvex", "cyclonedx"), default="openvex")
    vex_parser.add_argument("--dev-not-affected", action="store_true",
                            help="Kilit dosyasında yalnız geliştirme bağımlılığı olan paketleri 'not_affected' (component_not_present) say")

    dependency_list = subparsers.add_parser("list-dependencies", parents=[common], help="Kalıcı bağımlılık bulgularını listele")
    dependency_list.add_argument("--view", choices=("table", "json"), default="table")

    dependency_export = subparsers.add_parser("export-dependencies", parents=[common], help="Bağımlılık güvenliği raporunu dışa aktar")
    dependency_export.add_argument("--out", "-o", type=Path, required=True)

    history_parser = subparsers.add_parser("nuclei-history", parents=[common], help="Son Nuclei HTTP işlerinin maskelenmiş özetlerini listele")
    history_parser.add_argument("--data-dir", type=Path, help="Açıkça seçilen, yalnız sahibinin erişebildiği veri dizini")

    ci_parser = subparsers.add_parser(
        "ci", parents=[common],
        help="CI/CD güvenlik kapısı: analiz + çevrimdışı SCA + politika; SARIF/GitLab raporları (çıkış: 0 geçti, "
             "1 politika ihlali, 2 yapılandırma hatası, 3 analiz hatası)")
    ci_parser.add_argument("project_path", help="Proje dizini (CI çalışma dizini)")
    ci_parser.add_argument("--policy", type=Path, default=None, help="Politika dosyası (varsayılan: <proje>/.sniper-policy.json|yml)")
    ci_parser.add_argument("--sarif", type=Path, default=None, help="SARIF 2.1.0 çıktı dosyası (GitHub code scanning)")
    ci_parser.add_argument("--gitlab-dir", type=Path, default=None,
                           help="gl-sast-report.json ve gl-dependency-scanning-report.json yazılacak dizin")
    ci_parser.add_argument("--summary", type=Path, default=None,
                           help="Markdown özeti (varsayılan: $GITHUB_STEP_SUMMARY varsa ona eklenir)")
    base_group = ci_parser.add_mutually_exclusive_group()
    base_group.add_argument("--baseline-sarif", type=Path, default=None, help="Önceki SARIF (yalnız yeni bulgular için)")
    base_group.add_argument("--baseline-audit", default=None, help="Kayıtlı analiz kimliği (prj_…)")
    base_group.add_argument("--baseline-ref", default=None, help="Git tabanı (ör. origin/main): değişen dosyalar yeni sayılır")
    ci_parser.add_argument("--no-sca", action="store_true", help="Çevrimdışı bağımlılık açığı taramasını atla")
    ci_parser.add_argument("--store", action="store_true", help="Analizi veritabanına kaydet (bulgu takibi için)")
    ci_parser.add_argument("--json", type=Path, default=None, help="Ayrıntılı karar raporu (JSON)")
    ci_parser.add_argument("--limit", type=int, default=10000, help="En çok dosya sayısı")

    bulk_parser = subparsers.add_parser(
        "bulk", parents=[common],
        help="Toplu depo taraması: kök dizindeki depoları keşfet ve her birini CI kapısından geçir (depo başına SARIF, "
             "tek Markdown özet; çıkış kodu en kötü depo)")
    bulk_parser.add_argument("root", help="Kök dizin (altındaki git depoları / proje kökleri)")
    bulk_parser.add_argument("--dry-run", action="store_true", help="Yalnız keşfet ve listele; tarama yapma")
    bulk_parser.add_argument("--parallel", type=int, default=1, choices=range(1, 5), metavar="N",
                             help="Aynı anda taranacak depo sayısı (1–4)")
    bulk_parser.add_argument("--sarif-dir", type=Path, default=None, help="Depo başına SARIF dosyalarının yazılacağı dizin")
    bulk_parser.add_argument("--summary", type=Path, default=None,
                             help="Tek Markdown özet (varsayılan: $GITHUB_STEP_SUMMARY varsa ona eklenir)")
    bulk_parser.add_argument("--json", type=Path, default=None, help="Keşif (kuru çalıştırma) ya da sonuç raporu (JSON)")
    bulk_parser.add_argument("--state", type=Path, default=None,
                             help="Durum dosyası: depo → son taranan commit; commit değişmeyen depolar atlanır")
    bulk_parser.add_argument("--max-depth", type=int, default=4, help="Keşif derinliği (0–8)")
    bulk_parser.add_argument("--max-repos", type=int, default=100, help="En çok depo (1–300)")
    bulk_parser.add_argument("--include-large", action="store_true", help="Boyut sınırını aşan depoları da tara")
    bulk_parser.add_argument("--timeout", type=int, default=1800, help="Depo başına süre sınırı (saniye)")
    bulk_parser.add_argument("--policy", type=Path, default=None, help="Tüm depolar için politika dosyası")
    bulk_parser.add_argument("--no-sca", action="store_true", help="Çevrimdışı bağımlılık açığı taramasını atla")
    bulk_parser.add_argument("--store", action="store_true", help="Analizleri veritabanına kaydet (bulgu takibi/portföy)")

    offline_parser = subparsers.add_parser("osv-offline", parents=[common],
                                           help="Kilit dosyalarını yerel OSV veritabanıyla eşle (tüm ekosistemler, ağ yok)")
    offline_parser.add_argument("project_path", help="Proje yolu")
    offline_parser.add_argument("--no-save", action="store_true", help="Bulguları veritabanına kaydetme")

    osv_parser = subparsers.add_parser("osv-query", parents=[common], help="OSV sorgusunu yalnız Tor üzerinden çalıştır")
    osv_parser.add_argument("project_path", help="Proje yolu")
    osv_parser.add_argument("--out", "-o", type=Path, required=True, help="OSV JSON çıktı yolu")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    db_path = args.db
    if args.command == "list":
        list_projects(args.limit, view=args.view, db_path=db_path)
    elif args.command == "export":
        export_project(args.audit_id, args.format, target_dir=args.out, db_path=db_path)
    elif args.command == "project-diff":
        compare_project_audits_cli(
            args.previous,
            args.current,
            view=args.view,
            output=args.out,
            db_path=db_path,
        )
    elif args.command == "quality-gate":
        qg_res = run_quality_gate_cli(
            target_ref=args.target,
            project_audit_id=args.project_audit,
            engagement_id=args.engagement,
            min_score=args.min_score,
            max_critical=args.max_critical,
            max_high=args.max_high,
            max_medium=args.max_medium,
            max_overdue=args.max_overdue,
            min_wstg_coverage=args.min_wstg_coverage,
            fail_on_new_findings=args.fail_on_new_findings,
            view=args.view,
            output=args.out,
            db_path=db_path,
        )
        if int(qg_res.get("exit_code", 0)) != 0:
            raise SystemExit(int(qg_res["exit_code"]))
    elif args.command == "compliance":
        run_compliance_cli(
            engagement_id=args.engagement,
            project_audit_id=args.project_audit,
            view=args.view,
            output=args.out,
            db_path=db_path,
        )
    elif args.command == "mobile-audit":
        if not (args.project_path or args.package_path or args.manifest_file):
            parser.error(
                "mobile-audit için --project-path, --package-path veya --manifest-file seçeneklerinden en az biri gerekli"
            )
        run_mobile_audit_cli(
            project_path=args.project_path,
            package_path=args.package_path,
            manifest_file=args.manifest_file,
            app_profile=args.app_profile,
            output_format=args.output_format,
            output=args.output,
        )
    elif args.command == "ai-llm-audit":
        if not (args.project_path or args.file_path):
            parser.error("ai-llm-audit için --project-path veya --file seçeneklerinden biri gerekli")
        run_ai_llm_audit_cli(
            project_path=args.project_path,
            file_path=args.file_path,
            output_format=args.output_format,
            output=args.output,
        )
    elif args.command == "cloud-iam-audit":
        if not (args.project_path or args.file_path):
            parser.error("cloud-iam-audit için --project-path veya --file seçeneklerinden biri gerekli")
        run_cloud_iam_audit_cli(
            project_path=args.project_path,
            file_path=args.file_path,
            output_format=args.output_format,
            output=args.output,
        )
    elif args.command == "desktop-audit":
        if not (args.project_path or args.protocol_file):
            parser.error("desktop-audit için --project-path veya --protocol-file seçeneklerinden biri gerekli")
        run_desktop_audit_cli(
            project_path=args.project_path,
            protocol_file=args.protocol_file,
            protocol_type=args.protocol_type,
            output_format=args.output_format,
            output=args.output,
        )
    elif args.command == "auth-protocol-audit":
        if not (args.artifact or args.file_path):
            parser.error("auth-protocol-audit için --artifact veya --file seçeneklerinden biri gerekli")
        run_auth_protocol_audit_cli(
            artifact=args.artifact,
            file_path=args.file_path,
            artifact_type=args.artifact_type,
            output_format=args.output_format,
            output=args.output,
        )
    elif args.command == "attack-paths":
        run_attack_paths_cli(
            scan_id=args.scan_id,
            project_audit_id=args.project_audit,
            engagement_id=args.engagement,
            output_format=args.output_format,
            output=args.output,
            db_path=db_path,
        )
    elif args.command == "auto-patch":
        run_auto_patch_cli(
            scan_id=args.scan_id,
            project_audit_id=args.project_audit,
            target_stack=args.target_stack,
            output_format=args.output_format,
            output=args.output,
            db_path=db_path,
        )
    elif args.command == "executive-report":
        run_executive_report_cli(
            engagement_id=args.engagement,
            project_audit_id=args.project_audit,
            scan_id=args.scan_id,
            include_patches=not args.no_patches,
            output_format=args.output_format,
            output=args.output,
            db_path=db_path,
        )
    elif args.command == "business-logic-audit":
        if not (args.project_path or args.file_path):
            parser.error("business-logic-audit için --project-path veya --file seçeneklerinden biri gerekli")
        run_business_logic_audit_cli(
            project_path=args.project_path,
            file_path=args.file_path,
            output_format=args.output_format,
            output=args.output,
        )
    elif args.command == "db-schema-audit":
        if not (args.project_path or args.file_path):
            parser.error("db-schema-audit için --project-path veya --file seçeneklerinden biri gerekli")
        run_db_schema_audit_cli(
            project_path=args.project_path,
            file_path=args.file_path,
            output_format=args.output_format,
            output=args.output,
        )
    elif args.command == "crypto-cbom-audit":
        if not (args.project_path or args.file_path):
            parser.error("crypto-cbom-audit için --project-path veya --file seçeneklerinden biri gerekli")
        run_crypto_cbom_audit_cli(
            project_path=args.project_path,
            file_path=args.file_path,
            output_format=args.output_format,
            output=args.output,
        )
    elif args.command == "web3-iot-audit":
        if not (args.project_path or args.file_path):
            parser.error("web3-iot-audit için --project-path veya --file seçeneklerinden biri gerekli")
        run_web3_iot_audit_cli(
            project_path=args.project_path,
            file_path=args.file_path,
            target_type=args.target_type,
            output_format=args.output_format,
            output=args.output,
        )
    elif args.command == "threat-model":
        run_threat_model_cli(
            project_path=args.project_path,
            scan_id=args.scan_id,
            project_audit_id=args.project_audit,
            engagement_id=args.engagement,
            output_format=args.output_format,
            output=args.output,
            db_path=db_path,
        )
    elif args.command == "supply-chain-slsa":
        if not (args.project_path or args.workflow_file):
            parser.error("supply-chain-slsa için --project-path veya --workflow-file seçeneklerinden biri gerekli")
        run_supply_chain_slsa_cli(
            project_path=args.project_path,
            workflow_file=args.workflow_file,
            license_policy=args.license_policy,
            output_format=args.output_format,
            output=args.output,
        )
    elif args.command == "blue-team-rules":
        run_blue_team_rules_cli(
            scan_id=args.scan_id,
            project_audit_id=args.project_audit,
            target_domain=args.target_domain,
            output_format=args.output_format,
            output=args.output,
            db_path=db_path,
        )
    elif args.command in {
        "secret-intel",
        "privacy-dataflow",
        "host-cis",
        "dos-resilience",
        "audit-logging",
        "extension-pwa",
        "zero-trust-mesh",
    }:
        sources = [args.project_path, args.input_path]
        labels = "--project veya --input"
        if args.command == "audit-logging":
            sources.append(args.verify_chain)
            labels = "--project, --input veya --verify-chain"
        if sum(1 for s in sources if s) != 1:
            parser.error(f"{args.command} için {labels} seçeneklerinden yalnızca biri gerekli")
        common_kwargs = {
            "project_path": args.project_path,
            "input_path": args.input_path,
            "filename": args.filename,
            "output_format": args.output_format,
            "output": args.output,
        }
        if args.command == "secret-intel":
            run_secret_intel_cli(**common_kwargs)
        elif args.command == "privacy-dataflow":
            run_privacy_dataflow_cli(**common_kwargs)
        elif args.command == "host-cis":
            run_host_cis_cli(config_type=args.config_type, **common_kwargs)
        elif args.command == "dos-resilience":
            run_dos_resilience_cli(**common_kwargs)
        elif args.command == "audit-logging":
            run_audit_logging_cli(verify_chain=args.verify_chain, **common_kwargs)
        elif args.command == "extension-pwa":
            run_extension_pwa_cli(**common_kwargs)
        else:
            run_zero_trust_mesh_cli(**common_kwargs)
    elif args.command == "cvss-ssvc":
        if bool(args.input_path) == bool(args.vector):
            parser.error("cvss-ssvc için --input veya --vector seçeneklerinden yalnızca biri gerekli")
        run_cvss_ssvc_cli(
            input_path=args.input_path,
            vector=args.vector,
            exposure=args.exposure,
            mission_prevalence=args.mission_prevalence,
            exploitation=args.exploitation,
            discovered_at=args.discovered_at,
            now=args.now,
            output_format=args.output_format,
            output=args.output,
        )
    elif args.command == "auto-scan":
        saved = auto_scan_project(
            args.path, limit=args.limit, db_path=db_path, scope=_cli_scope(args),
            sarif=args.sarif, fail_on=args.fail_on, store=not args.no_store,
        )
        if saved.get("gate_failed"):
            raise SystemExit(1)
    elif args.command == "ci":
        raise SystemExit(run_ci_gate(args, db_path=db_path))
    elif args.command == "bulk":
        raise SystemExit(run_bulk(args, db_path=db_path))
    elif args.command == "sbom":
        action = args.action_or_path
        if action == "scan":
            if not args.path:
                parser.error("sbom scan için SBOM dosya yolu gerekli")
            raise SystemExit(scan_sbom_file(args.path, view=args.view, save=args.save, vex=args.vex,
                                            vex_out=args.vex_out, osv_root=args.osv_root, fail_on=args.fail_on,
                                            db_path=db_path))
        project = args.path if action == "export" else action
        if not project or args.out is None:
            parser.error("sbom export için proje yolu ve --out gerekli")
        generate_dependency_sbom(project, args.out, db_path=db_path, fmt=args.format)
    elif args.command == "image":
        raise SystemExit(scan_container_image(args.image_path, view=args.view, sbom=args.sbom, save=args.save,
                                              ignore_unfixed=args.ignore_unfixed, osv_root=args.osv_root,
                                              fail_on=args.fail_on, dockerfile_path=args.dockerfile_path,
                                              db_path=db_path))
    elif args.command == "vex":
        export_dependency_vex(args.project_path, args.out, args.format, db_path=db_path, dev_not_affected=args.dev_not_affected)
    elif args.command == "import-dependencies":
        import_dependency_report(args.report_path, args.project_path, args.source, db_path=db_path)
    elif args.command == "list-dependencies":
        list_dependency_findings(args.view, db_path=db_path)
    elif args.command == "export-dependencies":
        export_dependency_report(args.out, db_path=db_path)
    elif args.command == "nuclei-history":
        if db_path is not None:
            parser.error("nuclei-history için --db kullanılamaz")
        try:
            print(json.dumps(list_nuclei_history(args.data_dir), ensure_ascii=False))
        except (AggregateHistoryError, OSError, ValueError):
            # Journal contents, target and private filesystem paths stay off stderr.
            print("Nuclei geçmişi güvenle okunamadı.", file=sys.stderr)
            raise SystemExit(1) from None
    elif args.command == "osv-offline":
        scan_osv_offline(args.project_path, db_path=db_path, save=not args.no_save)
    elif args.command == "osv-query":
        query_osv_online(args.project_path, args.out)
    elif args.command == "users":
        manage_users(args, db_path=db_path)
    elif args.command == "triage":
        raise SystemExit(triage_cli(args, db_path=db_path))
    elif args.command == "scan-diff":
        previous, current = args.previous, args.current
        if args.latest:
            previous, current = resolve_latest_pair(args.latest, db_path=db_path)
        elif not previous or not current:
            parser.error("scan-diff için iki tarama kimliği ya da --latest HEDEF gerekli")
        compare_scans(
            previous,
            current,
            output=args.out,
            view=args.view,
            db_path=db_path,
            include_details=not args.summary_only,
            severity_filter=args.severity,
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
