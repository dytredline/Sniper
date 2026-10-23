"""Sniper editör tanılama sunucusu (Language Server Protocol, stdio; saf Python, yalnız standart kitaplık).

Editör bir dosyayı açınca ya da kaydedince o dosya, proje analiziyle aynı motorla (``project_analyzer``,
``scan_scope.only_paths`` ile yalnız bu dosya raporlanır; dosyalar arası taint bağlamı tüm projeden gelir)
incelenir ve bulgular ``textDocument/publishDiagnostics`` ile gönderilir. ``textDocument/codeAction``
mevcut ``taint_autofix`` dönüşümlerini hızlı düzeltme olarak önerir (düzenlemeyi editör uygular).

Güvenlik ve sınırlar:

* Ağ yok. Sunucu hiçbir proje dosyasına yazmaz; yalnız kendi önbellek dizinine (0700) taint önbelleği
  yazılır (``$XDG_CACHE_HOME/sniper-lsp`` ya da ``~/.cache/sniper-lsp``).
* Her analiz ayrı bir alt süreçte (kendi süreç grubunda) dosya başına süre sınırıyla çalışır; süre
  aşılırsa grup sonlandırılır, sunucu yanıt vermeye devam eder.
* Kalıcı tarama kapsamı (``$SNIPER_DATA_DIR/scan-scope.json``) yalnız okunur: atlanan dizinler
  (testler, vendor …) arayüzdeki gibi atlanır.
* Analiz yalnız kayıtta (didOpen/didSave) yapılır; kaydedilmemiş değişiklikler (didChange) yalnız
  hızlı düzeltmenin üzerinde çalışacağı metni günceller.
"""

from __future__ import annotations

import argparse
import dataclasses
import difflib
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any, BinaryIO, Callable
from urllib.parse import unquote, urlparse

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

SERVER_NAME = "sniper-lsp"
SERVER_VERSION = "1"
MAX_HEADER_BYTES = 8_192
MAX_MESSAGE_BYTES = 64 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 30.0
MIN_TIMEOUT_SECONDS = 2.0
MAX_TIMEOUT_SECONDS = 300.0
MAX_CACHE_ENTRIES = 64
MAX_MESSAGE_CHARS = 1_500

# LSP DiagnosticSeverity: 1 hata, 2 uyarı, 3 bilgi, 4 ipucu
SEVERITY_TO_LSP = {"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# JSON-RPC hata kodları
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
SERVER_NOT_INITIALIZED = -32002


class ProtocolError(ValueError):
    """Bozuk LSP çerçevesi (başlık/uzunluk)."""


# ---------------------------------------------------------------------------
# JSON-RPC çerçeveleme (Content-Length başlığı + UTF-8 JSON gövde)
# ---------------------------------------------------------------------------
def read_message(stream: BinaryIO) -> dict[str, Any] | None:
    """Bir LSP iletisi okur; akış bittiyse ``None``. Başlık/uzunluk bozuksa ProtocolError,
    gövde JSON değilse ValueError (çağıran -32700 döner)."""
    length: int | None = None
    header_bytes = 0
    while True:
        line = stream.readline(MAX_HEADER_BYTES + 1)
        if not line:
            if header_bytes == 0:
                return None
            raise ProtocolError("İleti başlığı yarıda kesildi.")
        header_bytes += len(line)
        if header_bytes > MAX_HEADER_BYTES:
            raise ProtocolError("İleti başlığı çok uzun.")
        if line in (b"\r\n", b"\n"):
            if length is None:
                if header_bytes == len(line):
                    continue  # iletiler arası boş satır
                raise ProtocolError("Content-Length başlığı eksik.")
            break
        name, _, value = line.decode("ascii", "replace").partition(":")
        if name.strip().lower() == "content-length":
            try:
                length = int(value.strip())
            except ValueError as exc:
                raise ProtocolError("Content-Length geçersiz.") from exc
            if not 0 <= length <= MAX_MESSAGE_BYTES:
                raise ProtocolError("İleti boyut sınırını aşıyor.")
    body = stream.read(length)
    if len(body) != length:
        raise ProtocolError("İleti gövdesi yarıda kesildi.")
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON-RPC iletisi bir nesne olmalıdır.")
    return payload


def encode_message(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------
def uri_to_path(uri: str) -> Path | None:
    parsed = urlparse(uri or "")
    if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
        return None
    path = unquote(parsed.path)
    if not path or "\x00" in path:
        return None
    return Path(path)


def utf16_len(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def _strip_eol(line: str) -> str:
    return line.rstrip("\r\n")


def end_position(lines: list[str]) -> dict[str, int]:
    """Belgenin sonu (LSP konumu). Son satır satır sonuyla bitiyorsa bir sonraki (boş) satırın başı."""
    if not lines:
        return {"line": 0, "character": 0}
    if lines[-1].endswith(("\n", "\r")):
        return {"line": len(lines), "character": 0}
    return {"line": len(lines) - 1, "character": utf16_len(lines[-1])}


def text_edit_for(old: str, new: str) -> dict[str, Any] | None:
    """Eski ve yeni tam metin arasındaki değişen satır aralığını tek TextEdit olarak verir."""
    old_lines = old.splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)
    if old_lines == new_lines:
        return None
    opcodes = [op for op in difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False).get_opcodes() if op[0] != "equal"]
    first, last = opcodes[0], opcodes[-1]
    a_start, a_end = first[1], last[2]
    b_start, b_end = first[3], last[4]
    start = {"line": a_start, "character": 0}
    end = {"line": a_end, "character": 0} if a_end < len(old_lines) else end_position(old_lines)
    return {"range": {"start": start, "end": end}, "newText": "".join(new_lines[b_start:b_end])}


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "sniper-lsp"


def prepare_cache_dir(path: Path | None) -> Path | None:
    """Önbellek dizinini 0700 kur ve sahibini denetle; güvensizse ``None`` (önbellek kapalı)."""
    if path is None:
        return None
    try:
        path = Path(path)
        if not path.is_absolute():
            return None
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        return None
    return path


def default_data_dir() -> Path | None:
    raw = os.environ.get("SNIPER_DATA_DIR")
    if raw:
        return Path(raw)
    candidate = Path.home() / ".local" / "share" / "sniper" / "data"
    return candidate if candidate.is_dir() else None


def load_scope(data_dir: Path | None):
    """Kalıcı tarama kapsamı (salt okunur); yoksa varsayılan."""
    import scan_scope

    if data_dir is None:
        return scan_scope.DEFAULT_SCOPE
    return scan_scope.load_default({"SNIPER_DATA_DIR": str(data_dir)})


def is_candidate(path: Path) -> bool:
    """Proje analizinin inceleyebileceği dosya türü mü (uzantı, bildirim ya da konteyner dosyası)?"""
    import project_analyzer

    name = path.name.casefold()
    return (path.suffix.casefold() in project_analyzer.SOURCE_EXTENSIONS
            or name in project_analyzer.MANIFEST_NAMES
            or project_analyzer._is_containerfile_name(name))


def _cwe_href(reference: str) -> str | None:
    import re

    match = re.fullmatch(r"CWE-(\d{1,5})", reference.strip())
    return f"https://cwe.mitre.org/data/definitions/{match.group(1)}.html" if match else None


def finding_to_diagnostic(finding: dict[str, Any], lines: list[str], root: Path) -> dict[str, Any]:
    import finding_tracking
    import taint_autofix

    line_no = 0
    try:
        line_no = max(0, int(finding.get("line") or 0) - 1)
    except (TypeError, ValueError):
        line_no = 0
    if line_no >= len(lines):
        line_no = max(0, len(lines) - 1)
    text = _strip_eol(lines[line_no]) if lines else ""
    indent = len(text) - len(text.lstrip())
    start_char = utf16_len(text[:indent])
    end_char = max(start_char, utf16_len(text))
    severity = str(finding.get("severity") or "info")
    reference = str(finding.get("reference") or "")
    message = str(finding.get("title") or "Sniper bulgusu")
    evidence = str(finding.get("evidence") or "").strip()
    recommendation = str(finding.get("recommendation") or "").strip()
    if evidence:
        message += f"\n{evidence}"
    if recommendation:
        message += f"\nÖneri: {recommendation}"
    if len(message) > MAX_MESSAGE_CHARS:
        message = message[: MAX_MESSAGE_CHARS - 1] + "…"
    flow = finding.get("taint_flow") if isinstance(finding.get("taint_flow"), dict) else None
    data = {
        "fingerprint": finding_tracking.fingerprint(finding),
        "severity": severity,
        "category": str(finding.get("category") or ""),
        "kind": taint_autofix.finding_kind(finding),
        "line": line_no + 1,
    }
    if flow:
        data["flow"] = flow
    iac = finding.get("iac")
    code = reference or (str(iac.get("id")) if isinstance(iac, dict) and iac.get("id") else "")
    diagnostic: dict[str, Any] = {
        "range": {"start": {"line": line_no, "character": start_char}, "end": {"line": line_no, "character": end_char}},
        "severity": SEVERITY_TO_LSP.get(severity, 3),
        "source": "sniper",
        "message": message,
        "data": data,
    }
    if code:
        diagnostic["code"] = code
        href = _cwe_href(code)
        if href:
            diagnostic["codeDescription"] = {"href": href}
    if flow and flow.get("source_line"):
        try:
            source_line = max(0, int(flow["source_line"]) - 1)
        except (TypeError, ValueError):
            source_line = -1
        if source_line >= 0:
            source_file = str(flow.get("source_file") or finding.get("file") or "")
            target = (root / source_file).resolve() if source_file else None
            if target is not None and (target == root or root in target.parents):
                diagnostic["relatedInformation"] = [{
                    "location": {"uri": target.as_uri(), "range": {"start": {"line": source_line, "character": 0},
                                                                   "end": {"line": source_line, "character": 0}}},
                    "message": f"Kaynak: {flow.get('source') or flow.get('source_label') or 'istek girdisi'}",
                }]
    return diagnostic


# ---------------------------------------------------------------------------
# Analiz alt süreci
# ---------------------------------------------------------------------------
def worker_main() -> int:
    """``--worker``: standart girdiden iş (JSON) okur, yalnız istenen dosyanın bulgularını JSON yazar."""
    job = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    real_stdout = sys.stdout
    sys.stdout = sys.stderr  # analiz sırasında yazılabilecek her şey protokol çıktısına karışmasın
    try:
        result = _run_analysis(job)
    except Exception as exc:  # ayrıntılı hata kullanıcıya log iletisi olarak döner
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:500]}
    finally:
        sys.stdout = real_stdout
    sys.stdout.buffer.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))
    sys.stdout.flush()
    return 0


def _run_analysis(job: dict[str, Any]) -> dict[str, Any]:
    import project_analyzer
    import scan_scope

    rel = str(job["rel"])
    scope = scan_scope.parse_scope(job.get("scope") or None)
    scope = dataclasses.replace(scope, only_paths=frozenset({rel}), changed_only=False, skipped_only=False, base_ref="")
    roots = tuple(Path(p) for p in job["allowed_roots"]) if job.get("allowed_roots") else None
    try:
        result = project_analyzer.analyze_project(str(job["root"]), allowed_roots=roots, scope=scope)
    except project_analyzer.ProjectRejected as exc:
        # Kapsam dışı (atlanan dizin, boyut sınırı) ya da analiz edilebilir kaynak yok.
        return {"ok": True, "findings": [], "skipped": str(exc)[:300]}
    findings = [f for f in result.get("findings", []) if str(f.get("file") or "").replace("\\", "/") == rel]
    return {"ok": True, "findings": findings, "partial": bool(result.get("partial"))}


@dataclasses.dataclass
class Document:
    uri: str
    path: Path
    root: Path
    rel: str
    text: str
    version: int | None = None


class SniperLanguageServer:
    """Tek istemcili LSP sunucusu. ``synchronous=True`` (testler) analizi istek iş parçacığında yapar."""

    def __init__(self, reader: BinaryIO, writer: BinaryIO, *, data_dir: Path | None = None,
                 cache_dir: Path | None = None, timeout: float = DEFAULT_TIMEOUT_SECONDS,
                 allowed_roots: tuple[Path, ...] | None = None, synchronous: bool = False,
                 worker_command: list[str] | None = None) -> None:
        self.reader = reader
        self.writer = writer
        self.data_dir = data_dir if data_dir is not None else default_data_dir()
        self.cache_dir = prepare_cache_dir(cache_dir if cache_dir is not None else default_cache_dir())
        self.timeout = timeout
        self.allowed_roots = allowed_roots
        self.synchronous = synchronous
        self.worker_command = worker_command or [sys.executable, "-I", str(APP_DIR / "lsp_server.py"), "--worker"]
        self.min_severity = "info"
        self.roots: list[Path] = []
        self.documents: dict[str, Document] = {}
        self.initialized = False
        self.shutdown_requested = False
        self.exit_code: int | None = None
        self._write_lock = threading.Lock()
        self._cond = threading.Condition()
        self._pending: dict[str, bool] = {}
        self._busy = False
        self._generation: dict[Path, int] = {}
        self._cache: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.stats = {"analyses": 0, "cache_hits": 0, "timeouts": 0}

    # -- çıktı -----------------------------------------------------------
    def send(self, payload: dict[str, Any]) -> None:
        data = encode_message(payload)
        with self._write_lock:
            self.writer.write(data)
            self.writer.flush()

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def log(self, message: str, kind: int = 3) -> None:
        self.notify("window/logMessage", {"type": kind, "message": f"[sniper] {message}"})

    def respond(self, msg_id: Any, result: Any = None, error: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": msg_id}
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result
        self.send(payload)

    # -- döngü -----------------------------------------------------------
    def serve(self) -> int:
        if not self.synchronous:
            self._thread = threading.Thread(target=self._worker_loop, name="sniper-lsp-analysis", daemon=True)
            self._thread.start()
        try:
            while self.exit_code is None:
                try:
                    message = read_message(self.reader)
                except ProtocolError as exc:
                    self.log(f"Protokol hatası: {exc}", 1)
                    self.exit_code = 1
                    break
                except (ValueError, UnicodeDecodeError):
                    self.respond(None, error={"code": PARSE_ERROR, "message": "JSON ayrıştırılamadı."})
                    continue
                if message is None:
                    self.exit_code = 0 if self.shutdown_requested else 1
                    break
                self.handle(message)
        finally:
            self._stop.set()
            with self._cond:
                self._cond.notify_all()
        return self.exit_code or 0

    def handle(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        msg_id = message.get("id")
        is_request = "id" in message
        if not isinstance(method, str):
            if is_request:
                self.respond(msg_id, error={"code": INVALID_REQUEST, "message": "Geçersiz istek."})
            return
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        if method == "exit":
            self.exit_code = 0 if self.shutdown_requested else 1
            return
        if not self.initialized and method != "initialize":
            if is_request:
                self.respond(msg_id, error={"code": SERVER_NOT_INITIALIZED, "message": "Sunucu henüz başlatılmadı."})
            return
        handler: Callable[[dict[str, Any]], Any] | None = {
            "initialize": self._initialize,
            "initialized": lambda p: None,
            "shutdown": self._shutdown,
            "textDocument/didOpen": self._did_open,
            "textDocument/didChange": self._did_change,
            "textDocument/didSave": self._did_save,
            "textDocument/didClose": self._did_close,
            "textDocument/codeAction": self._code_action,
            "workspace/didChangeWorkspaceFolders": self._workspace_folders,
        }.get(method)
        if handler is None:
            if is_request:
                self.respond(msg_id, error={"code": METHOD_NOT_FOUND, "message": f"Desteklenmeyen yöntem: {method}"})
            return  # bilinmeyen bildirimler ($/cancelRequest, $/setTrace …) yok sayılır
        try:
            result = handler(params)
        except (KeyError, TypeError, ValueError) as exc:
            if is_request:
                self.respond(msg_id, error={"code": INVALID_PARAMS, "message": f"Geçersiz parametre: {exc}"[:300]})
            return
        if is_request:
            self.respond(msg_id, result)

    # -- yaşam döngüsü ---------------------------------------------------
    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        roots: list[Path] = []
        for folder in params.get("workspaceFolders") or []:
            path = uri_to_path(str(folder.get("uri") or "")) if isinstance(folder, dict) else None
            if path is not None:
                roots.append(path)
        if not roots:
            path = uri_to_path(str(params.get("rootUri") or "")) if params.get("rootUri") else None
            if path is None and params.get("rootPath"):
                path = Path(str(params["rootPath"]))
            if path is not None:
                roots.append(path)
        self.roots = [self._resolve_root(p) for p in roots if self._resolve_root(p) is not None]
        options = params.get("initializationOptions") if isinstance(params.get("initializationOptions"), dict) else {}
        if "timeoutSeconds" in options:
            self.timeout = min(MAX_TIMEOUT_SECONDS, max(MIN_TIMEOUT_SECONDS, float(options["timeoutSeconds"])))
        if options.get("minSeverity") in SEVERITY_ORDER:
            self.min_severity = options["minSeverity"]
        if isinstance(options.get("dataDir"), str) and options["dataDir"]:
            self.data_dir = Path(os.path.expanduser(options["dataDir"]))
        self.initialized = True
        return {
            "capabilities": {
                "textDocumentSync": {"openClose": True, "change": 1, "save": {"includeText": False}},
                "codeActionProvider": {"codeActionKinds": ["quickfix"]},
                "workspace": {"workspaceFolders": {"supported": True, "changeNotifications": True}},
            },
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }

    @staticmethod
    def _resolve_root(path: Path) -> Path | None:
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        return resolved if resolved.is_dir() else None

    def _workspace_folders(self, params: dict[str, Any]) -> None:
        event = params.get("event") or {}
        for folder in event.get("removed") or []:
            path = uri_to_path(str(folder.get("uri") or ""))
            resolved = self._resolve_root(path) if path else None
            if resolved in self.roots:
                self.roots.remove(resolved)
        for folder in event.get("added") or []:
            path = uri_to_path(str(folder.get("uri") or ""))
            resolved = self._resolve_root(path) if path else None
            if resolved is not None and resolved not in self.roots:
                self.roots.append(resolved)

    def _shutdown(self, params: dict[str, Any]) -> None:
        self.shutdown_requested = True
        return None

    # -- belgeler ---------------------------------------------------------
    def _locate(self, uri: str) -> tuple[Path, Path, str] | None:
        path = uri_to_path(uri)
        if path is None:
            return None
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        best: Path | None = None
        for root in self.roots:
            if root in resolved.parents and (best is None or len(root.parts) > len(best.parts)):
                best = root
        if best is None or not resolved.is_file():
            return None
        return resolved, best, resolved.relative_to(best).as_posix()

    def _did_open(self, params: dict[str, Any]) -> None:
        item = params["textDocument"]
        uri = str(item["uri"])
        located = self._locate(uri)
        if located is None:
            return
        path, root, rel = located
        self.documents[uri] = Document(uri, path, root, rel, str(item.get("text") or ""), item.get("version"))
        self._schedule(uri)

    def _did_change(self, params: dict[str, Any]) -> None:
        uri = str(params["textDocument"]["uri"])
        doc = self.documents.get(uri)
        if doc is None:
            return
        changes = params.get("contentChanges") or []
        for change in changes:
            if isinstance(change, dict) and "range" not in change and isinstance(change.get("text"), str):
                doc.text = change["text"]  # tam eşitleme (change: 1)
        doc.version = params["textDocument"].get("version", doc.version)

    def _did_save(self, params: dict[str, Any]) -> None:
        uri = str(params["textDocument"]["uri"])
        doc = self.documents.get(uri)
        if doc is None:
            return
        self._generation[doc.root] = self._generation.get(doc.root, 0) + 1  # projedeki önbellekli sonuçlar eskidi
        if isinstance(params.get("text"), str):
            doc.text = params["text"]
        self._schedule(uri)

    def _did_close(self, params: dict[str, Any]) -> None:
        uri = str(params["textDocument"]["uri"])
        if self.documents.pop(uri, None) is not None:
            with self._cond:
                self._pending.pop(uri, None)
            self.notify("textDocument/publishDiagnostics", {"uri": uri, "diagnostics": []})

    # -- analiz kuyruğu ---------------------------------------------------
    def _schedule(self, uri: str) -> None:
        if self.synchronous:
            self._analyze_and_publish(uri)
            return
        with self._cond:
            self._pending.pop(uri, None)
            self._pending[uri] = True  # aynı belge için bekleyen istekler birleşir
            self._cond.notify_all()

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            with self._cond:
                while not self._pending and not self._stop.is_set():
                    self._cond.wait(0.5)
                if self._stop.is_set():
                    return
                uri = next(iter(self._pending))
                del self._pending[uri]
                self._busy = True
            try:
                self._analyze_and_publish(uri)
            except Exception as exc:  # bir dosyanın hatası sunucuyu düşürmez
                self.log(f"Analiz hatası: {type(exc).__name__}", 1)
            finally:
                with self._cond:
                    self._busy = False
                    self._cond.notify_all()

    def wait_idle(self, timeout: float = 60.0) -> bool:
        deadline = time.monotonic() + timeout
        with self._cond:
            while self._pending or self._busy:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cond.wait(remaining)
        return True

    def _analyze_and_publish(self, uri: str) -> None:
        doc = self.documents.get(uri)
        if doc is None or not is_candidate(doc.path):
            return
        try:
            disk = doc.path.read_bytes()
        except OSError:
            return
        scope = load_scope(self.data_dir)
        scope_public = scope.public()
        key = (str(doc.root), doc.rel, hashlib.sha256(disk).hexdigest(), json.dumps(scope_public, sort_keys=True),
               self._generation.get(doc.root, 0))
        findings = self._cache.get(key)
        if findings is not None:
            self.stats["cache_hits"] += 1
        else:
            findings = self._run_worker(doc, scope_public)
            if findings is None:
                return  # zaman aşımı / hata: önceki tanılamalar korunur
            self._cache[key] = findings
            while len(self._cache) > MAX_CACHE_ENTRIES:
                self._cache.pop(next(iter(self._cache)))
        if uri not in self.documents:
            return  # analiz sürerken kapatıldı
        text = disk.decode("utf-8", "replace")
        lines = text.splitlines(keepends=True)
        threshold = SEVERITY_ORDER.get(self.min_severity, 0)
        diagnostics = [finding_to_diagnostic(f, lines, doc.root) for f in findings
                       if SEVERITY_ORDER.get(str(f.get("severity") or "info"), 0) >= threshold]
        params: dict[str, Any] = {"uri": uri, "diagnostics": diagnostics}
        if doc.text == text and isinstance(doc.version, int):
            params["version"] = doc.version
        self.notify("textDocument/publishDiagnostics", params)

    def _run_worker(self, doc: Document, scope_public: dict[str, Any]) -> list[dict[str, Any]] | None:
        job = {"root": str(doc.root), "rel": doc.rel, "scope": scope_public,
               "allowed_roots": [str(p) for p in self.allowed_roots] if self.allowed_roots else None}
        env = dict(os.environ)
        # Taint önbelleği yalnız sunucunun kendi önbellek dizinine yazılır (canlı veri dizinine asla).
        if self.cache_dir is not None:
            env["SNIPER_DATA_DIR"] = str(self.cache_dir)
        else:
            env.pop("SNIPER_DATA_DIR", None)
            env["SNIPER_TAINT_CACHE"] = "0"
        env["SNIPER_PROJECT_TIME_BUDGET_SECONDS"] = str(max(1, int(self.timeout * 0.8)))
        env["SNIPER_QUIET"] = "1"
        started = time.monotonic()
        self.stats["analyses"] += 1
        try:
            proc = subprocess.Popen(self.worker_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, env=env, cwd=str(APP_DIR), start_new_session=True)
        except OSError as exc:
            self.log(f"Analiz süreci başlatılamadı: {exc}", 1)
            return None
        try:
            out, _ = proc.communicate(json.dumps(job).encode("utf-8"), timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self._kill_group(proc)
            self.stats["timeouts"] += 1
            self.log(f"{doc.rel}: analiz {self.timeout:.0f} sn süre sınırını aştı; tanılamalar güncellenmedi.", 2)
            return None
        try:
            result = json.loads(out.decode("utf-8") or "{}")
        except ValueError:
            self.log(f"{doc.rel}: analiz süreci geçersiz yanıt verdi (çıkış kodu {proc.returncode}).", 1)
            return None
        if not result.get("ok"):
            self.log(f"{doc.rel}: analiz hatası: {result.get('error') or 'bilinmiyor'}", 1)
            return None
        if result.get("skipped"):
            self.log(f"{doc.rel}: analiz edilmedi ({result['skipped']}).", 3)
        if result.get("partial"):
            self.log(f"{doc.rel}: süre bütçesi nedeniyle kısmi sonuç.", 2)
        self.log(f"{doc.rel}: {len(result.get('findings') or [])} bulgu, {time.monotonic() - started:.1f} sn.", 4)
        findings = result.get("findings")
        return findings if isinstance(findings, list) else []

    @staticmethod
    def _kill_group(proc: subprocess.Popen) -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)  # yalnız bu analizin süreç grubu (Node köprüsü dahil)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.communicate(timeout=5)
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass

    # -- hızlı düzeltme ---------------------------------------------------
    def _code_action(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        import taint_autofix

        uri = str(params["textDocument"]["uri"])
        doc = self.documents.get(uri)
        if doc is None:
            return []
        actions: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for diagnostic in (params.get("context") or {}).get("diagnostics") or []:
            if not isinstance(diagnostic, dict) or diagnostic.get("source") != "sniper":
                continue
            data = diagnostic.get("data") if isinstance(diagnostic.get("data"), dict) else {}
            kind = data.get("kind")
            if kind not in taint_autofix.STRATEGIES:
                continue
            try:
                line = int(diagnostic["range"]["start"]["line"]) + 1
            except (KeyError, TypeError, ValueError):
                continue
            if (kind, line) in seen:
                continue
            seen.add((kind, line))
            flow = data.get("flow") if isinstance(data.get("flow"), dict) else None
            try:
                suggestion, fixed = taint_autofix.compute_fix(doc.text, doc.rel, line, kind, flow=flow)
            except taint_autofix.AutofixError:
                continue
            if fixed is None:
                continue
            edit = text_edit_for(doc.text, fixed)
            if edit is None:
                continue
            actions.append({
                "title": f"Sniper: {suggestion['strategy']['title']} (güven: {suggestion.get('confidence', 'düşük')})",
                "kind": "quickfix",
                "diagnostics": [diagnostic],
                "isPreferred": suggestion.get("confidence") == "yüksek",
                "edit": {"changes": {uri: [edit]}},
            })
        return actions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sniper-lsp", description="Sniper editör tanılama sunucusu (LSP, stdio).")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--stdio", action="store_true", help="stdio üzerinden konuş (varsayılan; istemci uyumu için)")
    parser.add_argument("--data-dir", help="Sniper veri dizini (yalnız kalıcı tarama kapsamı okunur)")
    parser.add_argument("--cache-dir", help="Önbellek dizini (varsayılan ~/.cache/sniper-lsp)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="Dosya başına süre sınırı (sn)")
    args = parser.parse_args(argv)
    if args.worker:
        return worker_main()
    server = SniperLanguageServer(
        sys.stdin.buffer, sys.stdout.buffer,
        data_dir=Path(os.path.expanduser(args.data_dir)) if args.data_dir else None,
        cache_dir=Path(os.path.expanduser(args.cache_dir)) if args.cache_dir else None,
        timeout=min(MAX_TIMEOUT_SECONDS, max(MIN_TIMEOUT_SECONDS, args.timeout)),
    )
    return server.serve()


if __name__ == "__main__":
    raise SystemExit(main())
