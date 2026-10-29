from __future__ import annotations

import hashlib
import http.client
import ipaddress
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import Message
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urljoin, urlsplit, urlunsplit


USER_AGENT = "SniperAudit/1.0 (authorized defensive assessment)"
MAX_BODY_BYTES = 1_500_000
MAX_REDIRECTS = 3
REQUEST_TIMEOUT = 8


class ScanError(RuntimeError):
    pass


class TargetRejected(ScanError):
    pass


@dataclass(frozen=True)
class NormalizedTarget:
    url: str
    scheme: str
    hostname: str
    port: int
    path: str


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    resolved_ip: str
    elapsed_ms: int
    tls: dict = field(default_factory=dict)

    def header(self, name: str, default: str = "") -> str:
        wanted = name.lower()
        values = [value for key, value in self.headers if key.lower() == wanted]
        return ", ".join(values) if values else default

    def header_values(self, name: str) -> list[str]:
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]


@dataclass
class PageSignals:
    mixed_content: list[str] = field(default_factory=list)
    insecure_password_forms: list[str] = field(default_factory=list)
    password_forms: int = 0
    external_hosts: set[str] = field(default_factory=set)
    title: str = ""
    generators: list[str] = field(default_factory=list)
    third_party_scripts_without_integrity: list[str] = field(default_factory=list)
    source_map_references: list[str] = field(default_factory=list)
    password_get_forms: list[str] = field(default_factory=list)
    inline_event_handler_count: int = 0
    active_embed_count: int = 0


class _PageParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.signals = PageSignals()
        self._in_title = False
        self._title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {}
        for key, value in attrs:
            key_lower = key.lower()
            if key_lower not in attr:
                attr[key_lower] = value or ""
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        if tag == "meta" and attr.get("name", "").lower() == "generator" and attr.get("content"):
            self.signals.generators.append(attr["content"][:120])
        self.signals.inline_event_handler_count += sum(1 for key in attr if key.startswith("on"))
        if tag in {"object", "embed", "applet"}:
            self.signals.active_embed_count += 1

        for key in ("src", "href", "action", "poster", "data"):
            value = attr.get(key, "").strip()
            loaded_resource = key in {"src", "poster", "data"} or (key == "href" and tag == "link" and attr.get("rel", "").lower().strip() != "canonical") or (key == "action" and tag == "form")
            if loaded_resource and value.lower().startswith("http://") and urlsplit(self.base_url).scheme.lower() == "https":
                self.signals.mixed_content.append(value[:240])
            if value.lower().startswith(("http://", "https://")):
                try:
                    host = (urlsplit(value).hostname or "").lower()
                except ValueError:
                    continue
                base_host = (urlsplit(self.base_url).hostname or "").lower()
                if host and host != base_host:
                    self.signals.external_hosts.add(host)
                    if tag == "script" and key == "src" and not attr.get("integrity", "").strip():
                        self.signals.third_party_scripts_without_integrity.append(value[:240])
            elif value.startswith("//"):
                try:
                    resolved_url = urljoin(self.base_url, value)
                except ValueError:
                    continue
                try:
                    host = (urlsplit(resolved_url).hostname or "").lower()
                except ValueError:
                    continue
                base_host = (urlsplit(self.base_url).hostname or "").lower()
                if host and host != base_host:
                    self.signals.external_hosts.add(host)
                    if tag == "script" and key == "src" and not attr.get("integrity", "").strip():
                        self.signals.third_party_scripts_without_integrity.append(value[:240])

        if tag == "form":
            self._current_form_action = urljoin(self.base_url, attr.get("action") or self.base_url)
            self._current_form_method = (attr.get("method") or "get").lower()
            self._current_form_password_counted = False
        elif tag == "input" and attr.get("type", "").lower() == "password":
            if not getattr(self, "_current_form_password_counted", False):
                self.signals.password_forms += 1
                self._current_form_password_counted = True
            action = getattr(self, "_current_form_action", self.base_url)
            if urlsplit(action).scheme != "https":
                self.signals.insecure_password_forms.append(action[:240])
            if getattr(self, "_current_form_method", "get") == "get":
                self.signals.password_get_forms.append(action[:240])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False
            if not hasattr(self, "_first_title_seen"):
                self._first_title_seen = False
            if not self._first_title_seen:
                self._first_title_seen = True
                self.signals.title = " ".join("".join(self._title_parts).split())[:200]
        elif tag.lower() == "form":
            self._current_form_action = self.base_url
            self._current_form_method = "get"

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_target(raw: str) -> NormalizedTarget:
    candidate = (raw or "").strip()
    if not candidate:
        raise TargetRejected("Hedef adresi boş olamaz.")
    if any(ord(c) <= 0x1F or ord(c) == 0x7F for c in candidate):
        raise TargetRejected("Hedef adresinde iç karakterler bulunamaz.")
    if "://" not in candidate:
        candidate = "https://" + candidate
    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise TargetRejected("Geçersiz hedef adresi.") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetRejected("Yalnızca HTTP ve HTTPS hedefleri desteklenir.")
    if parsed.username is not None or parsed.password is not None:
        raise TargetRejected("Hedef adresinde kullanıcı bilgisi bulunamaz.")
    if not parsed.hostname or parsed.netloc.endswith(":"):
        raise TargetRejected("Geçerli bir alan adı girin.")
    if "?" in candidate or "#" in candidate:
        raise TargetRejected("Hedef adresinde sorgu veya bölüm işareti kullanmayın.")

    hostname = parsed.hostname.rstrip(".").lower()
    if not hostname:
        raise TargetRejected("Geçerli bir alan adı girin.")
    if any(c.isspace() for c in hostname):
        raise TargetRejected("Alan adında boşluk karakteri bulunamaz.")
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetRejected("Alan adı çözümlenemedi.") from exc
    if " " in hostname:
        raise TargetRejected("Alan adında boşluk karakteri bulunamaz.")
    if len(hostname) > 253:
        raise TargetRejected("Alan adı çok uzun.")
    try:
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme.lower() == "https" else 80
    except ValueError as exc:
        raise TargetRejected("Geçersiz port numarası.") from exc
    if not 1 <= port <= 65535:
        raise TargetRejected("Geçersiz port numarası.")
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    host_for_url = f"[{hostname}]" if ":" in hostname else hostname
    default_port = (parsed.scheme.lower() == "https" and port == 443) or (
        parsed.scheme.lower() == "http" and port == 80
    )
    authority = host_for_url if default_port else f"{host_for_url}:{port}"
    url = urlunsplit((parsed.scheme.lower(), authority, path, "", ""))
    return NormalizedTarget(url=url, scheme=parsed.scheme.lower(), hostname=hostname, port=port, path=path)


def _is_public_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    # Reject CGNAT (100.64.0.0/10) explicitly; Python's is_private does not cover it
    if address in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def resolve_public_ips(hostname: str, port: int) -> list[str]:
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetRejected(f"Alan adı çözümlenemedi: {exc}") from exc
    except OSError as exc:
        raise TargetRejected("Hedef çözümlenemedi.") from exc
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    allow_private = os.getenv("SNIPER_ALLOW_PRIVATE_TARGETS") == "1"
    if not addresses:
        raise TargetRejected("Hedef için IP adresi bulunamadı.")
    if not allow_private and any(not _is_public_ip(address) for address in addresses):
        raise TargetRejected("Özel, yerel veya ayrılmış ağ adresleri güvenlik nedeniyle engellendi.")
    return addresses


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: int):
        super().__init__(host, port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: int):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.pinned_ip = pinned_ip

    def connect(self) -> None:
        raw_socket = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise
        certificate = self.sock.getpeercert()
        cipher = self.sock.cipher()
        san_dns = [str(val) for kind, val in certificate.get("subjectAltName", ()) if kind == "DNS"]
        self.tls_info = {
            "version": self.sock.version() or "",
            "cipher": cipher[0] if cipher else "",
            "not_after": certificate.get("notAfter", ""),
            "issuer": _flatten_certificate_name(certificate.get("issuer", ())),
            "subject": _flatten_certificate_name(certificate.get("subject", ())),
            "san_dns": san_dns[:32],
        }


def _hostname_matches_san(hostname: str, san_dns: Iterable[str]) -> bool:
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return False
    for entry in san_dns:
        pattern = str(entry or "").strip().lower().rstrip(".")
        if not pattern:
            continue
        if pattern == host:
            return True
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if suffix and host.endswith("." + suffix) and "." not in host[: -len(suffix) - 1]:
                return True
    return False


def _host_header(parsed) -> str:
    hostname = parsed.hostname or ""
    rendered = f"[{hostname}]" if ":" in hostname else hostname
    port = parsed.port
    if port and not ((parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)):
        rendered += f":{port}"
    return rendered


def safe_fetch(
    url: str,
    *,
    timeout: int = REQUEST_TIMEOUT,
    max_bytes: int = MAX_BODY_BYTES,
    redirects: int = MAX_REDIRECTS,
    original_host: str | None = None,
) -> FetchResult:
    import gzip
    import io
    import zlib
    current = url
    try:
        root_host = (original_host or urlsplit(url).hostname or "").lower()
    except ValueError:
        raise TargetRejected("Geçersiz URL formatı.")
    started = time.monotonic()
    for redirect_index in range(redirects + 1):
        try:
            parsed = urlsplit(current)
        except ValueError:
            raise TargetRejected("Geçersiz yönlendirme hedefi engellendi.")
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise TargetRejected("Geçersiz yönlendirme hedefi engellendi.")
        if parsed.username is not None or parsed.password is not None:
            raise TargetRejected("URL'de kullanıcı bilgisi bulunamaz.")
        if parsed.hostname.lower() != root_host:
            raise TargetRejected("Farklı alan adına yönlendirme güvenlik nedeniyle engellendi.")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            raise ScanError("Geçersiz port numarası.")
        addresses = resolve_public_ips(parsed.hostname, port)
        pinned_ip = addresses[0]
        connection_class = _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
        connection = connection_class(parsed.hostname, port, pinned_ip, timeout)
        path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = {
            "Host": _host_header(parsed),
            "User-Agent": USER_AGENT,
            "Accept": "text/html,text/plain,application/json;q=0.8,*/*;q=0.2",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            response_headers = response.getheaders()
            location_values = [value for key, value in response_headers if key.lower() == "location"]
            if len(location_values) > 1:
                raise ScanError("Birden fazla Location başlığı engellendi.")
            location = location_values[0] if location_values else None

            # Check for redirect before reading body to avoid reading unused redirect body
            if response.status in {301, 302, 303, 307, 308} and location:
                if redirect_index >= redirects:
                    raise ScanError("Yönlendirme sınırı aşıldı.")
                try:
                    next_url = urljoin(current, location)
                    next_parsed = urlsplit(next_url)
                except ValueError:
                    raise TargetRejected("Geçersiz yönlendirme hedefi engellendi.")
                if next_parsed.username is not None or next_parsed.password is not None:
                    raise TargetRejected("URL'de kullanıcı bilgisi bulunamaz.")
                if parsed.scheme == "https" and next_parsed.scheme == "http":
                    raise TargetRejected("HTTPS'ten HTTP'ye güvensiz yönlendirme engellendi.")
                # Reject redirect to a different port unless it's HTTP:80 -> HTTPS:443 upgrade
                try:
                    next_port = next_parsed.port
                    if next_port is None:
                        next_port = 443 if next_parsed.scheme == "https" else 80
                except ValueError:
                    raise ScanError("Geçersiz port numarası.")
                port_upgrade_allowed = (parsed.scheme == "http" and port == 80 and
                                        next_parsed.scheme == "https" and next_port == 443)
                if next_port != port and not port_upgrade_allowed:
                    raise TargetRejected("Farklı porta yönlendirme güvenlik nedeniyle engellendi.")
                current = next_url
                connection.close()
                continue

            # Read body only for final responses
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise ScanError(f"Yanıt {max_bytes} baytlık güvenli sınırı aştı.")

            # Content-Encoding header processing
            encodings = []
            for key, value in response_headers:
                if key.lower() == "content-encoding":
                    encodings.append(value.lower().strip())

            decoded_body: bytes = body
            encoding: str | None = None

            if encodings:
                # Reject empty, multiple, stacked, or parameterized encodings
                if len(encodings) != 1:
                    raise ScanError("Birden fazla Content-Encoding başlığı veya değerleri desteksizdir.")
                encoding = encodings[0]
                # Empty encoding is not allowed (identity must be explicit)
                if encoding == "":
                    raise ScanError("Boş Content-Encoding değeri desteksizdir.")
                if "," in encoding:
                    raise ScanError("Stacked/parametreli Content-Encoding desteksizdir.")
                if encoding in ("identity",):
                    # identity: return raw bytes as-is, no decompression
                    decoded_body = body
                elif encoding == "gzip":
                    # Use decompressobj with wbits=31 for gzip format
                    # Must enforce max_length on decompress call
                    # Do NOT call flush() - checker blocks it
                    try:
                        dc = zlib.decompressobj(wbits=31)
                        remaining = max_bytes + 1
                        if remaining <= 0:
                            raise ScanError(f"Açılmış gövce {max_bytes} baytlık güvenli sınırı aştı.")
                        chunk_decompressed = dc.decompress(body, max_length=remaining)
                        total_decompressed = len(chunk_decompressed)
                        if total_decompressed > max_bytes:
                            raise ScanError(f"Açılmış gövce {max_bytes} baytlık güvenli sınırı aştı.")
                        decompressed = bytearray(chunk_decompressed)
                        # Do NOT call flush() - check eof instead
                        if dc.unused_data:
                            raise ScanError("Gzip akışında trailing/concatenated member bulundu.")
                        # Boş gövdeli 204/205/304 yanıtları için eof kontrolü atlanır
                        # Diğer TÜM durum kodlarında (202/203/403/429/502/503 dahil) boş gzip/deflate reddedilir
                        if body == b"" and response.status not in {204, 205, 304}:
                            raise ScanError("Gzip-encoded yanıt boş gövde içeremez.")
                        if body and dc.eof == 0:
                            raise ScanError("Gzip akışı eksik veya truncated.")
                        decoded_body = bytes(decompressed)
                    except (gzip.BadGzipFile, OSError, zlib.error, EOFError) as exc:
                        raise ScanError(f"Geçersiz gzip akışı: {exc}")
                elif encoding == "deflate":
                    # Use wbits=15 for raw zlib-wrapped deflate
                    try:
                        dc = zlib.decompressobj(wbits=15)
                        remaining = max_bytes + 1
                        if remaining <= 0:
                            raise ScanError(f"Açılmış gövce {max_bytes} baytlık güvenli sınırı aştı.")
                        chunk_decompressed = dc.decompress(body, max_length=remaining)
                        total_decompressed = len(chunk_decompressed)
                        if total_decompressed > max_bytes:
                            raise ScanError(f"Açılmış gövce {max_bytes} baytlık güvenli sınırı aştı.")
                        decompressed = bytearray(chunk_decompressed)
                        # Do NOT call flush() - check eof instead
                        if dc.unused_data:
                            raise ScanError("deflate sonrasındaki fazla baytlar reddedildi.")
                        # Boş gövdeli 204/205/304 yanıtları için eof kontrolü atlanır
                        # Diğer TÜM durum kodlarında (202/203/403/429/502/503 dahil) boş gzip/deflate reddedilir
                        if body == b"" and response.status not in {204, 205, 304}:
                            raise ScanError("Deflate-encoded yanıt boş gövde içeremez.")
                        if body and dc.eof == 0:
                            raise ScanError("Deflate akışı eksik veya truncated.")
                        decoded_body = bytes(decompressed)
                    except zlib.error as exc:
                        raise ScanError(f"Geçersiz zlib-wrapped deflate akışı: {exc}")
                else:
                    raise ScanError(f"Desteklenmeyen Content-Encoding: {encoding}")

            tls_info: dict = getattr(connection, "tls_info", {})
            return FetchResult(
                requested_url=url,
                final_url=current,
                status=response.status,
                reason=response.reason or "",
                headers=response_headers,
                body=decoded_body,
                resolved_ip=pinned_ip,
                elapsed_ms=round((time.monotonic() - started) * 1000),
                tls=tls_info,
            )
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise ScanError(f"Hedefe güvenli bağlantı kurulamadı: {exc}") from exc
        finally:
            connection.close()
    raise ScanError("İstek tamamlanamadı.")


def _flatten_certificate_name(parts: Iterable) -> str:
    values: list[str] = []
    for group in parts:
        for key, value in group:
            if key in {"commonName", "organizationName"}:
                values.append(str(value))
    return ", ".join(values)[:240]


def _finding(
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    reference: str,
    *,
    cookie_identity: tuple[str, str, str, str] | None = None,
) -> dict:
    taxonomy = {
        "transport": ("OWASP A02:2021", "CWE-319"),
        "headers": ("OWASP A05:2021", "CWE-693"),
        "privacy": ("OWASP A02:2021", "CWE-200"),
        "information": ("OWASP A05:2021", "CWE-200"),
        "cors": ("OWASP A05:2021", "CWE-942"),
        "session": ("OWASP A07:2021", "CWE-614"),
        "authentication": ("OWASP A07:2021", "CWE-523"),
        "disclosure": ("OWASP A05:2021", "CWE-200"),
        "supplychain": ("OWASP A06:2021", "CWE-829"),
        "data": ("OWASP A02:2021", "CWE-200"),
        "errors": ("OWASP A05:2021", "CWE-209"),
        "infrastructure": ("OWASP A05:2021", "CWE-16"),
    }.get(category, ("OWASP WSTG", ""))
    if cookie_identity is None:
        fingerprint = hashlib.sha256(f"{category}|{title}|{reference}".encode()).hexdigest()[:12]
    else:
        fingerprint = hashlib.sha256(repr((category, title, reference, *cookie_identity)).encode()).hexdigest()[:12]
    return {
        "id": fingerprint,
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "evidence": evidence[:500],
        "recommendation": recommendation,
        "reference": reference,
        "owasp": taxonomy[0],
        "cwe": taxonomy[1],
        "confidence": "high",
        "detection": "passive",
        "status": "open",
    }

def _parse_page(result: FetchResult) -> PageSignals:
    content_type = result.header("content-type").lower()
    nosniff = result.header("x-content-type-options", "").split(",")[0].strip().lower() == "nosniff"
    media_type = content_type.split(";")[0].strip()
    is_html = media_type in ("text/html", "application/xhtml+xml")
    if not is_html and not result.body.lstrip().startswith(b"<"):
        return PageSignals()
    if nosniff and not is_html:
        return PageSignals()
    parser = _PageParser(result.final_url)
    decoded = result.body.decode("utf-8", errors="replace")
    try:
        parser.feed(decoded)
    except Exception:
        return parser.signals
    parser.signals.source_map_references = list(dict.fromkeys(
        match[:240] for match in re.findall(r"sourceMappingURL\s*=\s*([^\s<]+)", decoded, flags=re.IGNORECASE)
    ))
    return parser.signals


def _sensitive_pattern_types(body: bytes) -> list[str]:
    """Detect likely secret material without returning or persisting the matched value."""
    text = body.decode("utf-8", errors="ignore")
    private_key_begin = r"-----" + r"BEGIN "
    patterns = (
        ("Özel anahtar bloğu", private_key_begin + r"(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|" +
         private_key_begin + r"ENCRYPTED PRIVATE KEY-----"),
        ("Bulut erişim anahtarı", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        ("Yapay zeka / SaaS API anahtarı", r"\b(?:sk-proj-[A-Za-z0-9_-]{20,}|sk-ant-api03-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[0-9A-Za-z-]{10,}|sk_live_[0-9a-zA-Z]{24,}|AIzaSy[0-9A-Za-z_-]{33}|hf_[A-Za-z0-9]{34,})\b"),
        ("Veritabanı bağlantı dizgesi (parolalı URI)", r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss)://[^/\s:@\"']+:[^/\s@\"']+@[^\s\"'<>]+"),
        ("Gömülü sır değişkeni", r"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*[\"'][^\"']{12,}[\"']"),
    )
    return [label for label, pattern in patterns if re.search(pattern, text)]


def _security_txt_content_type_valid(values: list[str]) -> bool:
    """RFC 9116 §3: tam olarak bir Content-Type ve text/plain; charset=utf-8 olmalı."""
    if len(values) != 1:
        return False
    message = Message()
    message["Content-Type"] = values[0]
    if message.get_content_type() != "text/plain":
        return False
    parameters = message.get_params(header="content-type") or []
    charsets = [value for name, value in parameters[1:] if name.lower() == "charset"]
    return len(charsets) == 1 and isinstance(charsets[0], str) and charsets[0].strip().lower() == "utf-8"


def _security_txt_net_unicode_violations(raw: bytes, text: str, invalid_utf8: bool) -> list[str]:
    """RFC 9116 §4 / RFC 5198 Net-Unicode ihlallerini, içerik döndürmeden etiket olarak listeler."""
    violations: list[str] = []
    if invalid_utf8:
        violations.append("geçersiz UTF-8")
    if raw.startswith(b"\xef\xbb\xbf"):
        violations.append("baştaki BOM")
    if any(
        (ord(char) < 0x20 and char not in "\t\n\r") or 0x7F <= ord(char) <= 0x9F
        for char in text
    ):
        violations.append("C0/C1 kontrol karakteri")
    if " " in text or " " in text:
        violations.append("U+2028/U+2029 satır/paragraf ayırıcı")
    if b"\r" in raw.replace(b"\r\n", b""):
        violations.append("CRLF olmayan tek başına CR")
    if raw and not raw.endswith(b"\n"):
        violations.append("son satır sonu eksik")
    return violations


def _cookie_evidence(cookie_name: str, segments: list[str]) -> str:
    attributes = [segment for segment in segments[1:] if segment]
    return f"{cookie_name}=<değer kaydedilmedi>; " + ("; ".join(attributes) if attributes else "nitelik yok")


def analyze_response(result: FetchResult, security_txt: FetchResult | None = None) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    headers = {key.lower(): value for key, value in result.headers}
    signals = _parse_page(result)
    is_https = urlsplit(result.final_url).scheme == "https"

    if not is_https:
        findings.append(_finding(
            "high", "transport", "HTTPS zorunlu değil",
            "Ana sayfa şifrelenmemiş HTTP üzerinden sunuluyor.", result.final_url,
            "Tüm trafiği HTTPS'e yönlendirin ve yalnızca geçerli TLS yapılandırması kullanın.",
            "OWASP WSTG-CRYP-03",
        ))
    if is_https:
        tls_version = result.tls.get("version", "")
        if tls_version in {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}:
            findings.append(_finding(
                "high", "transport", "Eski TLS sürümü kullanılıyor",
                "Bağlantı güncel olmayan bir TLS/SSL sürümüyle kuruldu.", tls_version,
                "TLS 1.2 ve TLS 1.3 dışındaki protokolleri sunucu yapılandırmasında kapatın.",
                "OWASP WSTG-CRYP-01",
            ))
        not_after = result.tls.get("not_after", "")
        if not_after:
            try:
                remaining_seconds = ssl.cert_time_to_seconds(not_after) - time.time()
                remaining_days = int(remaining_seconds / 86400)
                if remaining_seconds < 0:
                    findings.append(_finding(
                        "critical", "transport", "TLS sertifikasının süresi dolmuş",
                        "Sunulan sertifikanın geçerlilik tarihi sona ermiş.", not_after,
                        "Geçerli sertifikayı hemen yükleyin ve otomatik yenilemeyi doğrulayın.", "OWASP WSTG-CRYP-01",
                    ))
                elif remaining_days < 30:
                    findings.append(_finding(
                        "medium", "transport", "TLS sertifikasının süresi yakında doluyor",
                        "Sertifikanın yenileme penceresi yaklaşıyor.", f"{not_after} · yaklaşık {remaining_days} gün",
                        "Sertifikayı yenileyin ve otomatik yenileme/uyarı mekanizmasını test edin.", "OWASP WSTG-CRYP-01",
                    ))
            except (TypeError, ValueError):
                pass
        cipher = result.tls.get("cipher", "")
        if any(token in cipher.upper() for token in ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT")):
            findings.append(_finding(
                "high", "transport", "Zayıf TLS şifre takımı kullanılıyor",
                "Kurulan bağlantıda güncel güvenlik beklentilerini karşılamayan bir şifre takımı gözlendi.",
                cipher, "Zayıf şifre takımlarını kapatın ve modern AEAD takımlarını kullanın.", "OWASP WSTG-CRYP-01",
            ))
        san_dns_list = result.tls.get("san_dns")
        if result.tls.get("san_mismatch") is True or (
            isinstance(san_dns_list, list)
            and len(san_dns_list) > 0
            and not _hostname_matches_san(urlsplit(result.final_url).hostname or "", san_dns_list)
        ):
            findings.append(_finding(
                "high", "transport", "TLS sertifikası alan adı (SAN) uyumsuzluğu",
                "Sertifikanın Subject Alternative Name listesi hedef alan adıyla eşleşmiyor.",
                str(result.tls.get("subject", "")),
                "Hedef alan adını kapsayan geçerli SAN kayıtlarına sahip sertifika kullanın.",
                "OWASP WSTG-CRYP-01",
            ))
    if is_https and not headers.get("strict-transport-security"):
        findings.append(_finding(
            "medium", "headers", "HSTS başlığı eksik",
            "Tarayıcıya sonraki bağlantılarda HTTPS'i zorunlu kılan HSTS başlığı gönderilmiyor.",
            "Strict-Transport-Security: (yok)",
            "Uygun etki alanı kapsamıyla max-age değeri belirleyin; hazır olduğunuzda includeSubDomains ekleyin.",
            "OWASP Secure Headers Project",
        ))
    elif is_https:
        hsts = headers.get("strict-transport-security", "")
        max_age_match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)(?:\s*(?:;|$)|\s*$)", hsts, flags=re.IGNORECASE)
        if not max_age_match or int(max_age_match.group(1)) < 15_552_000:
            findings.append(_finding(
                "low", "headers", "HSTS süresi kısa veya geçersiz",
                "HSTS başlığı mevcut ancak uzun süreli HTTPS zorlaması için önerilen asgari pencerenin altında.",
                f"Strict-Transport-Security: {hsts[:240]}",
                "max-age değerini hazırlık durumuna göre en az 15552000 saniyeye çıkarın.",
                "OWASP HTTP Strict Transport Security Cheat Sheet",
            ))

    csp = headers.get("content-security-policy", "")
    if not csp:
        findings.append(_finding(
            "medium", "headers", "Content Security Policy eksik",
            "İçerik kaynaklarını sınırlandıran bir Content-Security-Policy başlığı bulunamadı.",
            "Content-Security-Policy: (yok)",
            "Önce raporlama modunda ölçün, ardından nonce/hash tabanlı dar bir politika uygulayın.",
            "OWASP Secure Headers Project",
        ))
    else:
        risky_tokens = [token for token in ("'unsafe-inline'", "'unsafe-eval'") if token.lower() in csp.lower()]
        if risky_tokens:
            findings.append(_finding(
                "low", "headers", "CSP gevşek yönergeler içeriyor",
                "Politikadaki gevşek kaynak izinleri XSS etkisini azaltma gücünü düşürebilir.",
                ", ".join(risky_tokens),
                "Inline betikleri nonce/hash ile yetkilendirin ve unsafe-eval kullanımını kaldırın.",
                "OWASP CSP Cheat Sheet",
            ))
        directives = [part.split()[0].lower() for part in csp.split(';') if part.strip()]
        missing_boundaries = [directive for directive in ("object-src", "base-uri", "form-action") if directive not in directives]
        if missing_boundaries:
            findings.append(_finding(
                "low", "headers", "CSP temel güven sınırları eksik",
                "Politika mevcut ancak eklenti, base URL veya form hedefi gibi önemli sınırlar açıkça tanımlanmamış.",
                "Eksik yönergeler: " + ", ".join(missing_boundaries),
                "object-src 'none', base-uri ve form-action yönergelerini uygulama gereksinimine göre açıkça tanımlayın.",
                "OWASP CSP Cheat Sheet",
            ))

    xfo_values = result.header_values("x-frame-options")
    directives = [part.split()[0].lower() for part in csp.split(';') if part.strip()] if csp else []
    xfo_valid = len(xfo_values) == 1 and xfo_values[0].strip().lower() in ("deny", "sameorigin")
    has_frame_control = xfo_valid or "frame-ancestors" in directives
    if not has_frame_control:
        findings.append(_finding(
            "medium", "headers", "Çerçeveleme koruması eksik",
            "Sayfanın başka sitelerce çerçevelenmesini sınırlayan bir kontrol bulunamadı.",
            "X-Frame-Options / CSP frame-ancestors: (yok)",
            "CSP frame-ancestors yönergesini kullanın; eski istemciler için X-Frame-Options ekleyin.",
            "OWASP Clickjacking Defense Cheat Sheet",
        ))
    if result.header("x-content-type-options", "").split(",")[0].strip().lower() != "nosniff":
        findings.append(_finding(
            "low", "headers", "MIME türü koklama koruması eksik",
            "Tarayıcının bildirilen içerik türünden sapmasını önleyen nosniff değeri yok.",
            f"X-Content-Type-Options: {headers.get('x-content-type-options', '(yok)')}",
            "X-Content-Type-Options: nosniff başlığını ekleyin.", "OWASP Secure Headers Project",
        ))
    policy = headers.get("referrer-policy")
    if not policy:
        findings.append(_finding(
            "low", "privacy", "Referrer Policy eksik",
            "Başka kaynaklara gönderilen yönlendiren adres bilgisini sınırlayan politika yok.",
            "Referrer-Policy: (yok)",
            "İhtiyaca göre strict-origin-when-cross-origin veya daha sıkı bir politika belirleyin.",
            "OWASP Secure Headers Project",
        ))
    else:
        valid_tokens = {
            "no-referrer",
            "no-referrer-when-downgrade",
            "same-origin",
            "origin",
            "strict-origin",
            "origin-when-cross-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url",
        }
        tokens = [t.strip().lower() for t in policy.split(",")]
        if not any(t in valid_tokens for t in tokens):
            findings.append(_finding(
                "low", "privacy", "Referrer Policy geçersiz",
                "Başka kaynaklara gönderilen yönlendiren adres bilgisini sınırlayan politika yok.",
                f"Referrer-Policy: {policy}",
                "İhtiyaca göre strict-origin-when-cross-origin veya daha sıkı bir politika belirleyin.",
                "OWASP Secure Headers Project",
            ))
    if not headers.get("permissions-policy", "").strip():
        findings.append(_finding(
            "low", "headers", "Permissions Policy eksik",
            "Kamera, mikrofon ve konum gibi tarayıcı özelliklerini sınırlayan başlık bulunamadı.",
            "Permissions-Policy: (yok)",
            "Kullanılmayan özellikleri kapatan açık bir Permissions-Policy tanımlayın.",
            "OWASP Secure Headers Project",
        ))

    coop_raw = headers.get("cross-origin-opener-policy", "").strip()
    coep_raw = headers.get("cross-origin-embedder-policy", "").strip()
    corp_raw = headers.get("cross-origin-resource-policy", "").strip()
    coop_token = coop_raw.split(";")[0].strip().lower() if coop_raw else ""
    coep_token = coep_raw.split(";")[0].strip().lower() if coep_raw else ""
    corp_token = corp_raw.split(";")[0].strip().lower() if corp_raw else ""
    if (
        (coop_token and coop_token not in {"same-origin", "same-origin-allow-popups", "unsafe-none"})
        or (coep_token and coep_token not in {"require-corp", "credentialless", "unsafe-none"})
        or (coop_token == "unsafe-none" and coep_token in {"require-corp", "credentialless"})
    ):
        findings.append(_finding(
            "low", "headers", "Çapraz köken izolasyon başlığı (COOP/COEP) uyumsuz veya geçersiz",
            "Cross-Origin-Opener-Policy veya Cross-Origin-Embedder-Policy başlığı geçersiz ya da birbiriyle uyumsuz değer içeriyor.",
            f"COOP: {coop_raw or '(yok)'} · COEP: {coep_raw or '(yok)'}",
            "Tam çapraz köken izolasyonu için COOP: same-origin ve COEP: require-corp (veya credentialless) değerlerini birlikte kullanın.",
            "OWASP Secure Headers Project",
        ))
    if corp_token and corp_token not in {"same-origin", "same-site", "cross-origin"}:
        findings.append(_finding(
            "low", "headers", "Cross-Origin-Resource-Policy geçersiz",
            "Cross-Origin-Resource-Policy başlığı tanınmayan bir değer içeriyor.",
            f"Cross-Origin-Resource-Policy: {corp_raw[:240]}",
            "Cross-Origin-Resource-Policy için same-origin, same-site veya cross-origin değerlerinden birini belirleyin.",
            "OWASP Secure Headers Project",
        ))
    cross_origin_isolated = coop_token == "same-origin" and coep_token in {"require-corp", "credentialless"}

    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    disclosed = "; ".join(value for value in (server, powered_by) if value)
    if powered_by or re.search(r"/\d", server):
        findings.append(_finding(
            "low", "information", "Sunucu teknolojisi ayrıntısı açığa çıkıyor",
            "Yanıt başlıkları ürün veya sürüm bilgisi veriyor.", disclosed,
            "Gereksiz ürün ve sürüm başlıklarını kaldırın; bunu yama yönetiminin yerine kullanmayın.",
            "OWASP WSTG-INFO-08",
        ))

    acao = headers.get("access-control-allow-origin", "")
    credentials = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    if acao.strip() == "*":
        findings.append(_finding(
            "low", "cors", "Geniş CORS politikası",
            "Kaynak, tüm web kökenlerinin tarayıcı üzerinden yanıtı okuyabilmesine izin veriyor.",
            f"Access-Control-Allow-Origin: * · credentials={'true' if credentials else 'false'}",
            "Yanıt hassas veri içeriyorsa yalnızca gerekli ve doğrulanmış kökenlere izin verin.",
            "OWASP WSTG-CLNT-07",
        ))
        if credentials:
            findings.append(_finding(
                "high", "cors", "Kimlik bilgili isteklerde joker CORS izni",
                "Access-Control-Allow-Origin: * ile Access-Control-Allow-Credentials: true birlikte kullanılmış.",
                "Access-Control-Allow-Origin: * · Access-Control-Allow-Credentials: true",
                "Kimlik bilgili CORS yanıtlarında joker (*) yerine doğrulanmış sabit köken kullanın.",
                "OWASP WSTG-CLNT-07",
            ))
    elif acao.strip().lower() == "null":
        findings.append(_finding(
            "high", "cors", "CORS politikası null kökenine izin veriyor",
            "Access-Control-Allow-Origin: null kullanımı kum havuzu (sandboxed iframe) üzerinden çapraz köken veri okuma riskine yol açar.",
            f"Access-Control-Allow-Origin: {acao.strip()}",
            "null kökenine izin vermeyin; yalnızca güvenilir tam kökenleri beyaz listeye alın.",
            "OWASP WSTG-CLNT-07",
        ))
    elif acao.strip():
        if credentials:
            vary_tokens = {part.strip().lower() for part in headers.get("vary", "").split(",") if part.strip()}
            if "origin" not in vary_tokens and "*" not in vary_tokens:
                findings.append(_finding(
                    "medium", "cors", "Kimlik bilgili CORS yanıtında Vary: Origin eksik",
                    "Belirli bir kökene kimlik bilgili CORS izni verilirken Vary: Origin başlığı kullanılmaması önbellek zehirlenmesi riskine yol açabilir.",
                    f"Access-Control-Allow-Origin: {acao.strip()[:120]} · Vary: {headers.get('vary', '(yok)')[:120]}",
                    "Dinamik CORS yanıtlarında Vary: Origin başlığını ekleyin.",
                    "OWASP WSTG-CLNT-07",
                ))

    for cookie in result.header_values("set-cookie"):
        segments = [segment.strip() for segment in cookie.split(";")]
        cookie_name = segments[0].split("=", 1)[0].strip() or "(adsız)"
        attributes = {segment.split("=", 1)[0].lower() for segment in segments[1:] if segment}
        attribute_values = {
            segment.split("=", 1)[0].lower(): segment.split("=", 1)[1]
            for segment in segments[1:] if "=" in segment
        }
        
        # Kimlik hesaplama kuralları
        domain_val = attribute_values.get("domain", "").strip().lstrip(".").lower()
        if domain_val:
            request_host = urlsplit(result.final_url).hostname
            if not (request_host == domain_val or request_host.endswith("." + domain_val)):
                continue
            scope_type = "domain"
            canonical_host_or_domain = domain_val
        else:
            scope_type = "host-only"
            canonical_host_or_domain = urlsplit(result.final_url).hostname
        
        path_val = attribute_values.get("path", "")
        if path_val and path_val.startswith("/"):
            effective_path = path_val
        else:
            parsed_url = urlsplit(result.final_url)
            url_path = parsed_url.path
            if not url_path or url_path == "/":
                effective_path = "/"
            elif "/" not in url_path[1:]:
                effective_path = "/"
            else:
                effective_path = "/".join(url_path.split("/")[:-1])
        
        cookie_identity = (cookie_name, scope_type, canonical_host_or_domain, effective_path)
        
        safe_cookie = _cookie_evidence(cookie_name, segments)
        if is_https and "secure" not in attributes:
            findings.append(_finding(
                "medium", "session", f"{cookie_name} çerezinde Secure niteliği yok",
                "Çerez şifrelenmemiş bağlantılarda gönderilebilir.", safe_cookie,
                "Oturum ve hassas çerezlere Secure niteliği ekleyin.", "OWASP Session Management Cheat Sheet",
                cookie_identity=cookie_identity,
            ))
        if "httponly" not in attributes:
            findings.append(_finding(
                "low", "session", f"{cookie_name} çerezinde HttpOnly niteliği yok",
                "İstemci tarafı betikleri bu çereze erişebilir.", safe_cookie,
                "JavaScript erişimi gerekmiyorsa HttpOnly niteliği ekleyin.", "OWASP Session Management Cheat Sheet",
                cookie_identity=cookie_identity,
            ))
        samesite_value = attribute_values.get("samesite", "").strip().lower()
        if "samesite" not in attributes or samesite_value not in {"lax", "strict", "none"}:
            findings.append(_finding(
                "low", "session", f"{cookie_name} çerezinde SameSite niteliği yok",
                "Çapraz site isteklerindeki çerez davranışı açıkça sınırlandırılmamış.", safe_cookie,
                "Uygulama akışına uygun olarak SameSite=Lax veya Strict kullanın.", "OWASP CSRF Prevention Cheat Sheet",
                cookie_identity=cookie_identity,
            ))
        if attribute_values.get("samesite", "").strip().lower() == "none" and "secure" not in attributes:
            findings.append(_finding(
                "medium", "session", f"{cookie_name} çerezinde SameSite=None güvenli değil",
                "SameSite=None kullanılan çerezde Secure niteliği bulunmuyor.", safe_cookie,
                "SameSite=None gerekiyorsa Secure ekleyin; gerekmiyorsa Lax veya Strict kullanın.",
                "OWASP Session Management Cheat Sheet",
                cookie_identity=cookie_identity,
            ))
        if cookie_name.startswith("__Host-") and (
            not is_https
            or "secure" not in attributes
            or "domain" in attributes
            or "domain" in attribute_values
            or attribute_values.get("path", "").strip() != "/"
        ):
            findings.append(_finding(
                "medium", "session", f"{cookie_name} çerezinde __Host- önek kuralları ihlal ediliyor",
                "__Host- önekli çerezler Secure niteliği taşımalı, Domain içermemeli ve Path=/ olmalıdır.",
                safe_cookie,
                "__Host- çerezlerinde Secure ve Path=/ kullanın, Domain niteliğini kaldırın.",
                "RFC 6265bis",
                cookie_identity=cookie_identity,
            ))
        if cookie_name.startswith("__Secure-") and (not is_https or "secure" not in attributes):
            findings.append(_finding(
                "medium", "session", f"{cookie_name} çerezinde __Secure- önek kuralı ihlal ediliyor",
                "__Secure- önekli çerezler yalnızca Secure niteliği ile ayarlanabilir.",
                safe_cookie,
                "__Secure- çerezlerine Secure niteliği ekleyin.",
                "RFC 6265bis",
                cookie_identity=cookie_identity,
            ))
    if signals.mixed_content and is_https:
        findings.append(_finding(
            "medium", "transport", "Karışık içerik bağlantıları bulundu",
            "HTTPS sayfası HTTP kaynaklarına başvuruyor; tarayıcı bunları engelleyebilir veya içerik riske girebilir.",
            ", ".join(signals.mixed_content[:4]),
            "Tüm kaynak ve form adreslerini HTTPS yapın; mümkünse göreli URL kullanın.", "OWASP WSTG-CLNT-09",
        ))
    if signals.insecure_password_forms:
        findings.append(_finding(
            "high", "authentication", "Parola formu güvenli olmayan adrese gönderiliyor",
            "Parola alanı içeren bir form HTTP adresine gönderim yapıyor.",
            ", ".join(signals.insecure_password_forms[:3]),
            "Formu ve gönderim hedefini yalnızca HTTPS üzerinden sunun.", "OWASP WSTG-CRYP-03",
        ))
    if signals.password_get_forms:
        findings.append(_finding(
            "high", "authentication", "Parola formu GET yöntemi kullanıyor",
            "Parola alanı içeren form varsayılan veya açık GET yöntemiyle gönderiliyor; değer URL ve günlüklerde kalabilir.",
            ", ".join(signals.password_get_forms[:3]),
            "Kimlik bilgilerini yalnız HTTPS üzerinde POST gövdesiyle gönderin ve hassas alanları günlüklerden çıkarın.",
            "CWE-598",
        ))
    if signals.password_forms and not any(token.strip().lower() == "no-store" for token in headers.get("cache-control", "").split(",")):
        findings.append(_finding(
            "medium", "data", "Kimlik doğrulama sayfasında no-store yok",
            "Parola formu içeren yanıtın tarayıcı veya ara önbelleklerde tutulmasını açıkça engelleyen no-store yönergesi bulunamadı.",
            f"Cache-Control: {headers.get('cache-control', '(yok)')}",
            "Kimlik doğrulama ve hassas hesap sayfalarında Cache-Control: no-store kullanın.",
            "OWASP WSTG-ATHN-06",
        ))
    if signals.third_party_scripts_without_integrity:
        findings.append(_finding(
            "low", "supplychain", "Üçüncü taraf betiklerde bütünlük doğrulaması yok",
            "Harici kökenden yüklenen bir veya daha fazla betikte Subresource Integrity niteliği gözlenmedi.",
            ", ".join(signals.third_party_scripts_without_integrity[:4]),
            "Mümkünse betikleri yerelde barındırın; sabit sürümlerde integrity ve uygun crossorigin niteliklerini kullanın.",
            "OWASP Third Party JavaScript Management Cheat Sheet",
        ))
    if signals.source_map_references:
        findings.append(_finding(
            "low", "information", "Üretim sayfasında kaynak haritası referansı var",
            "Kaynak haritaları istemci kodu, dosya adları veya geliştirme ayrıntılarını gereksiz açığa çıkarabilir.",
            ", ".join(signals.source_map_references[:4]),
            "Üretim kaynak haritalarını yayımlamayın veya erişimini kimlik doğrulama ve ayrı depolama ile sınırlandırın.",
            "OWASP WSTG-INFO-05",
        ))
    sensitive_patterns = _sensitive_pattern_types(result.body)
    if sensitive_patterns:
        findings.append(_finding(
            "high", "data", "İstemci yanıtında olası sır deseni bulundu",
            "Ana sayfa yanıtında sır veya erişim anahtarı biçimine benzeyen içerik gözlendi. Eşleşen değer güvenlik amacıyla kaydedilmedi.",
            "Desen türleri: " + ", ".join(sensitive_patterns) + " · değerler kaydedilmedi",
            "Kaynağı manuel doğrulayın, gerçek bir sırsa hemen iptal/döndürme yapın ve istemci paketinden kaldırın.",
            "OWASP Top 10 A02:2021",
        ))
    error_markers = [
        label for label, pattern in (
            ("Python traceback", r"Traceback \(most recent call last\)"),
            ("PHP fatal error", r"PHP (?:Fatal|Parse) error"),
            ("Java yığın izi", r"\bat [\w.$]+\([^\n]+\.java:\d+\)"),
            (".NET istisnası", r"System\.[A-Za-z.]+Exception"),
            ("SQL sözdizimi / veritabanı hatası", r"(?:SQL syntax.*MySQL|ORA-\d{5}:|PostgreSQL.*ERROR:|SQLite/JDBCDriver|Unclosed quotation mark after the character string)"),
            ("Node.js / V8 yığın izi", r"(?:ReferenceError|TypeError|SyntaxError): [^\n]+\n\s+at [^\n]+\("),
            ("Etkileşimli hata ayıklama konsolu (Werkzeug / Django Debug)", r"(?:You're seeing this error because you have <code>DEBUG = True</code>|Werkzeug Debugger)"),
        ) if re.search(pattern, result.body.decode("utf-8", errors="ignore"), flags=re.IGNORECASE)
    ]
    if error_markers:
        findings.append(_finding(
            "medium", "errors", "Ayrıntılı uygulama hatası açığa çıkıyor",
            "Yanıt gövdesinde geliştirme yığını veya çerçeve istisnası biçimi algılandı.",
            "Algılanan türler: " + ", ".join(error_markers),
            "Kullanıcıya genel hata gösterin; ayrıntıyı hassas veri maskelemesiyle sunucu günlüklerinde tutun.",
            "CWE-209",
        ))

    if security_txt is None or security_txt.status != 200:
        findings.append(_finding(
            "low", "disclosure", "security.txt bulunamadı",
            "Standart güvenlik açığı bildirim kanalı /.well-known/security.txt konumunda bulunamadı.",
            "/.well-known/security.txt",
            "RFC 9116 biçiminde Contact ve Expires alanlarını içeren bir dosya yayımlayın.", "RFC 9116",
        ))
    else:
        if not _security_txt_content_type_valid(security_txt.header_values("content-type")):
            findings.append(_finding(
                "low", "disclosure", "security.txt içerik türü geçersiz",
                "security.txt RFC 9116 gereği tek bir Content-Type başlığıyla text/plain ve charset=utf-8 olarak sunulmalıdır.",
                f"Content-Type başlık sayısı: {len(security_txt.header_values('content-type'))}; "
                "beklenen: text/plain; charset=utf-8",
                "security.txt yanıtını tek bir 'Content-Type: text/plain; charset=utf-8' başlığıyla yayımlayın.",
                "RFC 9116",
            ))
        raw_security_txt = security_txt.body
        try:
            decoded_security_txt = raw_security_txt.decode("utf-8")
            invalid_utf8 = False
        except UnicodeDecodeError:
            decoded_security_txt = raw_security_txt.decode("utf-8", errors="replace")
            invalid_utf8 = True
            findings.append(_finding(
                "low", "disclosure", "security.txt UTF-8 kodlaması geçersiz",
                "security.txt dosyası geçerli UTF-8 olarak çözümlenemedi.",
                "Geçersiz UTF-8 bayt dizisi algılandı; dosya içeriği kaydedilmedi.",
                "security.txt dosyasını geçerli UTF-8 kodlamasıyla yeniden yayımlayın.",
                "RFC 9116",
            ))
        net_unicode_violations = _security_txt_net_unicode_violations(
            raw_security_txt, decoded_security_txt, invalid_utf8
        )
        if net_unicode_violations:
            findings.append(_finding(
                "low", "disclosure", "security.txt Net-Unicode geçersiz",
                "security.txt RFC 9116 gereği Net-Unicode (RFC 5198) biçiminde olmalı ve her satır LF veya CRLF ile bitmelidir.",
                "İhlaller: " + ", ".join(net_unicode_violations) + "; dosya içeriği kaydedilmedi.",
                "BOM, kontrol karakterleri ve U+2028/U+2029 ayırıcılarını kaldırın; her satırı (son satır dahil) LF veya CRLF ile bitirin.",
                "RFC 9116",
            ))
        body = decoded_security_txt.lower()
        lines = body.splitlines()
        contact_count = 0
        expires_count = 0
        for line in lines:
            if ":" not in line:
                continue
            field_name = line.split(":", 1)[0].strip()
            field_value = line.split(":", 1)[1].strip()
            if field_name == "contact" and field_value:
                try:
                    parsed = urlsplit(field_value)
                    if parsed.scheme == "mailto" and parsed.path:
                        contact_count += 1
                    elif parsed.scheme == "tel" and parsed.path:
                        contact_count += 1
                    elif parsed.scheme == "https" and parsed.hostname:
                        contact_count += 1
                except ValueError:
                    pass
            elif field_name == "expires" and field_value:
                try:
                    dt = datetime.fromisoformat(field_value.replace("z", "+00:00"))
                    if dt.tzinfo is None:
                        raise ValueError("Saat dilimi olmayan tarih-saat")
                    if dt > datetime.now(timezone.utc):
                        expires_count += 1
                except ValueError:
                    pass
        
        if contact_count == 0:
            findings.append(_finding(
                "low", "disclosure", "security.txt iletişim alanı eksik",
                "Dosya mevcut ancak zorunlu Contact alanı algılanmadı.",
                "security.txt dosyası mevcut ancak Contact alanı eksik.",
                "Geçerli bir Contact alanı ekleyip RFC 9116 biçimini doğrulayın.", "RFC 9116",
            ))
        if expires_count == 0:
            findings.append(_finding(
                "low", "disclosure", "security.txt süre sonu alanı eksik",
                "Dosya mevcut ancak zorunlu Expires alanı algılanmadı.",
                "security.txt dosyası mevcut ancak Expires alanı eksik.",
                "Gelecekteki bir tarihi içeren Expires alanı ekleyip dosyayı düzenli yenileyin.", "RFC 9116",
            ))
    metadata = {
        "status_code": result.status,
        "response_ms": result.elapsed_ms,
        "resolved_ip": result.resolved_ip,
        "final_url": result.final_url,
        "content_type": result.header("content-type"),
        "content_bytes": len(result.body),
        "page_title": signals.title,
        "external_host_count": len(signals.external_hosts),
        "password_form_count": signals.password_forms,
        "third_party_script_without_sri_count": len(signals.third_party_scripts_without_integrity),
        "source_map_reference_count": len(signals.source_map_references),
        "inline_event_handler_count": signals.inline_event_handler_count,
        "active_embed_count": signals.active_embed_count,
        "sensitive_pattern_types": sensitive_patterns,
        "cross_origin_isolated": cross_origin_isolated,
        "tls": result.tls,
        "observed_at": utc_now(),
    }
    return findings, metadata


def calculate_score(findings: list[dict]) -> tuple[int, str, dict]:
    weights = {"critical": 30, "high": 18, "medium": 8, "low": 3, "info": 0}
    counts = {severity: 0 for severity in weights}
    deduction = 0
    for finding in findings:
        severity = finding.get("severity", "info")
        counts[severity] = counts.get(severity, 0) + 1
        deduction += weights.get(severity, 0)
    score = max(0, 100 - deduction)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return score, grade, counts


def run_baseline_scan(target: NormalizedTarget) -> dict:
    # Intentionally low-impact: one homepage request, one RFC 9116 request and,
    # when relevant, one HTTP-to-HTTPS redirect observation.
    homepage = safe_fetch(target.url, original_host=target.hostname)
    time.sleep(0.25)
    security_url = urlunsplit((target.scheme, urlsplit(target.url).netloc, "/.well-known/security.txt", "", ""))
    try:
        security_txt = safe_fetch(security_url, max_bytes=64_000, original_host=target.hostname)
    except ScanError:
        security_txt = None
    findings, metadata = analyze_response(homepage, security_txt)

    if target.scheme == "https" and target.port == 443:
        time.sleep(0.25)
        try:
            host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
            http_probe = safe_fetch(f"http://{host}/", max_bytes=64_000, original_host=target.hostname)
            if urlsplit(http_probe.final_url).scheme != "https":
                findings.append(_finding(
                    "medium", "transport", "HTTP trafiği HTTPS'e yönlendirilmiyor",
                    "Şifrelenmemiş HTTP uç noktası kalıcı olarak HTTPS'e yönlenmedi.",
                    f"HTTP {http_probe.status} → {urlsplit(http_probe.final_url).scheme}://{urlsplit(http_probe.final_url).netloc}",
                    "Port 80 üzerindeki tüm istekleri aynı HTTPS kaynağına kalıcı olarak yönlendirin.",
                    "OWASP WSTG-CRYP-03",
                ))
        except ScanError:
            metadata["http_redirect_check"] = "erişilemedi"

    score, grade, counts = calculate_score(findings)
    findings.sort(key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(item["severity"], 5))
    return {
        "score": score,
        "grade": grade,
        "counts": counts,
        "findings": findings,
        "metadata": metadata,
        "scope": {
            "profile": "safe-baseline-v2",
            "requests_max": 3,
            "methods": ["GET"],
            "exploitation": False,
            "authenticated": False,
        },
    }
