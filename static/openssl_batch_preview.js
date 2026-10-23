// Passive saved-report batch preview helper for OpenSSL x509 summaries.
// Never initiates active network connections or subprocess execution.

const BATCH_SUMMARY_ENDPOINT = "/api/tool-reports/openssl-x509/batch-summary";
const MAX_BATCH_BLOCKS = 8;
const MAX_BATCH_BYTES = 65536;

function utf8ByteLength(text) {
  return new TextEncoder().encode(text).length;
}

export function defaultEscapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function parseOpenSslBatchInputs(rawText) {
  if (Array.isArray(rawText)) {
    if (rawText.length < 1 || rawText.length > MAX_BATCH_BLOCKS) {
      throw new Error("OpenSSL x509 toplu önizleme 1 ile 8 arasında sertifika bloğu gerektirir.");
    }
    const normalized = [];
    let totalBytes = 0;
    for (const item of rawText) {
      if (typeof item !== "string") {
        throw new Error("Her sertifika bloğu metin olmalıdır.");
      }
      const trimmed = item.trim();
      if (!trimmed || trimmed.includes("\0")) {
        throw new Error("Boş veya geçersiz sertifika bloğu kabul edilmez.");
      }
      const itemBytes = utf8ByteLength(trimmed);
      totalBytes += itemBytes;
      if (itemBytes > MAX_BATCH_BYTES || totalBytes > MAX_BATCH_BYTES) {
        throw new Error("OpenSSL x509 toplu girdisi 65536 bayt sınırını aşıyor.");
      }
      normalized.push(trimmed);
    }
    return normalized;
  }

  if (typeof rawText !== "string") {
    throw new Error("OpenSSL x509 toplu girdisi metin olmalıdır.");
  }
  if (rawText.includes("\0")) {
    throw new Error("Geçersiz karakter içeren OpenSSL x509 girdisi.");
  }
  if (utf8ByteLength(rawText) > MAX_BATCH_BYTES) {
    throw new Error("OpenSSL x509 toplu girdisi 65536 bayt sınırını aşıyor.");
  }

  const trimmed = rawText.trim();
  if (!trimmed) {
    throw new Error("OpenSSL x509 toplu girdisi boş olamaz.");
  }

  let rawBlocks;
  if (trimmed.includes("---CERT---")) {
    rawBlocks = trimmed.split(/\r?\n?[ \t]*---CERT---[ \t]*\r?\n?/);
  } else {
    rawBlocks = trimmed.split(/\r?\n[ \t]*\r?\n+/);
  }

  const blocks = rawBlocks.map((block) => block.trim());
  if (blocks.length < 1 || blocks.some((block) => !block)) {
    throw new Error("Boş sertifika bloğu içeren OpenSSL x509 toplu girdisi reddedildi.");
  }
  if (blocks.length > MAX_BATCH_BLOCKS) {
    throw new Error("En fazla 10 sertifika bloğu gönderilebilir.");
  }

  return blocks;
}

export function renderOpenSslBatchPreviewHtml(summary, escapeHtml) {
  if (!summary || typeof summary !== "object" || Array.isArray(summary)) {
    throw new Error("Geçersiz OpenSSL x509 toplu özet yanıtı.");
  }

  const esc =
    typeof escapeHtml === "function"
      ? (value) => String(escapeHtml(value ?? ""))
      : defaultEscapeHtml;

  const format = esc(summary.format ?? "openssl-x509-batch-summary-v1");
  const statusCounts =
    summary.status_counts && typeof summary.status_counts === "object"
      ? summary.status_counts
      : summary.validity_counts && typeof summary.validity_counts === "object"
        ? summary.validity_counts
        : {};

  const certificates = Array.isArray(summary.certificates)
    ? summary.certificates
    : Array.isArray(summary.items)
      ? summary.items
      : Array.isArray(summary.rows)
        ? summary.rows
        : [];

  const certificateCount = esc(
    summary.certificate_count ?? summary.report_count ?? certificates.length
  );
  const validCount = esc(statusCounts.valid ?? 0);
  const expiredCount = esc(statusCounts.expired ?? 0);
  const notYetValidCount = esc(statusCounts.not_yet_valid ?? 0);
  const expiringSoonHtml =
    statusCounts.expiring_soon !== undefined
      ? `<div class="summary-stat"><span class="label">Yakında Dolacak</span><span class="value" data-field="status_expiring_soon">${esc(statusCounts.expiring_soon)}</span></div>`
      : "";
  const nearestExpiryDays = esc(summary.nearest_expiry_days ?? "-");
  const batchSha256 = esc(summary.batch_sha256 ?? "");

  const rowsHtml = certificates
    .map((cert, index) => {
      const item = cert && typeof cert === "object" ? cert : {};
      const subject = esc(item.subject ?? item.common_name ?? item.name ?? item.label ?? `#${index + 1}`);
      const issuer = esc(item.issuer ?? "-");
      const status = esc(item.status ?? item.validity ?? "-");
      const expiryDays = esc(
        item.days_until_expiry ?? item.expiry_days ?? item.nearest_expiry_days ?? "-"
      );
      const notBefore = esc(item.not_before ?? item.not_before_utc ?? "-");
      const notAfter = esc(item.not_after ?? item.not_after_utc ?? "-");
      const certSha256 = esc(
        item.sha256 ?? item.fingerprint_sha256 ?? item.report_sha256 ?? item.fingerprint ?? "-"
      );
      return `<tr class="openssl-batch-cert-row" data-index="${index}">` +
        `<td data-field="cert_index">${index + 1}</td>` +
        `<td data-field="cert_subject">${subject}</td>` +
        `<td data-field="cert_issuer">${issuer}</td>` +
        `<td data-field="cert_status">${status}</td>` +
        `<td data-field="cert_days_until_expiry">${expiryDays}</td>` +
        `<td data-field="cert_not_before">${notBefore}</td>` +
        `<td data-field="cert_not_after">${notAfter}</td>` +
        `<td data-field="cert_sha256"><code>${certSha256}</code></td>` +
        `</tr>`;
    })
    .join("");

  return (
    `<div class="openssl-batch-preview-card" data-format="${format}">` +
    `<div class="openssl-batch-summary-grid">` +
    `<div class="summary-stat"><span class="label">Sertifika Sayısı</span><span class="value" data-field="certificate_count">${certificateCount}</span></div>` +
    `<div class="summary-stat"><span class="label">Geçerli</span><span class="value" data-field="status_valid">${validCount}</span></div>` +
    `<div class="summary-stat"><span class="label">Süresi Dolmuş</span><span class="value" data-field="status_expired">${expiredCount}</span></div>` +
    `<div class="summary-stat"><span class="label">Henüz Geçerli Değil</span><span class="value" data-field="status_not_yet_valid">${notYetValidCount}</span></div>` +
    expiringSoonHtml +
    `<div class="summary-stat"><span class="label">En Yakın Bitiş (Gün)</span><span class="value" data-field="nearest_expiry_days">${nearestExpiryDays}</span></div>` +
    `<div class="summary-stat"><span class="label">Batch SHA-256</span><code class="value" data-field="batch_sha256">${batchSha256}</code></div>` +
    `</div>` +
    `<table class="openssl-batch-cert-table">` +
    `<thead><tr><th>#</th><th>Subject</th><th>Issuer</th><th>Durum</th><th>Kalan Gün</th><th>Not Before</th><th>Not After</th><th>SHA-256</th></tr></thead>` +
    `<tbody>${rowsHtml}</tbody>` +
    `</table>` +
    `</div>`
  );
}

export async function requestOpenSslBatchPreview(api, rawReports) {
  if (typeof api !== "function") {
    throw new Error("Geçerli bir API istemcisi gereklidir.");
  }
  const reports = parseOpenSslBatchInputs(rawReports);
  const body = JSON.stringify({ reports });
  if (utf8ByteLength(body) > MAX_BATCH_BYTES) {
    throw new Error("OpenSSL x509 toplu isteği 65536 bayt sınırını aşıyor.");
  }
  return await api(BATCH_SUMMARY_ENDPOINT, {
    method: "POST",
    body,
  });
}

if (typeof globalThis !== "undefined") {
  globalThis.parseOpenSslBatchInputs = parseOpenSslBatchInputs;
  globalThis.renderOpenSslBatchPreviewHtml = renderOpenSslBatchPreviewHtml;
  globalThis.requestOpenSslBatchPreview = requestOpenSslBatchPreview;
}
