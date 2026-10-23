# Özel taint kuralları ve otomatik düzeltme önerileri

## Özel kurallar (`sniper-taint-rules-v1`)
Kurallar yalnız veridir (YAML veya JSON); kod çalıştırılmaz. Taranan proje kural getiremez: kurallar
yalnız işletmeci API'si ile (açık onayla) `$SNIPER_DATA_DIR/custom-rules/` (0700) altına yazılır.

```yaml
format: sniper-taint-rules-v1
name: sirket-db            # [a-z0-9][a-z0-9._-]{0,63}
language: python           # python | javascript
description: Şirket içi ham sorgu yardımcısı
sinks:
  - kind: sql              # taint_models.KNOWN_KINDS içinden
    calls: [sirket.db.ham_sorgu]
    args: [0]              # isteğe bağlı: lekeli olması gereken argüman sıraları
    keywords: [sorgu]      # isteğe bağlı
    cwe: CWE-89
    severity: high
sanitizers:
  - calls: [sirket.db.kacis]
    kinds: [sql]
propagators: [sirket.util.birlestir]
sources:                   # Python/JS motorlarında ve Opengrep çıktısında etkili
  - calls: [sirket.istek.parametre]
    label: http
```

Sınırlar: kural en çok 64 KB, en çok 50 kural, kural başına en çok 500 kayıt; deneme kodu en çok 200 KB, 30 sn.

## API
| Yöntem | Yol | Açıklama |
|---|---|---|
| GET | `/api/taint-rules` | Kural listesi, etkinlik durumu, sınırlar |
| GET | `/api/taint-rules/opengrep` | Tüm kuralların Opengrep (`mode: taint`) derlemesi |
| POST | `/api/taint-rules` | `{content, confirm_custom_rules: true}` → 201; onaysız 403 |
| POST | `/api/taint-rules/<ad>/delete` | `{confirm_custom_rules: true}` |
| POST | `/api/taint-rules/try` | `{content, code, filename}` → `new_flows`, `removed_flows` (kaydetmez) |
| POST | `/api/project-audits/<id>/findings/<sıra>/autofix` | Boş gövde; salt-okunur fark önizlemesi |

Kayıt/silme `STORE.log` ile `taint_rule.saved` / `taint_rule.deleted` olarak günlüğe yazılır.

## Otomatik düzeltme (`sniper-autofix-v1`)
Öneri dosyaya yazılmaz (`applied: false`). Python'da AST, JavaScript'te satır tabanlı dönüşüm yapılır;
güvenli dönüşüm bulunamazsa `mode: text` ile örnek güvenli kullanım döner.
Desteklenen türler: sql, command, eval, deserialize, html, path, ssrf, redirect, ldap, xpath, xxe,
session, log, regex, cookie, weakrand.
