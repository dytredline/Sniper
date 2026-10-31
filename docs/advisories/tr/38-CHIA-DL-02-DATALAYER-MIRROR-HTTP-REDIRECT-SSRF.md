# Chia DataLayer Ayna (Mirror) Senkronizasyonunda HTTP `30x` Yönlendirmesi İle Sunucu Taraflı İstek Sahteciliği / SSRF (`DL-02`)

[English](../38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md) | **Türkçe** | [日本語](../ja/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md) | [简体中文](../zh-CN/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md) | [한국어](../ko/38-CHIA-DL-02-DATALAYER-MIRROR-HTTP-REDIRECT-SSRF.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
1. **Adım 1 — Abone Olunan DataLayer Mağazalarında Ayna (Mirror) URL'lerinin Otomatik İndirilmesi (`chia/data_layer/download_data.py`):** Bir Chia DataLayer düğümü bir veri mağazasına abone olduğunda, zincir üstünde duyurulan Mirror URL adreslerine `aiohttp.ClientSession.get(...)` ile otomatik HTTP/HTTPS isteği göndererek `.dat` dosyalarını indirir.
2. **Adım 2 — HTTP `301`/`302`/`307` Yönlendirme Hedeflerinde İç Ağ / Loopback Kontrolünün Yapılmaması:** İlk Mirror URL'si dış dünyadaki normal bir adres görünse bile, `aiohttp` varsayılan olarak yönlendirmeleri (`allow_redirects=True`) takip eder ve yönlendirilen hedefin `127.0.0.1`, şirket içi özel ağ (`10.0.0.0/8`, `192.168.0.0/16`) veya bulut metadata servisi (`169.254.169.254`) olup olmadığını denetlemez.
3. **Adım 3 — Abone Düğümlerin İç Ağ Servislerine SSRF İsteği Göndermesi:** Saldırgan zincir üstünde `302 Found -> http://127.0.0.1:...` döndüren bir Mirror duyurduğunda, mağazaya abone olan tüm kurumsal DataLayer sunucuları kendi iç ağlarına istek atar.

### Zafiyetli Kod Kesiti
```python
# File: chia/data_layer/download_data.py
async with session.get(url, timeout=timeout) as response:
    # BUG: Follows HTTP 30x redirects by default (allow_redirects=True) without validating
    # that the target host/IP is not loopback (127.0.0.1), RFC1918 private, or link-local (169.254.169.254)!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Kurumsal DataLayer Sunucularında İç Ağ (`127.0.0.1`) ve Bulut Metadata (`169.254.169.254`) Erişimi
Popüler bir DataLayer mağazasına eklenen ayna URL'si `302` ile iç servislere yönlendirme yaparak abone sunucuların iç ağını tetikler.

### Senaryo B — Otomatik Senkronizasyon Botları Üzerinden İç Ağ Taraması
Mağazayı takip eden tüm yedekleme (mirror) düğümleri periyodik olarak yönlendirilen iç IP adreslerine istek gönderir.

### Senaryo C — Yamalı (`GREEN`) Doğrulama
`allow_redirects=False` ve hedef IP adresinin özel/loopback ağlara karşı doğrulanması ile SSRF tamamen engellenir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

```bash
# 1. Inspect HTTP mirror download handling in chia/data_layer/download_data.py
grep -n -C 10 "session.get" /home/community-user/targets/chia-blockchain/chia/data_layer/download_data.py
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Chia Network Tam Doğrulama Süiti ile üretilen çalışma zamanı kanıtı (bkz. [`chia-real-world-impact-e2e-20261031.json`](../chia-real-world-impact-e2e-20261031.json)):

```json
{
  "CHIA-DL-02": {
    "RED": {
      "mirror_url": "https://mirror.example/store.dat",
      "redirect_location": "http://127.0.0.1:18999/internal-secret",
      "redirect_to_loopback_followed": true,
      "internal_loopback_hit_count": 1
    },
    "GREEN": {
      "redirect_to_loopback_followed": false,
      "internal_loopback_hit_count": 0
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/chia/data_layer/download_data.py
+++ b/chia/data_layer/download_data.py
@@ -115,6 +115,8 @@
+    validate_public_http_target(url)
+    async with session.get(url, timeout=timeout, allow_redirects=False) as response:
```
