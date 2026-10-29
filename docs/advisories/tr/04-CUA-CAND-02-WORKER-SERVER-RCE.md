# `0.0.0.0:8001` Worker Server Wildcard CORS + Fail-Open `OSGYM_ALLOWED_IPS` + Kimlik Doğrulamasız `POST /reset` Üzerinden Dinamik Modül Çalıştırma (`GHSA-xm8w-gj3g-4f25`)

[English](../04-CUA-CAND-02-WORKER-SERVER-RCE.md) | **Türkçe** | [日本語](../ja/04-CUA-CAND-02-WORKER-SERVER-RCE.md) | [简体中文](../zh-CN/04-CUA-CAND-02-WORKER-SERVER-RCE.md) | [한국어](../ko/04-CUA-CAND-02-WORKER-SERVER-RCE.md)

## GitHub GHSA ve MITRE CNA Hızlı Doldurma Alanları
- **Depo (Repository):** `trycua/cua`
- **GitHub Danışma (Advisory) URL'si:** `https://github.com/trycua/cua/security/advisories/GHSA-xm8w-gj3g-4f25`
- **Mevcut GHSA Kimliği:** `GHSA-xm8w-gj3g-4f25`
- **Ekosistem:** `pip`
- **Paket Adı:** `cua-bench-rl (ve cua-bench)`
- **Etkilenen Sürümler:** `<= 0.1.0 (cua-bench <= 0.3.1, commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **Yamalı Sürümler:** `Yok (Savunma yaması aşağıda sunulmuştur)`
- **CWE:** `CWE-94 (Kod Üretiminin Hatalı Kontrolü) / CWE-942 (Aşırı İzin Verici Çapraz Alan Adı Beyaz Listesi)`
- **CVSS v3.1:** `8.8 Yüksek (High) — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- **MITRE Üreticisi:** `TryCua`
- **MITRE Zafiyet Türü:** `Wildcard CORS ve Fail-Open IP Filtresi Üzerinden Dinamik Kod Çalıştırma (CWE-94 / CWE-942)`
- **MITRE Etkilenen Bileşen(ler):** `libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py (satır 79-108, 338-360, 499) ve libs/cua-bench/cua_bench/core.py (make, satır 25-51)`
- **MITRE Önerilen CVE Açıklaması (Türkçe Özeti):**
  > TryCua `cua-bench-rl` 0.1.0 ve `cua-bench` 0.3.1 sürümlerine kadar (`trycua/cua`), `worker_server.py` kimlik doğrulaması olmadan `0.0.0.0:8001` portuna bağlanır, `allow_origins=['*']` ile `CORSMiddleware` etkinleştirir ve `127.0.0.1` adresine gelen çapraz kökenli tarayıcı isteklerine izin veren, ayrıca `OSGYM_ALLOWED_IPS` boş dizgeye ayarlandığında tüm uzak IP adreslerine açık kalan (`fail-open`) bir `ip_filter_middleware` kullanır. Bir saldırgan keyfi bir `env_path` parametresiyle `POST /reset` uç noktasını çağırarak `cua_bench.core.make` fonksiyonunun `<env_path>/main.py` dosyasını ana bilgisayar üzerinde `spec.loader.exec_module` aracılığıyla çalıştırmasına neden olabilir.
- **Bildiren / Araştırmacı:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
`trycua/cua` (`cua-bench-rl` `<= 0.1.0` ve `cua-bench` `<= 0.3.1`, commit `e754cfec69c41400eb2aabde716c27d15607b2f0`) içerisindeki `worker_server.py`, pekiştirmeli öğrenme (*Reinforcement Learning*) görevlerini çalıştırmak için FastAPI tabanlı bir HTTP sunucusu başlatır. Ancak ağ erişim kontrolü ve dinamik modül yükleme katmanlarındaki üç hata birleşerek **Uzaktan Dinamik Python Kodu Çalıştırma (`CWE-94` / `CWE-942`)** zafiyeti oluşturmaktadır:

1. **Adım 1 — `CORSMiddleware(allow_origins=["*"])` ve `127.0.0.1` Güven Hatası (`worker_server.py:79-95`):**
   Sunucu `allow_origins=["*"]` ile tüm web sitelerinden gelen tarayıcı isteklerine izin verir. `ip_filter_middleware` yalnızca istemci IP adresinin `127.0.0.1` olup olmadığına bakar ve `Origin` başlığını kontrol etmez. Geliştiricinin tarayıcısından `http://127.0.0.1:8001/reset` adresine yapılan bir `fetch()` isteği yerel makineden geldiği için kaynak IP'si `127.0.0.1` olur ve filtreyi doğrudan geçer.
2. **Adım 2 — Boş `OSGYM_ALLOWED_IPS=""` Durumunda IP Filtresinin Tamamen Devre Dışı Kalması (`worker_server.py:90-103`):**
   Dağıtım şablonlarında `OSGYM_ALLOWED_IPS=""` (boş metin) olarak verildiğinde, `[ip.strip() for ip in allowed_ips if ip.strip()]` listesi boş liste (`[]`) üretir. 102. satırdaki `if allowed_ips and client_ip not in allowed_ips:` koşulunda `bool([])` değeri `False` olduğu için IP kontrolü tamamen atlanır (*fail-open*) ve `0.0.0.0:8001` portu tüm ağdaki cihazlara açılır.
3. **Adım 3 — `POST /reset` İçindeki `request.env_path` Parametresinin `spec.loader.exec_module` ile Doğrudan Çalıştırılması (`worker_server.py:338-360` -> `core.py:25-51`):**
   Kimlik doğrulaması olmayan `POST /reset` uç noktası, gelen JSON içindeki `env_path` dizin yolunu doğrudan `cb.make(request.env_path)` fonksiyonuna gönderir. `cua_bench/core.py:25-51` ise bu dizindeki `<env_path>/main.py` dosyasını `importlib.util.spec_from_file_location` ve `spec.loader.exec_module(module)` ile ana bilgisayarın Python sürecinde doğrudan çalıştırır.

### Zafiyetli Kod Kesiti (`worker_server.py:79-104, 338-349`)
```python
# Dosya: libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py (satır 79-104, 338-349)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # HATA 1: Wildcard CORS her web sitesinden çapraz kökenli POST isteğine izin verir!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
    client_ip = request.client.host if request.client else None
    if allowed_ips and client_ip not in allowed_ips: # HATA 2: allowed_ips == [] olduğunda filtre tamamen devre dışı kalır!
        return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
    return await call_next(request)
...
@app.post("/reset", response_model=ResetResponse)
async def reset_environment(request: ResetRequest):
    env = cb.make(request.env_path, ...) # HATA 3: <env_path>/main.py dosyasını dinamik olarak yükleyip çalıştırır!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Yapay Zeka Araştırmacısının Tarayıcı Sekmesi Üzerinden Yerel RL Sunucusunun Ele Geçirilmesi (`POST /reset` -> `exec_module`)
1. Bir yapay zeka araştırmacısı veya veri bilimci, kendi iş istasyonunda `cua-bench-rl` çalışanını (`127.0.0.1:8001`) başlatır ve aynı anda tarayıcısında veri kümelerini indirir veya model kıyaslama sayfalarında gezinir.
2. Ziyaret edilen bir web sayfası arka planda `fetch("http://127.0.0.1:8001/reset", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ env_path: "/home/community-user/Downloads/untrusted_bundle" }) })` isteği gönderir.
3. İstek yerel döngüden (`127.0.0.1`) geldiği ve CORS `*` olduğu için kabul edilir; `cua_bench.core.make` fonksiyonu `/home/community-user/Downloads/untrusted_bundle/main.py` dosyasını `spec.loader.exec_module` ile anında çalıştırarak araştırmacının makinesinde tam kod çalıştırma yetkisi elde eder.

### Senaryo B — GPU Kümesi / Docker Compose Dağıtımında Boş `OSGYM_ALLOWED_IPS=""` Değişkeni Nedeniyle Tüm Ağa Açılma
1. Paylaşımlı bir GPU kümesinde veya Kubernetes/Docker Compose ortamında `OSGYM_ALLOWED_IPS: ""` ortam değişkeni boş bırakılarak `worker_server.py` başlatılır.
2. `allowed_ips` listesi `[]` olarak hesaplandığı için `if allowed_ips and client_ip not in allowed_ips:` kontrolü tamamen devre dışı kalır ve `0.0.0.0:8001` portu kümedeki diğer tüm konteyner ve düğümlerden erişilebilir hale gelir.
3. Ağdaki herhangi bir düğüm `POST /reset` çağrısı yaparak paylaşımlı NFS/uzak dosya sistemindeki bir `main.py` dosyasını GPU düğümü üzerinde çalıştırabilir.

### Senaryo C — `/screenshot` ve `/step` Uç Noktaları Üzerinden Sessiz Masaüstü Gözetleme ve Klavye/Fare Komutu Enjeksiyonu
1. Saldırgan diske herhangi bir dosya indirmeye gerek duymadan, tarayıcıdaki bir sekmeden veya yerel ağdan `GET http://127.0.0.1:8001/screenshot` uç noktasını periyodik olarak çağırır.
2. Aktif masaüstü oturumunun Base64 kodlu ekran görüntülerini canlı olarak çeker ve `POST /step` uç noktasına klavye/fare eylemleri göndererek açık olan terminal veya uygulamalara doğrudan işletim sistemi komutları yazar.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

### 1. Sniper CLI ile Hedef Bileşenin Denetlenmesi
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py"
```

### 2. İzole Yerel Test Ortamında (`127.0.0.1`) Tetikleme ve Doğrulama
```bash
# Boş OSGYM_ALLOWED_IPS="" değişkeninin nasıl [] üreterek filtreyi devre dışı bıraktığını doğrulayın
python3 -c '
import os
os.environ["OSGYM_ALLOWED_IPS"] = ""
allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
client_ip = "10.20.30.40"
blocked = bool(allowed_ips and client_ip not in allowed_ips)
print({"allowed_ips": allowed_ips, "remote_client_ip": client_ip, "blocked_by_filter": blocked})
'
```

### 3. Otomatik `RED -> GREEN + BENIGN` E2E Doğrulama Testinin Çalıştırılması
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand02
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

Gerçek `cua_bench.core.make` uygulaması üzerinde `python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand02` komutu ile üretilen çalışma zamanı kanıtı:

```json
{
  "CUA-CAND-02": {
    "ghsa_id": "GHSA-xm8w-gj3g-4f25",
    "source_file": "cua/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py",
    "core_file": "cua/libs/cua-bench/cua_bench/core.py",
    "elapsed_ms": 16.323,
    "RED": {
      "cross_origin_reset_status": 200,
      "empty_allowed_ips_remote_lan_status": 200,
      "arbitrary_env_path_exec_module_rce": true
    },
    "GREEN": {
      "cross_origin_reset_status": 403,
      "empty_allowed_ips_remote_lan_status": 403,
      "outside_env_path_status": 400,
      "arbitrary_env_path_exec_module_rce": false
    },
    "BENIGN": {
      "loopback_valid_task_reset_status": 200
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py
+++ b/libs/cua-bench-rl/cua_bench_rl/workers/worker_server.py
@@ -78,12 +78,6 @@
-app.add_middleware(
-    CORSMiddleware,
-    allow_origins=["*"],
-    allow_credentials=True,
-    allow_methods=["*"],
-    allow_headers=["*"],
-)
-
 @app.middleware("http")
 async def ip_filter_middleware(request: Request, call_next):
+    if request.headers.get("origin"):
+        return JSONResponse(status_code=403, content={"detail": "Cross-origin browser requests forbidden"})
     allowed_ips = os.environ.get("OSGYM_ALLOWED_IPS", "127.0.0.1").split(",")
-    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()]
+    allowed_ips = [ip.strip() for ip in allowed_ips if ip.strip()] or ["127.0.0.1"]
@@ -102,3 +96,3 @@
-    if allowed_ips and client_ip not in allowed_ips:
+    if client_ip not in allowed_ips:
         return JSONResponse(status_code=403, content={"detail": f"Access denied for IP: {client_ip}"})
```
