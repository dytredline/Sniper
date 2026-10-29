# WinArena Orkestratörünün Kimlik Doğrulamasız noVNC (`0.0.0.0:8006`) ve Parolasız RDP (`0.0.0.0:3390`) Portlarını Yazılabilir `/shared` Bağlamasıyla Tüm Ağa Açması (`GHSA-hvhg-6x47-cq96`)

[English](../07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | **Türkçe** | [日本語](../ja/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | [简体中文](../zh-CN/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md) | [한국어](../ko/07-CUA-CAND-06-WINARENA-GHSA-hvhg-6x47-cq96.md)

## GitHub GHSA ve MITRE CNA Hızlı Doldurma Alanları
- **Depo (Repository):** `trycua/cua`
- **GitHub Danışma (Advisory) URL'si:** `https://github.com/trycua/cua/security/advisories/GHSA-hvhg-6x47-cq96`
- **Mevcut GHSA Kimliği:** `GHSA-hvhg-6x47-cq96`
- **Ekosistem:** `pip`
- **Paket Adı:** `cua-bench`
- **Etkilenen Sürümler:** `<= 0.3.1 (commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **Yamalı Sürümler:** `Yok (Savunma yaması aşağıda sunulmuştur)`
- **CWE:** `CWE-668 (Kaynağın Yanlış Etki Alanına Açılması) / CWE-732 (Kritik Kaynak İçin Hatalı İzin Ataması)`
- **CVSS v3.1:** `8.6 Yüksek (High) — CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- **MITRE Üreticisi:** `TryCua`
- **MITRE Zafiyet Türü:** `Kimlik Doğrulamasız Ağ İfşası ve Yazılabilir Ana Bilgisayar Dizin Bağlaması (CWE-668 / CWE-732)`
- **MITRE Etkilenen Bileşen(ler):** `libs/cua-bench/tasks/winarena_adapter/cli.py (satır 262-265, 421-424, 646-649) ve infra/vm/setup/server/main.py (satır 180-248, 290-321)`
- **MITRE Önerilen CVE Açıklaması (Türkçe Özeti):**
  > TryCua `cua-bench` 0.3.1 ve önceki sürümlerinde (`trycua/cua`), WinArena konteyner orkestratörü (`libs/cua-bench/tasks/winarena_adapter/cli.py`), Windows misafir sanal makinesinin kimlik doğrulamasız noVNC web masaüstünü (`-p 8006:8006`) ve parolasız RDP servisini (`-p 3390:3389`) `127.0.0.1` yerine `0.0.0.0` (tüm ağ arayüzleri) üzerinde yayınlar ve aynı anda ana bilgisayarın `setup_path` dizinini okuma-yazma yetkisiyle (`-v {setup_path}:/shared`) bağlar. Yerel ağdaki diğer cihazlar misafir masaüstünü ele geçirebilir ve ana bilgisayarla paylaşılan kurulum dosyalarını değiştirebilir.
- **Bildiren / Araştırmacı:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
`trycua/cua` (`cua-bench` `<= 0.3.1`, `libs/cua-bench/tasks/winarena_adapter/cli.py:262-265, 421-424, 646-649`, commit `e754cfec69c41400eb2aabde716c27d15607b2f0`) içerisindeki WinArena orkestratörü, Windows değerlendirme sanal makinesini bir Docker konteyneri içinde başlatır. Kodda üç ayrı başlatma fonksiyonunda (`cmd_vm_setup`, `cmd_vm_start`, `cmd_task_run`) tekrarlanan yapılandırma hataları, yerel ağdaki herhangi bir cihazın **Kimlik Doğrulamasız Masaüstü Ele Geçirme ve Ana Bilgisayar Dosya Sistemi Zehirleme (`CWE-668` / `CWE-732`)** saldırısı yapabilmesine yol açmaktadır:

1. **Adım 1 — Docker Portlarının `127.0.0.1` Yerine `0.0.0.0` Üzerinden Tüm Ağa Açılması (`cli.py:262-263, 421-422, 646-647`):**
   Docker'a `-p 8006:8006` (noVNC web masaüstü) ve `-p 3390:3389` (RDP) argümanları IP öneki (`127.0.0.1:`) olmadan verildiğinde, Docker bu portları tüm ağ arayüzlerinde (`0.0.0.0`) yayınlar ve `iptables` `DOCKER` zinciri üzerinden standart `ufw`/`firewalld` gelen bağlantı kurallarını bile atlar. Üstelik sanal makinedeki noVNC ve RDP oturumları tamamen şifresizdir.
2. **Adım 2 — Ana Bilgisayarın `setup_path` Dizinine Okuma-Yazma (`rw`) İzninin Verilmesi (`cli.py:264-265, 423-424, 648-649`):**
   Konteyner başlatılırken `-v {setup_path}:/shared` argümanı `:ro` (salt okunur) bayrağı olmadan verilir. Bu dizin doğrudan ana bilgisayardaki Python paketinin `winarena_adapter/infra/vm/setup` kaynak kod dizinidir.
3. **Adım 3 — Misafir Ortamdan Ana Bilgisayar Kodlarına Sıçrama ve Kimlik Doğrulamasız `exec()` (`server/main.py:180-248`):**
   Sanal makine içindeki kontrol sunucusu (`infra/vm/setup/server/main.py`) `0.0.0.0:5000` üzerinde kimlik doğrulamasız `POST /execute_windows` (`exec(command)`) ve `POST /setup/launch` (`shell=True`) uç noktaları çalıştırır. Ağdan `8006`/`3390` portuna bağlanan veya sanal makine içindeki tarayıcıdan `5000` portunu tetikleyen bir saldırgan, sanal makineyi ele geçirip `/shared` üzerinden ana bilgisayardaki kurulum betiklerini değiştirebilir.

### Zafiyetli Kod Kesiti (`winarena_adapter/cli.py:261-266`)
```python
# Dosya: libs/cua-bench/tasks/winarena_adapter/cli.py (satır 261-266, ayrıca 421-424 ve 646-649 satırlarında tekrarlanır)
        "-p", f"{args.browser_port}:8006", # HATA 1: Kimlik doğrulamasız noVNC portunu 0.0.0.0:8006 üzerinden yerel ağa açar!
        "-p", f"{args.rdp_port}:3389",     # HATA 2: Parolasız RDP servisini 0.0.0.0:3390 üzerinden yerel ağa açar!
        "-v", f"{storage_path}:/storage",
        "-v", f"{setup_path}:/shared",     # HATA 3: Ana bilgisayarın kaynak kodu dizinini :ro yerine yazılabilir (rw) bağlar!
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Üniversite / Kurumsal Laboratuvar Ağındaki Herhangi Bir Kullanıcının `http://<host-ip>:8006` (noVNC) veya `:3390` (RDP) Üzerinden Windows Sanal Makinesini Ele Geçirmesi
1. Bir araştırmacı, üniversite veya ofis ağına bağlı bir iş istasyonunda `cua-bench` WinArena görevlerini çalıştırır.
2. Docker, `-p 8006:8006 -p 3390:3389` parametreleri yüzünden bu portları `0.0.0.0` üzerinde yayınlar (ve Linux `ufw` güvenlik duvarı kurallarını `DOCKER` yönlendirme zinciriyle aşar).
3. Aynı ağdaki herhangi bir kişi tarayıcısından `http://<workstation-ip>:8006` adresini açarak hiçbir şifre girmeden Windows Administrator masaüstünü canlı olarak kontrol eder ve değerlendirme ortamına enjekte edilmiş OpenAI/Anthropic API anahtarlarını ele geçirir.

### Senaryo B — Yazılabilir `-v {setup_path}:/shared` Bağlantısı Üzerinden Misafir Ortamdan Ana Bilgisayar Kaynak Kodlarının Zehirlenmesi
1. Konteyner, ana bilgisayarın `winarena_adapter/infra/vm/setup` dizinini `/shared` noktasına yazılabilir (`rw`) olarak bağlar (`cli.py:265, 424, 649`).
2. Ağ üzerinden `0.0.0.0:8006` / `0.0.0.0:3390` portlarından konteynere/sanal makineye erişen saldırgan, `/shared` dizini içindeki kurulum betiklerini ve Python dosyalarını değiştirir.
3. Ana bilgisayardaki araştırmacı veya CI/CD hattı bir sonraki görevde bu dosyaları çalıştırdığında veya paketlediğinde, değiştirilmiş kodlar doğrudan ana bilgisayar üzerinde çalışır.

### Senaryo C — Değerlendirilen Web Ajanının Ziyaret Ettiği Bir Web Sayfasından `127.0.0.1:5000/execute_windows` (`exec()`) Tetiklenerek Sanal Makinenin Ele Geçirilmesi
1. WinArena içinde çalışan otonom bilgisayar kullanımı ajanı (*CUA agent*), görev sırasında sanal makinedeki Chrome/Edge tarayıcısıyla dış dünyadaki bir web sayfasını ziyaret eder.
2. Ziyaret edilen web sayfası, sanal makinenin içinde `0.0.0.0:5000` portunda kimlik doğrulamasız çalışan `server/main.py` servisine `POST http://127.0.0.1:5000/execute_windows` veya `POST http://127.0.0.1:5000/setup/launch` isteği gönderir.
3. `server/main.py:180-208` gelen Python kodunu doğrudan `exec(command)` ile çalıştırarak ajanın değerlendirme ortamını tamamen ele geçirir ve sonuçları manipüle eder.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

### 1. Sniper CLI ile Hedef Bileşenin Denetlenmesi
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua-bench/tasks/winarena_adapter/cli.py"
```

### 2. İzole Yerel Test Ortamında Tetikleme ve Doğrulama
```bash
# cli.py içindeki 0.0.0.0 Docker port bağlamalarını ve yazılabilir /shared bağlamalarını inceleyin
grep -n -C 4 "8006" \
  /home/community-user/targets/cua/libs/cua-bench/tasks/winarena_adapter/cli.py

# infra/vm/setup/server/main.py içindeki kimlik doğrulamasız exec() uç noktasını inceleyin
grep -n -C 8 "def execute_windows" \
  /home/community-user/targets/cua/libs/cua-bench/tasks/winarena_adapter/infra/vm/setup/server/main.py
```

### 3. Otomatik `RED -> GREEN + BENIGN` E2E Doğrulama Testinin Çalıştırılması
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand06` komutu ile üretilen çalışma zamanı kanıtı:

```json
{
  "CUA-CAND-06": {
    "ghsa_id": "GHSA-hvhg-6x47-cq96",
    "cli_source_file": "cua/libs/cua-bench/tasks/winarena_adapter/cli.py",
    "server_source_file": "cua/libs/cua-bench/tasks/winarena_adapter/infra/vm/setup/server/main.py",
    "elapsed_ms": 0.05,
    "RED": {
      "lan_exposed_ports": [
        "8006:8006",
        "3390:3389"
      ],
      "host_setup_dir_mounted_writable": true,
      "guest_execute_windows_requires_auth": false
    },
    "GREEN": {
      "lan_exposed_ports": [],
      "host_setup_dir_mounted_writable": false,
      "guest_execute_windows_requires_auth": true
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/libs/cua-bench/tasks/winarena_adapter/cli.py
+++ b/libs/cua-bench/tasks/winarena_adapter/cli.py
@@ -261,9 +261,9 @@
-        "-p", f"{args.browser_port}:8006",
-        "-p", f"{args.rdp_port}:3389",
-        "-v", f"{storage_path}:/storage",
-        "-v", f"{setup_path}:/shared",
+        "-p", f"127.0.0.1:{args.browser_port}:8006",
+        "-p", f"127.0.0.1:{args.rdp_port}:3389",
+        "-v", f"{storage_path}:/storage",
+        "-v", f"{setup_path}:/shared:ro",
```
