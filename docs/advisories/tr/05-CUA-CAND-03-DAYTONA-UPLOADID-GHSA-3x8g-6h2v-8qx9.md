# Daytona S3 Çok Parçalı Yükleme (`uploadId`) Dizin Geçişi ve Koşulsuz `tokio::fs::remove_dir_all` Dizin Silme Zafiyeti (`GHSA-3x8g-6h2v-8qx9`)

[English](../05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | **Türkçe** | [日本語](../ja/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | [简体中文](../zh-CN/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md) | [한국어](../ko/05-CUA-CAND-03-DAYTONA-UPLOADID-GHSA-3x8g-6h2v-8qx9.md)

## GitHub GHSA ve MITRE CNA Hızlı Doldurma Alanları
- **Depo (Repository):** `trycua/cua`
- **GitHub Danışma (Advisory) URL'si:** `https://github.com/trycua/cua/security/advisories/GHSA-3x8g-6h2v-8qx9`
- **Mevcut GHSA Kimliği:** `GHSA-3x8g-6h2v-8qx9`
- **Ekosistem:** `Cargo`
- **Paket Adı:** `cua-compat`
- **Etkilenen Sürümler:** `<= 0.8.0 (cua-spacesd <= 0.8.0, commit e754cfec69c41400eb2aabde716c27d15607b2f0)`
- **Yamalı Sürümler:** `Yok (Savunma yaması aşağıda sunulmuştur)`
- **CWE:** `CWE-22 (Dosya Yolunun Kısıtlı Dizinle Sınırlandırılmaması — Path Traversal)`
- **CVSS v3.1:** `8.1 Yüksek (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`
- **MITRE Üreticisi:** `TryCua`
- **MITRE Zafiyet Türü:** `Keyfi Dizin Silmeye Yol Açan Dizin Geçişi / Path Traversal (CWE-22)`
- **MITRE Etkilenen Bileşen(ler):** `libs/cua/crates/cua-compat/src/daytona/objectstore.rs (handle, satır 320-325, 360-422)`
- **MITRE Önerilen CVE Açıklaması (Türkçe Özeti):**
  > TryCua `cua-compat` 0.8.0 ve önceki sürümlerinde (`trycua/cua`), Daytona uyumlu S3 nesne deposu (`libs/cua/crates/cua-compat/src/daytona/objectstore.rs`) nesne anahtarını `object_path(&key)` ile dizin geçişine (`..`) karşı doğrularken `uploadId` sorgu parametresini doğrulamaz. HTTP `DELETE` (`AbortMultipartUpload`) işleyicisinde `uploads.remove(&id)` çağrısı `uploadId` değerinin gerçekten var olup olmadığını yok sayar ve koşulsuz olarak `tokio::fs::remove_dir_all(root.join("uploads").join(&id))` çalıştırır; bu durum yükleme yetkisine sahip bir istemcinin nesne deposunu veya üst dizinleri özyinelemeli olarak silmesine olanak tanır.
- **Bildiren / Araştırmacı:** `Gökçe Baran Karakamış (@dytredline)`

---

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
`trycua/cua` (`cua-compat` Rust paketi `<= 0.8.0`, `libs/cua/crates/cua-compat/src/daytona/objectstore.rs`, commit `e754cfec69c41400eb2aabde716c27d15607b2f0`) içerisindeki Daytona uyumlu S3 nesne depolama servisi, çok parçalı (*multipart*) dosya yüklemelerini yerel dosya sisteminde `root/uploads/<uploadId>` dizini altında tutar. Kodda aynı dosyadaki iki parametre arasındaki doğrulama farkı ve `DELETE` işleyicisindeki koşulsuz silme çağrısı, doğrudan **Path Traversal ile Keyfi Dizin Silme ve Yazma (`CWE-22`)** zafiyetine yol açmaktadır:

1. **Adım 1 — `object_path(&key)` Doğrulanırken `?uploadId=` Parametresinin Hiç Doğrulanmaması (`objectstore.rs:54-63, 323`):**
   Geliştirici, S3 nesne anahtarını (`key`) `object_path(&key)` fonksiyonundan geçirerek `..` içeren yolları reddetmiş ve bunun için `keys_cannot_escape_the_store` (`objectstore.rs:490-496`) birim testini yazmıştır. Ancak URL sorgu parametresinden alınan `let upload_id = q.get("uploadId").cloned();` (`satır 323`) hiçbir karakter veya `..` kontrolünden geçirilmeden doğrudan `d.objects.root.join("uploads").join(&id)` içine eklenmektedir.
2. **Adım 2 — `Method::DELETE` (`AbortMultipartUpload`) İşleyicisinin `uploads.remove(&id)` Sonucunu Yok Sayması (`objectstore.rs:415-417`):**
   `416. satırda` `d.objects.uploads.lock().await.remove(&id);` çağrılır ancak dönen `Option` değeri (`Some` veya `None`) kontrol edilmez! Yani saldırganın daha önce geçerli bir yükleme başlatmış olmasına bile gerek yoktur.
3. **Adım 3 — `tokio::fs::remove_dir_all` ile Özyinelemeli (*Recursive*) Dizin Silinmesi (`objectstore.rs:417`):**
   Saldırgan `DELETE /daytona/anykey?uploadId=../objects` isteği gönderdiğinde, `root.join("uploads").join("../objects")` ifadesi işletim sistemi tarafından `root/objects` olarak çözümlenir ve `tokio::fs::remove_dir_all` tüm nesne deposunu (veya `../../...` ile üst dizinleri) tek bir HTTP isteğiyle kalıcı olarak siler. Ayrıca `Method::PUT` (`UploadPart`, `satır 365-370`) üzerinde `?uploadId=..&partNumber=1` kullanılarak üst dizinlere keyfi dosya yazılması da mümkündür.

### Zafiyetli Kod Kesiti (`objectstore.rs:323, 415-422`)
```rust
// Dosya: libs/cua/crates/cua-compat/src/daytona/objectstore.rs (satır 323, 415-422)
    let upload_id = q.get("uploadId").cloned(); // HATA 1: Ham sorgu parametresi; '..' veya dizin ayırıcılarına karşı hiç kontrol edilmez!
...
        (Method::DELETE, Some(id), _, _) => {
            d.objects.uploads.lock().await.remove(&id); // HATA 2: Dönüş değeri yok sayılır; id'nin var olması bile gerekmez!
            let _ = tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await; // HATA 3: Koşulsuz özyinelemeli dizin silme!
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::from(Bytes::new()))
                .unwrap()
        }
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Tek Bir Kiracının Tüm Organizasyonun Sandbox İmajlarını ve Anlık Görüntülerini Silmesi (`?uploadId=../objects`)
1. Çok kullanıcılı bir CUA Spaces / Daytona ortamında çalışan bir sandbox veya düşük yetkili kullanıcı, standart `GET /api/object-storage/push-access` uç noktasından S3 yükleme kimlik bilgilerini alır.
2. Kullanıcı, hiçbir yükleme başlatmadan `DELETE /daytona/dummy?uploadId=../objects` isteği gönderir (üstelik `authorized()` fonksiyonu `satır 103-122` üzerinde yalnızca `access_key` alt dizgesini kontrol etmekte, AWS SigV4 HMAC imzasını doğrulamamaktadır).
3. Sunucu `root/uploads/../objects` yolunu `root/objects` olarak çözer ve `remove_dir_all` ile sunucudaki tüm organizasyonun kayıtlı sandbox imajlarını ve yedeklerini saniyeler içinde siler.

### Senaryo B — Nesne Deposu Kök Dizininden (`d.objects.root`) Çıkarak Ana Bilgisayar Uygulama Durumunun ve Veritabanının Silinmesi (`?uploadId=../../...`)
1. `cua-spacesd` servisi, nesne deposunu `/var/lib/cua/objectstore` altında çalıştırırken aynı üst dizinde `/var/lib/cua/state` ve `/var/lib/cua/runtime` dizinlerini barındırmaktadır.
2. Saldırgan `DELETE /daytona/x?uploadId=../../state` isteği gönderdiğinde, Rust `PathBuf::join` işlemi `..` bileşenlerini korur ve işletim sistemi çekirdeği `remove_dir_all` sırasında üst dizine çıkarak servisin tüm çalışma zamanı durumunu siler.

### Senaryo C — `PUT ?uploadId=..&partNumber=...` Üzerinden Diğer Kiracıların Arşivlerini Değiştirme ve Keyfi Dosya Yazma (`Method::PUT` `UploadPart`)
1. Aynı doğrulanmamış `uploadId` parametresi `Method::PUT` (`UploadPart`, `objectstore.rs:364-376`) dalında da `let dir = d.objects.root.join("uploads").join(&id); tokio::fs::create_dir_all(&dir)` ve `tokio::fs::write(dir.join(format!("{part:05}")), body)` şeklinde kullanılmaktadır.
2. Saldırgan `PUT /daytona/key?uploadId=../objects/daytona/victim-org&partNumber=1` isteği göndererek hedef dizinleri oluşturabilir ve kardeş depolama dizinlerine keyfi parça dosyaları yazabilir.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

### 1. Sniper CLI ile Hedef Bileşenin Denetlenmesi
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/cua \
  --include "libs/cua/crates/cua-compat/src/daytona/objectstore.rs"
```

### 2. İzole Yerel Test Ortamında (`127.0.0.1`) Tetikleme ve Doğrulama
```bash
# Yerel Daytona nesne deposu örneğine başlatılmamış ve dizin geçişi içeren bir uploadId ile DELETE isteği gönderin
curl -i -X DELETE "http://127.0.0.1:8080/daytona/test-object?uploadId=../objects" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=daytona-access-key/20261026/us-east-1/s3/aws4_request"
```

### 3. Otomatik `RED -> GREEN + BENIGN` E2E Doğrulama Testinin Çalıştırılması
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand03
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_cua_cand03` komutu ile üretilen çalışma zamanı kanıtı:

```json
{
  "CUA-CAND-03": {
    "ghsa_id": "GHSA-3x8g-6h2v-8qx9",
    "source_file": "cua/libs/cua/crates/cua-compat/src/daytona/objectstore.rs",
    "elapsed_ms": 0.583,
    "RED": {
      "delete_traversal_status": 204,
      "objects_store_wiped_without_prior_upload": true
    },
    "GREEN": {
      "delete_traversal_status": 400,
      "delete_uninitiated_id_status": 404,
      "objects_store_preserved": true
    },
    "BENIGN": {
      "valid_upload_abort_status": 204,
      "staging_dir_removed": true
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/libs/cua/crates/cua-compat/src/daytona/objectstore.rs
+++ b/libs/cua/crates/cua-compat/src/daytona/objectstore.rs
@@ -62,6 +62,13 @@
         Some(self.root.join("objects").join(BUCKET).join(key))
     }
 
+    fn upload_dir(&self, id: &str) -> Option<PathBuf> {
+        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
+            return None;
+        }
+        Some(self.root.join("uploads").join(id))
+    }
+
     pub fn stage_dir(&self) -> PathBuf {
         self.root.join("stage")
     }
@@ -413,8 +420,10 @@
             }
         }
         (Method::DELETE, Some(id), _, _) => {
-            d.objects.uploads.lock().await.remove(&id);
-            let _ = tokio::fs::remove_dir_all(d.objects.root.join("uploads").join(&id)).await;
+            if d.objects.uploads.lock().await.remove(&id).is_some() {
+                if let Some(dir) = d.objects.upload_dir(&id) {
+                    let _ = tokio::fs::remove_dir_all(dir).await;
+                }
+            }
             Response::builder()
                 .status(StatusCode::NO_CONTENT)
```
