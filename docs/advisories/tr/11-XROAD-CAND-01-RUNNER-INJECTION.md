# Kalıcı Self-Hosted Runner (`xrd-runner-8c`) Üzerinde `_build-and-package.yml` İçinde `github.head_ref` Bash Betiği Enjeksiyonu (`GHSA-4fcw-7xqx-fjv5`)

[English](../11-XROAD-CAND-01-RUNNER-INJECTION.md) | **Türkçe** | [日本語](../ja/11-XROAD-CAND-01-RUNNER-INJECTION.md) | [简体中文](../zh-CN/11-XROAD-CAND-01-RUNNER-INJECTION.md) | [한국어](../ko/11-XROAD-CAND-01-RUNNER-INJECTION.md)

## 1. Açığın Özeti ve Kodda Nasıl Zafiyete Dönüştüğü (`Herkesin Anlayabileceği Adım Adım Teknik Mekanizma`)

### Adım Adım Teknik Mekanizma
`nordic-institute/X-Road` (commit `38cd99ec0ebbcc13ddbaaeb9187018d49bdd278b`) içerisindeki `.github/workflows/build.yaml:14-58` iş akışı, her `pull_request` tetiklendiğinde `permissions: contents: write, packages: write` ve `secrets: inherit` yetkileriyle `.github/workflows/_build-and-package.yml` dosyasını çağırır. Bu iş akışı, geçici (*ephemeral*) bir sanal makine yerine kurumun kendi kalıcı sunucusu olan **`xrd-runner-8c` (`self-hosted runner`)** üzerinde çalışmaktadır. `_build-and-package.yml:84-91` satırlarındaki şablon genişletme hatası doğrudan **Kalıcı Self-Hosted Runner Üzerinde İşletim Sistemi Komut Enjeksiyonu (`CWE-78`)** zafiyetine yol açmaktadır:

1. **Adım 1 — GitHub Actions `${{ github.head_ref }}` İfadesinin Bash Betiği Çalışmadan Önce Metin Olarak Genişletilmesi (`_build-and-package.yml:86-90`):**
   GitHub Actions, `run: |` bloğu içindeki `${{ github.head_ref }}` ve `${{ github.ref_name }}` ifadelerini Bash kabuğunu başlatmadan önce bir ön-işlemci (*preprocessor*) gibi doğrudan metin olarak yerine yazar.
2. **Adım 2 — Özel Karakter İçeren Dal (*Branch*) Adıyla Çift Tırnak (`"`) Bağlamından Kaçış:**
   Saldırgan veya PR açan bir kullanıcı dal adını `feat";id;#` olarak belirlediğinde, `87. satırdaki` `branch_name="${{ github.head_ref }}"` satırı Bash'e gönderilmeden önce `branch_name="feat";id;#"` haline dönüşür.
3. **Adım 3 — `xrd-runner-8c` Kalıcı Sunucusunda `secrets: inherit` ve `packages: write` Yetkileriyle Komut Çalıştırılması (`build.yaml:50-58`, `_build-and-package.yml:27`):**
   Bash betiği bu satırı çalıştırdığı anda `id` (veya saldırganın verdiği herhangi bir kabuk komutu) doğrudan `xrd-runner-8c` sunucusunda çalışır; üstelik bu adım kod incelemesinden önce çalışmakta ve aynı depodan veya onaylanan PR'lardan gelen çalışmalarda `packages: write` / `contents: write` yetkili `GITHUB_TOKEN` ile miras alınan tüm sırları (`secrets: inherit`) açıkta bırakmaktadır.

### Zafiyetli Kod Kesiti (`.github/workflows/_build-and-package.yml:26-27, 84-91`)
```yaml
# Dosya: .github/workflows/_build-and-package.yml (satır 26-27, 84-91)
    runs-on:
      labels: xrd-runner-8c # Kalıcı (persistent) self-hosted runner sunucu filosu
...
          get_branch_name() {
            local branch_name=""
            if [[ -n "${{ github.head_ref }}" ]]; then # HATA 1: Doğrudan bash betiğinin içine YAML şablon genişletmesi!
              branch_name="${{ github.head_ref }}"     # HATA 2: Dal adı "..." dışına çıkarak doğrudan kabuk komutu çalıştırır!
              echo "🔍 Using PR source branch: ${branch_name}" >&2
            elif [[ -n "${{ github.ref_name }}" ]]; then
              branch_name="${{ github.ref_name }}"
```

---

## 2. Günlük Hayatta Yol Açabileceği Kritik Senaryolar (`Senaryo A` / `Senaryo B` / `Senaryo C`)

### Senaryo A — Özel Oluşturulmuş PR Dal Adıyla (`feat";...;#`) Kod İncelemesinden Önce `xrd-runner-8c` Üzerinde Komut Çalıştırılması
1. PR iş akışını tetikleme yetkisine sahip bir katılımcı veya ele geçirilmiş bir geliştirici hesabı, yalnızca dal adı `feat";<komut>;#` olan ve kodda hiçbir şüpheli değişiklik içermeyen (örneğin bir `README.md` yazım hatası düzeltmesi) bir Pull Request açar.
2. Kod inceleyicileri PR'daki dosya farklarına (`Files changed`) baktığında yalnızca masum bir metin değişikliği görür.
3. Ancak `Setup build configuration` adımı çalıştığı anda `${{ github.head_ref }}` dal adı Bash betiğinin içine genişletilir ve kabuk komutu doğrudan `xrd-runner-8c` sunucusunda çalışır.

### Senaryo B — `secrets: inherit` ile Aktarılan Sırların ve `packages: write` Yetkili `GITHUB_TOKEN` Anahtarının Sızdırılması
1. `build.yaml:50-58`, `_build-and-package.yml` iş akışını `permissions: contents: write, packages: write` ve `secrets: inherit` ile çağırır.
2. Enjekte edilen kabuk komutu, çalışma zamanı ortamından (`env` / `/proc/self/environ`) `GITHUB_TOKEN` anahtarını ve miras alınan tüm kurumsal sırları okur.
3. Saldırgan elde ettiği `packages: write` ve `contents: write` yetkili anahtarla X-Road'un GitHub Container Registry (GHCR) paketlerine veya depo dallarına yetkisiz yazma işlemi yapabilir.

### Senaryo C — Kalıcı `xrd-runner-8c` Sunucusundaki Gradle/Docker Önbelleğinin Zehirlenmesiyle Sonraki Resmi X-Road Derlemelerine Sızılması
1. `xrd-runner-8c`, GitHub'ın her iş sonunda silinen geçici sanal makinelerinden biri değil, kalıcı bir `self-hosted runner` sunucusudur.
2. Enjekte edilen komut, sunucu üzerinde arka planda çalışan kalıcı bir süreç bırakabilir veya yerel Gradle/Docker/APT derleme önbelleklerini değiştirilmiş ikili dosyalarla zehirleyebilir.
3. Böylece daha sonra `main`/`develop` dalında çalışan resmi X-Road paket derlemeleri (`deb`/`rpm`/Docker imajları) bu zehirlenmiş önbelleği kullanarak tedarik zinciri (*supply-chain*) saldırısına maruz kalır.

---

## 3. Örnek Çalıştırma, Tetikleme ve Doğrulama Komutları

### 1. Sniper CLI ile Hedef Bileşenin Denetlenmesi
```bash
python3 scripts/sniper-project-audit \
  --repo-path /home/community-user/targets/X-Road \
  --include ".github/workflows/_build-and-package.yml"
```

### 2. İzole Yerel Test Ortamında (`Bash`) Tetikleme ve Doğrulama
```bash
# github.head_ref şablon genişletmesinin çift tırnaktan nasıl kaçtığını ve ortam değişkeni parametrelendirmesinin nasıl koruduğunu doğrulayın
bash -c '
HEAD_REF="feat\";echo INJECTED_ON_RUNNER >&2;#"
echo "--- [RED] Zafiyetli dogrudan sablon genisletmesi ---"
eval "if [[ -n \"${HEAD_REF}\" ]]; then branch_name=\"${HEAD_REF}\"; fi"

echo "--- [GREEN] Yamali ortam degiskeni parametrelendirmesi ---"
PR_HEAD_REF="$HEAD_REF" bash -c '\''if [[ -n "${PR_HEAD_REF}" ]]; then branch_name="${PR_HEAD_REF}"; echo "Guvenli metin branch_name=${branch_name}"; fi'\''
'
```

### 3. Otomatik `RED -> GREEN + BENIGN` E2E Doğrulama Testinin Çalıştırılması
```bash
python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01
```

---

## 4. Uçtan Uca Çalışma Zamanı Kanıtı (`RED -> GREEN + BENIGN`) ve Savunma Yaması

`python3 pre-submission-verification-20261026/tests/test_other_repos_and_cua_real_world_impact_e2e.py -k test_xroad_cand01` komutu ile üretilen çalışma zamanı kanıtı:

```json
{
  "XROAD-CAND-01": {
    "ghsa_id": "GHSA-4fcw-7xqx-fjv5",
    "build_workflow": "x-road/.github/workflows/build.yaml",
    "package_workflow": "x-road/.github/workflows/_build-and-package.yml",
    "elapsed_ms": 5.513,
    "RED": {
      "direct_yaml_interpolation": true,
      "arbitrary_command_executed_on_self_hosted_runner": true
    },
    "GREEN": {
      "env_var_parameterized": true,
      "arbitrary_command_executed_on_self_hosted_runner": false
    }
  }
}
```

### Birleştirilmiş Savunma Yaması (`git apply --check` temiz)
```diff
--- a/.github/workflows/_build-and-package.yml
+++ b/.github/workflows/_build-and-package.yml
@@ -72,6 +72,9 @@
       - name: Setup build configuration
         id: build-config
         working-directory: ./src
+        env:
+          PR_HEAD_REF: ${{ github.head_ref }}
+          GIT_REF_NAME: ${{ github.ref_name }}
         run: |
@@ -84,11 +87,11 @@
           get_branch_name() {
             local branch_name=""
-            if [[ -n "${{ github.head_ref }}" ]]; then
-              branch_name="${{ github.head_ref }}"
+            if [[ -n "${PR_HEAD_REF}" ]]; then
+              branch_name="${PR_HEAD_REF}"
               echo "🔍 Using PR source branch: ${branch_name}" >&2
-            elif [[ -n "${{ github.ref_name }}" ]]; then
-              branch_name="${{ github.ref_name }}"
+            elif [[ -n "${GIT_REF_NAME}" ]]; then
+              branch_name="${GIT_REF_NAME}"
```
