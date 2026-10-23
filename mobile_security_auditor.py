from __future__ import annotations

from contextlib import contextmanager
import hashlib
import io
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterator
import zipfile

from project_analyzer import ProjectRejected, _allowed_roots, validate_project_path
from project_tree import ProjectTree, ProjectTreeError
from scanner import calculate_score
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


SUPPORTED_APP_PROFILES: tuple[str, ...] = (
    "all",
    "finance",
    "ecommerce",
    "health",
    "social",
    "enterprise",
    "gaming",
)

MASVS_CONTROLS: dict[str, dict[str, str]] = {
    "MASVS-STORAGE": {
        "id": "MASVS-STORAGE",
        "title": "Yerel Veri Saklama ve Mahremiyet Koruması",
        "description": "SharedPreferences, UserDefaults, SQLite/Room/Realm, yedekleme (allowBackup), ekran görüntüsü ve log sızıntılarının önlenmesi.",
    },
    "MASVS-CRYPTO": {
        "id": "MASVS-CRYPTO",
        "title": "Kriptografi ve Gömülü Sır Yönetimi",
        "description": "Gömülü API/Firebase/AWS/Stripe/OAuth anahtarlarının önlenmesi, güçlü şifreleme (AES-GCM), güvenli IV/Salt ve PRNG kullanımı.",
    },
    "MASVS-AUTH": {
        "id": "MASVS-AUTH",
        "title": "Kimlik Doğrulama, Biyometri ve Sunucu Tarafı Yetkilendirme",
        "description": "CryptoObject/SecAccessControl tabanlı biyometri, OAuth PKCE S256 ve rol/fiyat/indirim/VIP kontrollerinin sunucuda yapılması.",
    },
    "MASVS-NETWORK": {
        "id": "MASVS-NETWORK",
        "title": "Ağ İletişimi, TLS ve Sertifika Sabitleme (SSL Pinning)",
        "description": "Cleartext HTTP engeli, güvenli ATS/Network Security Config, geçerli TLS doğrulaması ve sertifika sabitleme.",
    },
    "MASVS-PLATFORM": {
        "id": "MASVS-PLATFORM",
        "title": "Platform Entegrasyonu, IPC, Deep Link, WebView ve Ekran Koruması",
        "description": "Exported bileşenler, PendingIntent, Deep Link autoVerify, güvenli WebView, Tapjacking, Pano ve kilit ekranı bildirim güvenliği.",
    },
    "MASVS-CODE": {
        "id": "MASVS-CODE",
        "title": "Kod Kalitesi, İzin Hijyeni ve Tedarik Zinciri (Üçüncü Taraf SDK)",
        "description": "Tehlikeli mobil izinlerin sınırlandırılması ve üçüncü taraf SDK/bağımlılık sürümlerinin sabitlenmesi.",
    },
    "MASVS-RESILIENCE": {
        "id": "MASVS-RESILIENCE",
        "title": "Tersine Mühendislik, Root/Jailbreak ve Manipülasyon Dayanıklılığı",
        "description": "Debuggable/get-task-allow kapama, ProGuard/R8 küçültme, Root/Jailbreak/Frida tespiti ve sunucu doğrulanmış IAP/oyun ekonomisi.",
    },
    "MASVS-PRIVACY": {
        "id": "MASVS-PRIVACY",
        "title": "Kullanıcı Gizliliği, KVKK/GDPR, Privacy Manifest ve BLE Güvenliği",
        "description": "iOS PrivacyInfo.xcprivacy bildirimi, izleme (IDFA) sınırları ve sağlık/BLE cihaz iletişiminde şifreli eşleşme.",
    },
}

MOBILE_TOP_10_2024: dict[str, str] = {
    "M1": "M1:2024 Uygunsuz Kimlik Bilgisi ve Sır Kullanımı",
    "M2": "M2:2024 Yetersiz Tedarik Zinciri Güvenliği",
    "M3": "M3:2024 Güvensiz Kimlik Doğrulama ve Yetkilendirme",
    "M4": "M4:2024 Yetersiz Girdi/Çıktı Doğrulaması (IPC/Deep Link/WebView)",
    "M5": "M5:2024 Güvensiz İletişim (Cleartext/TLS/Pinning)",
    "M6": "M6:2024 Yetersiz Gizlilik Kontrolleri (KVKK/Privacy/BLE)",
    "M7": "M7:2024 Yetersiz İkili (Binary) ve Tersine Mühendislik Korumaları",
    "M8": "M8:2024 Güvenlik Yanlış Yapılandırması (Manifest/ATS/Backup)",
    "M9": "M9:2024 Güvensiz Veri Saklama",
    "M10": "M10:2024 Yetersiz Kriptografi",
}

DANGEROUS_ANDROID_PERMISSIONS: tuple[tuple[str, str, str], ...] = (
    ("android.permission.READ_SMS", "high", "SMS okuma izni (OTP/2FA sızıntı riski)"),
    ("android.permission.RECEIVE_SMS", "high", "SMS alma izni (OTP yakalama riski)"),
    ("android.permission.READ_CALL_LOG", "medium", "Arama kaydı okuma izni"),
    ("android.permission.READ_CONTACTS", "low", "Rehber okuma izni"),
    ("android.permission.ACCESS_BACKGROUND_LOCATION", "medium", "Arka planda sürekli konum izleme izni"),
    ("android.permission.QUERY_ALL_PACKAGES", "medium", "Cihazdaki tüm yüklü uygulamaları sorgulama izni"),
    ("android.permission.SYSTEM_ALERT_WINDOW", "high", "Ekran üstü katman (Overlay / Tapjacking) izni"),
    ("android.permission.BIND_ACCESSIBILITY_SERVICE", "critical", "Erişilebilirlik servisi bağlama izni (tam ekran/girdi kontrolü)"),
    ("android.permission.REQUEST_INSTALL_PACKAGES", "high", "Harici APK paket yükleme izni"),
)

MOBILE_SOURCE_EXTENSIONS: set[str] = {
    ".kt", ".kts", ".java", ".swift", ".m", ".mm",
    ".dart", ".js", ".jsx", ".ts", ".tsx", ".cs",
}

MOBILE_CONFIG_FILENAMES: set[str] = {
    "androidmanifest.xml",
    "network_security_config.xml",
    "info.plist",
    "entitlements.plist",
    "privacyinfo.xcprivacy",
    "googleservice-info.plist",
    "google-services.json",
    "build.gradle",
    "build.gradle.kts",
    "pubspec.yaml",
    "package.json",
    "podfile",
}


@contextmanager
def _opened_project_tree(root: Path) -> Iterator[ProjectTree]:
    try:
        with ProjectTree(str(root)) as tree:
            yield tree
    except ProjectTreeError as exc:
        raise ProjectRejected("Proje ağacı güvenli biçimde okunamadı.") from exc


MAX_PACKAGE_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_000
MAX_UNCOMPRESSED_BYTES = 250 * 1024 * 1024

# Pattern tuple: (rule_id, severity, masvs, m_top10, domains, title, description, recommendation, regex)
SOURCE_RULES: tuple[tuple[str, str, str, str, tuple[str, ...], str, str, str, str], ...] = (
    # A. MASVS-STORAGE & M9
    (
        "SNIPER-MOB-STOR-01",
        "high",
        "MASVS-STORAGE",
        "M9",
        ("all", "finance", "ecommerce", "social", "enterprise"),
        "Şifresiz yerel depolamada (SharedPreferences / UserDefaults) hassas veri saklama",
        "Oturum jetonu, parola veya anahtar bilgisi EncryptedSharedPreferences / Keychain yerine düz metin yerel depoya yazılıyor.",
        "Android'de EncryptedSharedPreferences/Keystore, iOS'ta Keychain (kSecAttrAccessibleWhenUnlockedThisDeviceOnly) kullanın.",
        r"(?:getSharedPreferences|PreferenceManager\.getDefaultSharedPreferences|UserDefaults\.standard|AsyncStorage\.setItem|SharedPreferences\.getInstance)[^\n]{0,120}(?:token|password|secret|pin|jwt|apikey|card|cvv|iban)",
    ),
    (
        "SNIPER-MOB-STOR-02",
        "medium",
        "MASVS-STORAGE",
        "M9",
        ("all", "health", "finance", "enterprise"),
        "Harici (External) depolama alanına veri yazımı",
        "Uygulama diğer süreçler veya yedekleme araçları tarafından erişilebilen harici depolama API'lerini kullanıyor.",
        "Hassas dosyaları yalnızca uygulama içi korumalı dizinde şifrelenmiş olarak saklayın.",
        r"\b(?:getExternalStorageDirectory|getExternalStoragePublicDirectory|getExternalFilesDir|MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)\b",
    ),
    (
        "SNIPER-MOB-STOR-03",
        "low",
        "MASVS-STORAGE",
        "M9",
        ("all", "finance", "health", "social"),
        "Üretim kodunda konsol/sistem günlüğüne (Logcat / print / NSLog) hassas veri yazımı",
        "Hassas kimlik veya oturum verileri cihaz günlüklerine yazılıyor.",
        "Üretim derlemelerinde hassas log çağrılarını kaldırın veya ProGuard/R8 kurallarıyla temizleyin.",
        r"\b(?:Log\.[dveiw]|NSLog|debugPrint|console\.log)\s*\([^\n]{0,120}(?:token|password|secret|otp|pin|iban|cvv|ssn|tc_kimlik)",
    ),
    (
        "SNIPER-MOB-STOR-04",
        "medium",
        "MASVS-STORAGE",
        "M9",
        ("all", "finance", "health"),
        "SQLite / Room / Realm veritabanında şifreleme (SQLCipher) eksikliği",
        "Yerel veritabanı bağlantı çağrısında şifreleme anahtarı veya SQLCipher/encryptionKey yapılandırması gözlenmedi.",
        "Yerel veritabanlarını SQLCipher (SupportFactory) veya Realm encryptionKey ile şifreleyin.",
        r"\b(?:Room\.databaseBuilder|openOrCreateDatabase|SQLiteDatabase\.openDatabase)\s*\((?![^\)]{0,200}(?:SupportFactory|cipher|encrypt))",
    ),
    # B. MASVS-CRYPTO & M1 / M10
    (
        "SNIPER-MOB-CRYP-01",
        "critical",
        "MASVS-CRYPTO",
        "M1",
        ("all", "finance", "ecommerce", "health", "social", "enterprise", "gaming"),
        "Mobil kaynak kodunda gömülü API / Bulut / Ödeme anahtarı",
        "Uygulama ikilisi tersine mühendislikle (jadx/strings) incelendiğinde doğrudan çıkarılabilecek gömülü sır tespit edildi.",
        "Sırları istemci paketinden kaldırın; kısa ömürlü jetonlarla arka uç (backend) üzerinden aracılık yapın.",
        r"(?:AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{16,}|rk_live_[0-9a-zA-Z]{16,}|ghp_[0-9A-Za-z]{30,})",
    ),
    (
        "SNIPER-MOB-CRYP-02",
        "high",
        "MASVS-CRYPTO",
        "M10",
        ("all", "finance", "enterprise", "health"),
        "Zayıf simetrik şifreleme kipi (AES/ECB, DES, 3DES, RC4) veya kırık özet (MD5/SHA-1)",
        "Mobil kriptografi katmanında bütünlük koruması olmayan ECB kipi veya zayıf algoritma kullanılıyor.",
        "Simetrik şifrelemede yalnızca AES/GCM/NoPadding ve anahtar türetmede PBKDF2/Argon2id kullanın.",
        r"(?:AES/ECB/|Cipher\.getInstance\(\s*[\"'](?:AES|DES|DESede|RC4)[\"']\s*\)|MessageDigest\.getInstance\(\s*[\"'](?:MD5|SHA-1|SHA1)[\"']\s*\)|kCCOptionECBMode|CC_MD5|CC_SHA1)",
    ),
    (
        "SNIPER-MOB-CRYP-03",
        "high",
        "MASVS-CRYPTO",
        "M10",
        ("all", "finance", "enterprise"),
        "Sabit (Hardcoded) IV veya Salt dizisi kullanımı",
        "IvParameterSpec veya anahtar türetme fonksiyonuna sabit bayt dizisi veriliyor; bu durum şifreli metin tekrarını açığa çıkarır.",
        "Her şifreleme işleminde SecureRandom / SecRandomCopyBytes ile kriptografik rastgele IV/Salt üretin.",
        r"IvParameterSpec\s*\(\s*(?:[\"'][^\"']+[\"']\.getBytes|new\s+byte\s*\[\s*\]\s*\{)",
    ),
    (
        "SNIPER-MOB-CRYP-04",
        "medium",
        "MASVS-CRYPTO",
        "M10",
        ("all", "finance", "gaming"),
        "Kriptografik olmayan zayıf rastgele sayı üreteci (java.util.Random / Math.random)",
        "Tahmin edilebilir PRNG kullanımı OTP, nonce veya oyun ödül mantığında manipülasyona yol açabilir.",
        "Güvenlik kritik değerler için java.security.SecureRandom veya SecRandomCopyBytes kullanın.",
        r"\b(?:new\s+java\.util\.Random\s*\(|Math\.random\s*\()",
    ),
    # C. MASVS-NETWORK & M5
    (
        "SNIPER-MOB-NET-01",
        "critical",
        "MASVS-NETWORK",
        "M5",
        ("all", "finance", "ecommerce", "health", "social", "enterprise"),
        "TLS sertifika veya Hostname doğrulamasını devre dışı bırakan kod (TrustAll / ALLOW_ALL)",
        "Özel TrustManager, HostnameVerifier veya badCertificateCallback tüm sertifikaları koşulsuz kabul ederek MITM saldırısına izin veriyor.",
        "Özel sertifika atlama kodunu kaldırın; sistem güven deposunu ve sertifika sabitlemeyi (Pinning) zorunlu kılın.",
        r"(?:ALLOW_ALL_HOSTNAME_VERIFIER|NullHostnameVerifier|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|badCertificateCallback\s*=\s*\([^)]*\)\s*=>\s*true|NSAllowsArbitraryLoads)",
    ),
    # D. MASVS-PLATFORM & M4 / M8
    (
        "SNIPER-MOB-PLAT-01",
        "critical",
        "MASVS-PLATFORM",
        "M4",
        ("all", "ecommerce", "social", "enterprise"),
        "WebView içinde güvensiz JavaScript köprüsü veya evrensel dosya erişimi",
        "WebView yapılandırmasında addJavascriptInterface, setAllowUniversalAccessFromFileURLs(true) veya originWhitelist=['*'] kullanılıyor.",
        "Yalnızca doğrulanmış HTTPS kaynaklarını yükleyin, dosya URL erişimini kapatın ve JS köprülerini en az yetkiyle sınırlandırın.",
        r"(?:addJavascriptInterface\s*\(|setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)|setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)|originWhitelist\s*=\s*\{\s*\[\s*['\"]\*['\"]\s*\]\s*\}|\bUIWebView\b)",
    ),
    (
        "SNIPER-MOB-PLAT-02",
        "high",
        "MASVS-PLATFORM",
        "M4",
        ("all", "finance", "ecommerce", "social"),
        "Değiştirilebilir (FLAG_MUTABLE) veya örtük (Implicit) PendingIntent kullanımı",
        "Bildirim veya alarm içinde FLAG_IMMUTABLE olmadan oluşturulan PendingIntent üçüncü taraf uygulamalarca ele geçirilebilir.",
        "Android 12+ uyumu ve güvenlik için varsayılan olarak PendingIntent.FLAG_IMMUTABLE kullanın.",
        r"PendingIntent\.get(?:Activity|Broadcast|Service|ForegroundService)\s*\((?![^\)]{0,200}FLAG_IMMUTABLE)",
    ),
    (
        "SNIPER-MOB-PLAT-03",
        "high",
        "MASVS-PLATFORM",
        "M4",
        ("all", "ecommerce", "social", "enterprise"),
        "Doğrulanmamış girdiyle Intent Redirection (startActivity / getParcelableExtra)",
        "Dışarıdan gelen Intent içindeki gömülü hedef Intent doğrulanmadan başlatılıyor; dahili bileşenlere yetkisiz erişim doğabilir.",
        "Gelen Intent içindeki hedef bileşen adını ve paketini beyaz listeyle doğrulayın.",
        r"startActivity\s*\(\s*(?:\(Intent\)\s*)?getIntent\(\)\.(?:getParcelableExtra|getExtras)",
    ),
    (
        "SNIPER-MOB-PLAT-04",
        "medium",
        "MASVS-PLATFORM",
        "M6",
        ("all", "finance", "health", "social"),
        "Kilit ekranında hassas bildirim içeriği gösterimi (VISIBILITY_PUBLIC) veya Pano sızıntısı",
        "Hassas bildirimler kilit ekranında herkese açık gösteriliyor veya sır verisi genel panoya (Clipboard/Pasteboard) kopyalanıyor.",
        "Bildirimlerde VISIBILITY_PRIVATE / setPublicVersion kullanın; hassas alanlarda pano kopyalamayı engelleyin veya süreli temizleyin.",
        r"(?:NotificationCompat\.VISIBILITY_PUBLIC|Notification\.VISIBILITY_PUBLIC|ClipboardManager[^\n]{0,80}setPrimaryClip|UIPasteboard\.general\.string\s*=)",
    ),
    # E. MASVS-AUTH & M3 (Biometric, OAuth, Client-side Authz)
    (
        "SNIPER-MOB-AUTH-01",
        "high",
        "MASVS-AUTH",
        "M3",
        ("all", "finance", "enterprise", "health"),
        "Kriptografik bağlam (CryptoObject / SecAccessControl) olmadan biyometrik doğrulama",
        "Biyometrik doğrulama yalnızca boolean geri çağrıya (onAuthenticationSucceeded / evaluatePolicy) dayanıyor; Frida ile kolayca atlatılabilir.",
        "BiometricPrompt.authenticate çağrısını Keystore tabanlı bir CryptoObject (veya iOS SecAccessControl biometryCurrentSet) ile bağlayın.",
        r"(?:biometricPrompt\.authenticate\s*\(\s*promptInfo\s*\)|evaluatePolicy\s*\(\s*\.deviceOwnerAuthenticationWithBiometrics)",
    ),
    (
        "SNIPER-MOB-AUTH-02",
        "high",
        "MASVS-AUTH",
        "M3",
        ("all", "ecommerce", "gaming", "enterprise"),
        "İstemci tarafında rol, abonelik (VIP/Premium) veya fiyat/indirim doğrulaması",
        "Yetki, premium durum veya sepet tutarı/indirim oranı istemci tarafı değişkende/SharedPreferences'ta kontrol ediliyor.",
        "Rol, abonelik ve fiyat/kupon hesaplamalarını yalnızca sunucu tarafında doğrulayın.",
        r"(?:isPremiumUser|isAdminUser|discountAmount|totalPrice|vipLevel)\s*=\s*(?:prefs\.get|UserDefaults\.standard)",
    ),
    # F. Uygulama Tipine Özel Kontroller (Finans, E-Ticaret, Sağlık/BLE, Sosyal, Kurumsal, Oyun/IAP)
    (
        "SNIPER-MOB-DOM-FIN-01",
        "medium",
        "MASVS-STORAGE",
        "M9",
        ("finance", "health", "enterprise"),
        "Finans/Sağlık ekranlarında ekran görüntüsü ve arka plan snapshot koruması (FLAG_SECURE) eksikliği",
        "Kart, bakiye veya sağlık verisi gösteren aktivitelerde FLAG_SECURE / ekran kaydı engeli bulunmadığında arka plan görüntüsü sızabilir.",
        "Hassas ekranlarda window.setFlags(FLAG_SECURE, FLAG_SECURE) ve iOS applicationWillResignActive bulanıklaştırma katmanı uygulayın.",
        r"setContentView\s*\([^\n]{0,80}(?:payment|card|wallet|transfer|health|patient)",
    ),
    (
        "SNIPER-MOB-DOM-HLT-01",
        "high",
        "MASVS-PRIVACY",
        "M6",
        ("health", "all"),
        "Sağlık / IoT cihazlarında şifresiz Bluetooth (BLE / RFCOMM) eşleşmesi",
        "Bluetooth bağlantısı kimlik doğrulamasız / şifresiz kanal (listenUsingInsecureRfcommWithServiceRecord veya açık GATT karakteristiği) kullanıyor.",
        "BLE karakteristiklerinde CBAttributePermissionsReadableEncryptionRequired / BluetoothDevice.createBond şifreli eşleşmesini zorunlu kılın.",
        r"\b(?:listenUsingInsecureRfcommWithServiceRecord|createInsecureRfcommSocketToServiceRecord|CBAttributePermissionsReadable\b(?![^\n]{0,80}EncryptionRequired))",
    ),
    (
        "SNIPER-MOB-DOM-SOC-01",
        "medium",
        "MASVS-PRIVACY",
        "M6",
        ("social", "ecommerce", "all"),
        "Medya yüklemelerinde EXIF GPS konum/cihaz üstverisi temizleme eksikliği",
        "Kullanıcı fotoğraf/video yüklerken EXIF GPS koordinatları soyulmadan karşıya gönderiliyor olabilir.",
        "Medya yükleme öncesinde ExifInterface / CGImageDestination ile GPS ve cihaz seri numarası etiketlerini temizleyin.",
        r"\b(?:ImagePicker\.pickImage|launchImageLibrary|MediaStore\.Images\.Media\.getBitmap)\b(?![\s\S]{0,240}Exif)",
    ),
    (
        "SNIPER-MOB-DOM-GAM-01",
        "high",
        "MASVS-RESILIENCE",
        "M7",
        ("gaming", "ecommerce", "all"),
        "Uygulama içi satın alma (IAP) makbuzunun sunucu doğrulaması olmadan yerel onaylanması",
        "PurchaseState.PURCHASED veya SKPaymentTransactionStatePurchased durumu arka uç imza/makbuz doğrulaması beklenmeden yerel olarak ürünü açıyor.",
        "Satın alma makbuzunu (purchaseToken / App Store JWS) sunucu tarafında Google Play Developer API / App Store Server API ile doğrulayın.",
        r"(?:Purchase\.PurchaseState\.PURCHASED|SKPaymentTransactionStatePurchased|\.purchased\b)(?![\s\S]{0,220}(?:verifyReceipt|serverVerify|validatePurchase))",
    ),
    (
        "SNIPER-MOB-DOM-GAM-02",
        "medium",
        "MASVS-RESILIENCE",
        "M9",
        ("gaming", "all"),
        "Oyun parası, elmas veya skor değerinin şifresiz PlayerPrefs içinde saklanması",
        "Unity PlayerPrefs.SetInt/SetFloat ile saklanan oyun ekonomisi verileri cihazda XML/plist düzenlenerek kolayca değiştirilebilir.",
        "Oyun içi bakiye ve envanteri sunucu otoriteli tutun; yerel önbellekte bütünlük imzası (HMAC) kullanın.",
        r"PlayerPrefs\.Set(?:Int|Float|String)\s*\(\s*[\"'](?:coins?|gems?|gold|score|diamonds?|balance|lives)[\"']",
    ),
)


def _mobile_finding(
    *,
    rule_id: str,
    severity: str,
    masvs: str,
    m_top10: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    file_path: str = "",
    line: int = 1,
) -> dict[str, Any]:
    digest = hashlib.sha256(f"{rule_id}|{file_path}|{line}|{title}".encode("utf-8")).hexdigest()[:12]
    return {
        "id": digest,
        "control_id": rule_id,
        "severity": severity,
        "category": "mobile",
        "masvs": masvs,
        "mobile_top10": m_top10,
        "owasp": MOBILE_TOP_10_2024.get(m_top10, m_top10),
        "cwe": "CWE-200" if masvs in {"MASVS-STORAGE", "MASVS-PRIVACY"} else "CWE-287" if masvs == "MASVS-AUTH" else "CWE-319" if masvs == "MASVS-NETWORK" else "CWE-926",
        "title": title,
        "description": description,
        "evidence": evidence[:400],
        "recommendation": recommendation,
        "reference": f"OWASP {masvs} / {m_top10}",
        "file": file_path,
        "line": max(1, int(line)),
        "confidence": "high",
        "detection": "static",
        "status": "open",
    }


def _build_masvs_summary(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_control: dict[str, int] = {cid: 0 for cid in MASVS_CONTROLS}
    for f in findings:
        cid = str(f.get("masvs") or "")
        if cid in by_control:
            by_control[cid] += 1
    summary: list[dict[str, Any]] = []
    for cid, meta in MASVS_CONTROLS.items():
        count = by_control[cid]
        summary.append(
            {
                "id": cid,
                "title": meta["title"],
                "description": meta["description"],
                "finding_count": count,
                "status": "failed" if count > 0 else "passed",
            }
        )
    return summary


def _build_top10_summary(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_m: dict[str, int] = {mid: 0 for mid in MOBILE_TOP_10_2024}
    for f in findings:
        mid = str(f.get("mobile_top10") or "")
        if mid in by_m:
            by_m[mid] += 1
    return [
        {
            "id": mid,
            "title": title,
            "finding_count": by_m[mid],
            "status": "failed" if by_m[mid] > 0 else "passed",
        }
        for mid, title in MOBILE_TOP_10_2024.items()
    ]


_DATA_TAG_START = re.compile(r"<data\b", re.IGNORECASE)
_CERTIFICATES_TAG_START = re.compile(r"<certificates\b", re.IGNORECASE)
_ANDROID_SCHEME_ATTR = re.compile(r"android:scheme", re.IGNORECASE)
_SRC_ATTR = re.compile(r"src", re.IGNORECASE)


def _xml_start_tags(content: str, start_pattern: re.Pattern[str], *,
                    require_space: bool = False,
                    allow_unterminated: bool = False) -> list[tuple[int, int, str]]:
    """Collect bounded XML-like start tags without rescanning suffixes."""
    out: list[tuple[int, int, str]] = []
    consumed = 0
    for match in start_pattern.finditer(content):
        if match.start() < consumed:
            continue
        if require_space and (match.end() >= len(content) or not content[match.end()].isspace()):
            continue
        closing = content.find(">", match.end())
        if closing < 0:
            if allow_unterminated:
                out.append((match.start(), len(content), content[match.start():]))
            break
        consumed = closing + 1
        out.append((match.start(), consumed, content[match.start():consumed]))
    return out


def _xml_attribute_values(tag: str, pattern: re.Pattern[str]) -> list[str]:
    """Return quoted attribute values using one forward delimiter scan."""
    cursor = 0
    values: list[str] = []
    while cursor < len(tag):
        match = pattern.search(tag, cursor)
        if match is None:
            break
        index = match.end()
        while index < len(tag) and tag[index].isspace():
            index += 1
        if index >= len(tag) or tag[index] != "=":
            cursor = match.end()
            continue
        index += 1
        while index < len(tag) and tag[index].isspace():
            index += 1
        if index >= len(tag) or tag[index] not in "\"'":
            cursor = match.end()
            continue
        quote = tag[index]
        end = tag.find(quote, index + 1)
        if end < 0:
            cursor = match.end()
            continue
        values.append(tag[index + 1:end])
        cursor = end + 1
    return values


def _xml_attribute(tag: str, pattern: re.Pattern[str]) -> str | None:
    values = _xml_attribute_values(tag, pattern)
    return next((value for value in reversed(values) if value), None)


def _gradle_false_setting(content: str, name: str) -> bool:
    """Recognize ``name false`` and ``name = false`` in linear time."""
    cursor = 0
    while cursor < len(content):
        found = content.find(name, cursor)
        if found < 0:
            return False
        index = found + len(name)
        whitespace_start = index
        while index < len(content) and content[index].isspace():
            index += 1
        separated = index > whitespace_start
        if index < len(content) and content[index] == "=":
            separated = True
            index += 1
            while index < len(content) and content[index].isspace():
                index += 1
        if separated and content.startswith("false", index):
            return True
        cursor = found + len(name)
    return False


def _audit_manifest_or_config_text(
    content: str,
    *,
    rel_path: str,
    app_profile: str = "all",
) -> tuple[list[dict[str, Any]], str]:
    findings: list[dict[str, Any]] = []
    lower_name = Path(rel_path).name.lower()
    platform = "cross_platform"

    if lower_name == "androidmanifest.xml" or "<manifest" in content:
        platform = "android"
        if re.search(r"android:debuggable\s*=\s*[\"']true[\"']", content, re.IGNORECASE):
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-MAN-01",
                    severity="critical",
                    masvs="MASVS-RESILIENCE",
                    m_top10="M8",
                    title="Android uygulaması üretimde debuggable=true olarak yapılandırılmış",
                    description="android:debuggable='true' ayarı cihaz üzerinde jdwp/run-as ile uygulama belleğine ve verilerine tam erişim sağlar.",
                    evidence="android:debuggable=\"true\"",
                    recommendation="Üretim (release) derlemelerinde android:debuggable='false' yapın.",
                    file_path=rel_path,
                )
            )
        if re.search(r"android:allowBackup\s*=\s*[\"']true[\"']", content, re.IGNORECASE):
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-MAN-02",
                    severity="medium",
                    masvs="MASVS-STORAGE",
                    m_top10="M9",
                    title="Android uygulama verileri ADB/Bulut yedeklemesine açık (allowBackup=true)",
                    description="android:allowBackup='true' olduğunda uygulama içindeki yerel dosyalar ve tercihler yedekleme yoluyla dışarı aktarılabilir.",
                    evidence="android:allowBackup=\"true\"",
                    recommendation="android:allowBackup='false' belirleyin veya fullBackupContent ile hassas dosyaları hariç tutun.",
                    file_path=rel_path,
                )
            )
        if re.search(r"android:usesCleartextTraffic\s*=\s*[\"']true[\"']", content, re.IGNORECASE):
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-MAN-03",
                    severity="high",
                    masvs="MASVS-NETWORK",
                    m_top10="M5",
                    title="Android manifest içinde şifresiz HTTP trafiğine izin veriliyor (usesCleartextTraffic=true)",
                    description="Uygulama şifrelenmemiş HTTP bağlantıları kurabilir; ağ üzerindeki saldırganlar trafiği okuyabilir veya değiştirebilir.",
                    evidence="android:usesCleartextTraffic=\"true\"",
                    recommendation="android:usesCleartextTraffic='false' yapın ve yalnızca HTTPS uç noktaları kullanın.",
                    file_path=rel_path,
                )
            )
        for perm, sev, desc in DANGEROUS_ANDROID_PERMISSIONS:
            if perm in content:
                findings.append(
                    _mobile_finding(
                        rule_id="SNIPER-MOB-MAN-04",
                        severity=sev,
                        masvs="MASVS-CODE",
                        m_top10="M6",
                        title=f"Yüksek riskli Android izni talep ediliyor: {perm.split('.')[-1]}",
                        description=f"Manifest içinde {perm} ({desc}) tanımlanmış.",
                        evidence=perm,
                        recommendation="En az yetki ilkesine göre bu izni kaldırın veya kapsamlı gizlilik gerekçesi sunun.",
                        file_path=rel_path,
                    )
                )
        for comp_match in re.finditer(
            r"<(activity|service|receiver|provider)\b([^>]*?)>",
            content,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            comp_type = comp_match.group(1).lower()
            attrs = comp_match.group(2)
            name_m = re.search(r"android:name\s*=\s*[\"']([^\"']+)[\"']", attrs)
            comp_name = name_m.group(1) if name_m else comp_type
            is_exported = bool(re.search(r"android:exported\s*=\s*[\"']true[\"']", attrs, re.IGNORECASE))
            has_perm = bool(re.search(r"android:(?:permission|readPermission|writePermission)\s*=\s*[\"'][^\"']+[\"']", attrs, re.IGNORECASE))
            is_MainLauncher = "android.intent.action.MAIN" in content[comp_match.start() : comp_match.end() + 350]
            if is_exported and not has_perm and not is_MainLauncher:
                findings.append(
                    _mobile_finding(
                        rule_id="SNIPER-MOB-MAN-05",
                        severity="high" if comp_type in {"provider", "service", "receiver"} else "medium",
                        masvs="MASVS-PLATFORM",
                        m_top10="M4",
                        title=f"İzin koruması olmayan dışa açık (exported=true) Android bileşeni: {comp_name}",
                        description=f"<{comp_type}> bileşeni android:exported='true' olarak işaretlenmiş ancak özel bir android:permission ile korunmamış.",
                        evidence=f"<{comp_type} android:name=\"{comp_name}\" android:exported=\"true\">",
                        recommendation="Bileşen yalnızca uygulama içi kullanılıyorsa android:exported='false' yapın; dış erişim şartsa signature-level permission zorunlu kılın.",
                        file_path=rel_path,
                    )
                )
            if comp_type == "provider" and re.search(r"android:grantUriPermissions\s*=\s*[\"']true[\"']", attrs, re.IGNORECASE):
                findings.append(
                    _mobile_finding(
                        rule_id="SNIPER-MOB-MAN-06",
                        severity="high",
                        masvs="MASVS-PLATFORM",
                        m_top10="M4",
                        title=f"ContentProvider geniş URI erişim izni veriyor (grantUriPermissions=true): {comp_name}",
                        description="ContentProvider tüm alt yollar için geçici URI okuma/yazma izni verilmesine açık.",
                        evidence=f"provider {comp_name} grantUriPermissions=true",
                        recommendation="grantUriPermissions yerine yalnızca belirli güvenli alt yollar için <grant-uri-permission> tanımlayın.",
                        file_path=rel_path,
                    )
                )
        for tag_start, tag_end, tag in _xml_start_tags(content, _DATA_TAG_START):
            scheme = _xml_attribute(tag, _ANDROID_SCHEME_ATTR)
            if not scheme:
                continue
            scheme_val = scheme.lower()
            if scheme_val not in {"http", "https"}:
                findings.append(
                    _mobile_finding(
                        rule_id="SNIPER-MOB-MAN-07",
                        severity="medium",
                        masvs="MASVS-PLATFORM",
                        m_top10="M4",
                        title=f"Özel URL şeması (Custom Scheme Deep Link) ele geçirilmeye açık: {scheme_val}://",
                        description="Özel URL şemaları başka bir kötü amaçlı uygulama tarafından kaydedilerek OAuth/ödeme geri dönüşlerini yakalayabilir.",
                        evidence=f"android:scheme=\"{scheme_val}\"",
                        recommendation="Özel şema yerine android:autoVerify='true' ve assetlinks.json ile doğrulanmış HTTPS App Links kullanın.",
                        file_path=rel_path,
                    )
                )
            else:
                surrounding = content[max(0, tag_start - 300):tag_end + 200]
                if "BROWSABLE" in surrounding and "autoVerify=\"true\"" not in surrounding and "autoVerify='true'" not in surrounding:
                    findings.append(
                        _mobile_finding(
                            rule_id="SNIPER-MOB-MAN-08",
                            severity="low",
                            masvs="MASVS-PLATFORM",
                            m_top10="M4",
                            title="HTTPS Deep Link tanımında android:autoVerify='true' eksik",
                            description="BROWSABLE intent-filter tanımlanmış ancak alan adı sahipliğini doğrulayan autoVerify='true' bulunmuyor.",
                            evidence=tag[:160],
                            recommendation="intent-filter etiketine android:autoVerify='true' ekleyin ve /.well-known/assetlinks.json dosyasını yayımlayın.",
                            file_path=rel_path,
                        )
                    )

    elif lower_name == "network_security_config.xml" or "<network-security-config" in content:
        platform = "android"
        if re.search(r"cleartextTrafficPermitted\s*=\s*[\"']true[\"']", content, re.IGNORECASE):
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-NSC-01",
                    severity="high",
                    masvs="MASVS-NETWORK",
                    m_top10="M5",
                    title="Network Security Config içinde cleartextTrafficPermitted=true",
                    description="Ağ güvenlik yapılandırması şifrelenmemiş HTTP trafiğine izin veriyor.",
                    evidence="cleartextTrafficPermitted=\"true\"",
                    recommendation="Tüm base-config ve domain-config bloklarında cleartextTrafficPermitted='false' kullanın.",
                    file_path=rel_path,
                )
            )
        trusts_user_certificates = any(
            any(value.casefold() == "user" for value in _xml_attribute_values(tag, _SRC_ATTR))
            for _start, _end, tag in _xml_start_tags(
                content, _CERTIFICATES_TAG_START, require_space=True, allow_unterminated=True
            )
        )
        if trusts_user_certificates:
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-NSC-02",
                    severity="high",
                    masvs="MASVS-NETWORK",
                    m_top10="M5",
                    title="Network Security Config kullanıcı sertifikalarına (src='user') güveniyor",
                    description="Cihaza yüklenen özel vekil (Burp/Charles/MITM) sertifikaları üretim uygulamasında geçerli kabul ediliyor.",
                    evidence="<certificates src=\"user\" />",
                    recommendation="Üretim yapılandırmasında yalnızca <certificates src='system' /> ve pin-set kullanın.",
                    file_path=rel_path,
                )
            )
        if "<pin-set" not in content and app_profile in {"finance", "enterprise", "health"}:
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-NSC-03",
                    severity="medium",
                    masvs="MASVS-NETWORK",
                    m_top10="M5",
                    title="Network Security Config içinde sertifika sabitleme (<pin-set>) tanımlanmamış",
                    description="Yüksek hassasiyetli uygulama profilinde SPKI SHA-256 sertifika sabitlemesi bulunamadı.",
                    evidence="network_security_config.xml (<pin-set> yok)",
                    recommendation="Birincil ve yedek SPKI SHA-256 özetlerini içeren <pin-set> tanımlayın.",
                    file_path=rel_path,
                )
            )

    elif lower_name.endswith(".plist") or lower_name.endswith(".xcprivacy") or "<plist" in content:
        platform = "ios"
        if re.search(r"<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<true\s*/>", content, re.IGNORECASE):
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-IOS-01",
                    severity="high",
                    masvs="MASVS-NETWORK",
                    m_top10="M5",
                    title="iOS App Transport Security (ATS) devre dışı bırakılmış (NSAllowsArbitraryLoads=true)",
                    description="Uygulama tüm alan adlarına şifrelenmemiş HTTP bağlantısı yapılmasına izin veriyor.",
                    evidence="NSAllowsArbitraryLoads = true",
                    recommendation="NSAllowsArbitraryLoads değerini false yapın ve yalnızca zorunlu istisnaları alan adı bazında tanımlayın.",
                    file_path=rel_path,
                )
            )
        if re.search(r"<key>\s*get-task-allow\s*</key>\s*<true\s*/>", content, re.IGNORECASE):
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-IOS-02",
                    severity="critical",
                    masvs="MASVS-RESILIENCE",
                    m_top10="M7",
                    title="iOS Entitlements içinde hata ayıklayıcı (get-task-allow=true) izni açık",
                    description="get-task-allow=true ayarı lldb/debugserver ile süreç belleğine bağlanılmasına olanak tanır.",
                    evidence="get-task-allow = true",
                    recommendation="Dağıtım (App Store / Enterprise) paketlerinde get-task-allow=false kullanın.",
                    file_path=rel_path,
                )
            )
        if re.search(r"<key>\s*UIFileSharingEnabled\s*</key>\s*<true\s*/>", content, re.IGNORECASE):
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-IOS-03",
                    severity="medium",
                    masvs="MASVS-STORAGE",
                    m_top10="M9",
                    title="iOS Documents klasörü iTunes/Finder dosya paylaşımına açık (UIFileSharingEnabled=true)",
                    description="Kullanıcı cihazı bilgisayara bağlandığında uygulama Documents dizinindeki tüm dosyalar doğrudan kopyalanabilir.",
                    evidence="UIFileSharingEnabled = true",
                    recommendation="Gerekli değilse UIFileSharingEnabled=false yapın ve hassas verileri Application Support / Keychain içinde saklayın.",
                    file_path=rel_path,
                )
            )
        if "CFBundleURLSchemes" in content:
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-IOS-04",
                    severity="medium",
                    masvs="MASVS-PLATFORM",
                    m_top10="M4",
                    title="iOS özel URL şeması (CFBundleURLSchemes) tanımlanmış",
                    description="CFBundleURLSchemes başka uygulamalar tarafından çakıştırılarak (scheme hijacking) geri dönüş parametreleri çalınabilir.",
                    evidence="CFBundleURLSchemes",
                    recommendation="Kimlik doğrulama ve ödeme yönlendirmelerinde yalnızca apple-app-site-association ile doğrulanmış Universal Links kullanın.",
                    file_path=rel_path,
                )
            )

    elif lower_name in {"build.gradle", "build.gradle.kts"}:
        platform = "android"
        if _gradle_false_setting(content, "minifyEnabled"):
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-GRD-01",
                    severity="medium",
                    masvs="MASVS-RESILIENCE",
                    m_top10="M7",
                    title="Android release derlemesinde kod küçültme/gizleme (minifyEnabled) kapalı",
                    description="ProGuard/R8 etkin olmadığında sınıf ve metot adları APK/AAB içinde olduğu gibi kalır ve tersine mühendislik kolaylaşır.",
                    evidence="minifyEnabled false",
                    recommendation="Release buildType içinde minifyEnabled true ve shrinkResources true ayarlarını etkinleştirin.",
                    file_path=rel_path,
                )
            )
        if re.search(r"['\"][^'\"]+:\+['\"]", content):
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-GRD-02",
                    severity="medium",
                    masvs="MASVS-CODE",
                    m_top10="M2",
                    title="Gradle bağımlılığında dinamik sürüm (+) kullanılıyor",
                    description="Sabitlenmemiş bağımlılık sürümleri tedarik zinciri üzerinden doğrulanmamış paket çekilmesine yol açabilir.",
                    evidence="implementation '...:+'",
                    recommendation="Tüm üçüncü taraf mobil SDK sürümlerini tam sürüm numarası ve gradle.lockfile ile sabitleyin.",
                    file_path=rel_path,
                )
            )

    elif lower_name == "google-services.json":
        platform = "android"
        if re.search(r"\"current_key\"\s*:\s*\"AIza[0-9A-Za-z\-_]{35}\"", content):
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-CFG-01",
                    severity="low",
                    masvs="MASVS-CRYPTO",
                    m_top10="M1",
                    title="google-services.json içinde Firebase API anahtarı mevcut (Kısıtlama/Kurallar doğrulanmalı)",
                    description="Firebase yapılandırma dosyası paket içinde yer alıyor; Firestore/Storage güvenlik kuralları ve SHA-1 paket kısıtlaması yoksa veri sızıntısı yaşanabilir.",
                    evidence="google-services.json (current_key tanımlı · değer kaydedilmedi)",
                    recommendation="Google Cloud Console üzerinden API anahtarını uygulama paket adı + SHA-256 sertifika parmak iziyle sınırlandırın.",
                    file_path=rel_path,
                )
            )

    return findings, platform


def audit_mobile_manifest_inline(
    raw_content: str,
    *,
    filename: str = "AndroidManifest.xml",
    app_profile: str = "all",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Mobil manifest veya yapılandırma içeriği boş olamaz.")
    if len(raw_content) > 2_000_000:
        raise ValueError("Mobil yapılandırma içeriği güvenli boyut sınırını (2 MB) aşıyor.")
    profile = (app_profile or "all").strip().lower()
    if profile not in SUPPORTED_APP_PROFILES:
        raise ValueError(f"Desteklenmeyen uygulama profili: {app_profile}")

    findings, platform = _audit_manifest_or_config_text(
        raw_content,
        rel_path=filename or "AndroidManifest.xml",
        app_profile=profile,
    )
    score, grade, counts = calculate_score(findings)
    return {
        "format": "sniper-mobile-manifest-audit-v1",
        "filename": filename,
        "platform": platform,
        "app_profile": profile,
        "score": score,
        "grade": grade,
        "counts": counts,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "masvs_summary": _build_masvs_summary(findings),
        "mobile_top10_summary": _build_top10_summary(findings),
    }


def _scan_mobile_source_file(
    content: str,
    *,
    rel_path: str,
    app_profile: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rule_id, sev, masvs, m_top10, domains, title, desc, rec, pattern in SOURCE_RULES:
        if app_profile != "all" and "all" not in domains and app_profile not in domains:
            continue
        match = re.search(pattern, content, flags=re.IGNORECASE)
        if match:
            line_no = content.count("\n", 0, match.start()) + 1
            snippet = match.group(0)
            if rule_id == "SNIPER-MOB-CRYP-01":
                snippet = "<gömülü sır deseni tespit edildi · değer kaydedilmedi>"
            findings.append(
                _mobile_finding(
                    rule_id=rule_id,
                    severity=sev,
                    masvs=masvs,
                    m_top10=m_top10,
                    title=title,
                    description=desc,
                    evidence=f"{rel_path}:{line_no} -> {snippet[:180]}",
                    recommendation=rec,
                    file_path=rel_path,
                    line=line_no,
                )
            )
    return findings


def _build_domain_risk_summary(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    profiles = (
        ("finance", "Finans, Bankacılık, Cüzdan ve Ödeme", ("MASVS-NETWORK", "MASVS-CRYPTO", "MASVS-AUTH", "MASVS-RESILIENCE")),
        ("ecommerce", "E-Ticaret, Pazaryeri ve Sipariş/Kupon", ("MASVS-AUTH", "MASVS-PLATFORM", "MASVS-NETWORK")),
        ("health", "Sağlık, Tele-Tıp, Giyilebilir Cihaz (BLE) ve KVKK", ("MASVS-PRIVACY", "MASVS-STORAGE", "MASVS-CRYPTO")),
        ("social", "Sosyal Medya, Mesajlaşma ve Medya Paylaşımı", ("MASVS-PLATFORM", "MASVS-PRIVACY", "MASVS-STORAGE")),
        ("enterprise", "Kurumsal B2B, SaaS, MDM ve Saha Operasyon", ("MASVS-AUTH", "MASVS-STORAGE", "MASVS-CODE")),
        ("gaming", "Mobil Oyun, IAP ve Oyun Ekonomisi", ("MASVS-RESILIENCE", "MASVS-CRYPTO", "MASVS-AUTH")),
    )
    out: list[dict[str, Any]] = []
    for pid, label, key_controls in profiles:
        rel_findings = [f for f in findings if f.get("masvs") in key_controls]
        out.append(
            {
                "profile": pid,
                "title": label,
                "relevant_finding_count": len(rel_findings),
                "status": "risk_detected" if rel_findings else "ready",
            }
        )
    return out


@project_scan_scope
def audit_mobile_project(
    project_path: str,
    *,
    app_profile: str = "all",
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    profile = (app_profile or "all").strip().lower()
    if profile not in SUPPORTED_APP_PROFILES:
        raise ValueError(f"Desteklenmeyen uygulama profili: {app_profile}")
    root = validate_project_path(project_path, allowed_roots=allowed_roots)

    findings: list[dict[str, Any]] = []
    detected_platforms: set[str] = set()
    scanned_files = 0
    has_privacy_manifest = False
    has_ssl_pinning_signal = False
    has_root_jailbreak_signal = False

    skip_dirs = {".git", "node_modules", "build", "dist", ".gradle", ".dart_tool", "pods", "deriveddata", "__pycache__"}

    with _opened_project_tree(root) as tree:
        for project_file in tree.iter_files(skip_dirs=skip_dirs, reject_unsafe=False):
            fname = project_file.name
            lower_name = fname.lower()
            ext = project_file.path.suffix.lower()
            if lower_name not in MOBILE_CONFIG_FILENAMES and ext not in MOBILE_SOURCE_EXTENSIONS:
                continue

            if project_file.size > 1_000_000:
                continue
            text = tree.read_text(project_file, 1_000_000, errors="ignore", allow_empty=True)

            scanned_files += 1
            rel_path = project_file.path.as_posix()

            if lower_name == "privacyinfo.xcprivacy":
                has_privacy_manifest = True
            if lower_name == "pubspec.yaml" or ext == ".dart":
                detected_platforms.add("flutter")
            if lower_name == "package.json" and ("react-native" in text or "expo" in text):
                detected_platforms.add("react_native")
            if ext in {".kt", ".java"} or lower_name in {"androidmanifest.xml", "build.gradle", "build.gradle.kts"}:
                detected_platforms.add("android")
            if ext in {".swift", ".m", ".mm"} or lower_name.endswith(".plist") or lower_name.endswith(".xcprivacy"):
                detected_platforms.add("ios")

            if any(tok in text for tok in ("CertificatePinner", "pin-set", "TrustKit", "SSLPinning", "SecTrustEvaluate")):
                has_ssl_pinning_signal = True
            if any(tok in text for tok in ("RootBeer", "isDeviceRooted", "cydia", "Frida", "jailbreak", "PlayIntegrity", "AppAttest")):
                has_root_jailbreak_signal = True

            if lower_name in MOBILE_CONFIG_FILENAMES:
                cfg_findings, plat = _audit_manifest_or_config_text(text, rel_path=rel_path, app_profile=profile)
                if plat in {"android", "ios"}:
                    detected_platforms.add(plat)
                findings.extend(cfg_findings)

            if ext in MOBILE_SOURCE_EXTENSIONS:
                findings.extend(_scan_mobile_source_file(text, rel_path=rel_path, app_profile=profile))

    if "ios" in detected_platforms and not has_privacy_manifest:
        findings.append(
            _mobile_finding(
                rule_id="SNIPER-MOB-PRIV-01",
                severity="low",
                masvs="MASVS-PRIVACY",
                m_top10="M6",
                title="iOS projesinde PrivacyInfo.xcprivacy (Privacy Manifest) dosyası bulunamadı",
                description="Apple App Store gizlilik gereksinimleri kapsamında Required Reason API ve veri toplama beyanlarını içeren PrivacyInfo.xcprivacy tespit edilmedi.",
                evidence="PrivacyInfo.xcprivacy (eksik)",
                recommendation="Uygulama ve üçüncü taraf SDK'lar için PrivacyInfo.xcprivacy dosyasını projeye ekleyin.",
                file_path="PrivacyInfo.xcprivacy",
            )
        )

    if profile in {"finance", "enterprise", "health"} and scanned_files > 0:
        if not has_ssl_pinning_signal:
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-NET-02",
                    severity="medium",
                    masvs="MASVS-NETWORK",
                    m_top10="M5",
                    title="Yüksek hassasiyetli profilde SSL/TLS Sertifika Sabitleme (Pinning) sinyali bulunamadı",
                    description="Kod tabanında CertificatePinner, TrustKit veya Network Security Config pin-set kullanımı tespit edilmedi.",
                    evidence=f"app_profile={profile} · ssl_pinning=false",
                    recommendation="OkHttp CertificatePinner, Network Security Config <pin-set> veya iOS TrustKit/URLSessionDelegate ile SPKI sabitlemesi uygulayın.",
                )
            )
        if not has_root_jailbreak_signal:
            findings.append(
                _mobile_finding(
                    rule_id="SNIPER-MOB-RES-01",
                    severity="medium",
                    masvs="MASVS-RESILIENCE",
                    m_top10="M7",
                    title="Root / Jailbreak / Cihaz Bütünlüğü (Play Integrity / App Attest) doğrulama sinyali bulunamadı",
                    description="Kritik uygulama profilinde cihaz bütünlüğü veya enstrumantasyon (Frida) tespiti gözlenmedi.",
                    evidence=f"app_profile={profile} · integrity_attestation=false",
                    recommendation="Play Integrity API, Apple App Attest ve çalışma zamanı Root/Jailbreak/Frida kontrollerini entegre edin.",
                )
            )

    score, grade, counts = calculate_score(findings)
    return {
        "format": "sniper-mobile-security-audit-v1",
        "project_path": str(root),
        "project_name": root.name,
        "app_profile": profile,
        "detected_platforms": sorted(detected_platforms),
        "scanned_files": scanned_files,
        "score": score,
        "grade": grade,
        "counts": counts,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > PROJECT_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, PROJECT_FINDING_LIMIT)[0],
        "masvs_summary": _build_masvs_summary(findings),
        "mobile_top10_summary": _build_top10_summary(findings),
        "domain_risk_summary": _build_domain_risk_summary(findings),
        "controls_evaluated": list(MASVS_CONTROLS.keys()),
    }


def _extract_printable_strings(data: bytes) -> str:
    ascii_parts = [m.group(0).decode("latin-1", errors="ignore") for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]
    utf16_parts = [
        m.group(0).decode("utf-16le", errors="ignore")
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data)
    ]
    return "\n".join(ascii_parts + utf16_parts)


def audit_mobile_package_archive(
    package_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    if not isinstance(package_path, str) or not package_path.strip():
        raise ProjectRejected("Geçerli bir mobil paket (.apk, .aab, .ipa) dosya yolu girin.")
    raw = package_path.strip()
    resolved = Path(os.path.abspath(os.path.expandvars(os.path.expanduser(raw))))

    roots = allowed_roots if allowed_roots is not None else _allowed_roots()
    normalized_roots = tuple(Path(os.path.abspath(os.fspath(root))) for root in roots)
    if not any(resolved != root and root in resolved.parents for root in normalized_roots):
        raise ProjectRejected("Mobil paket yalnızca kullanıcı dizini veya izinli yerel çalışma alanı içinde olabilir.")

    ext = resolved.suffix.lower()
    if ext not in {".apk", ".aab", ".ipa"}:
        raise ProjectRejected("Yalnızca .apk, .aab ve .ipa uzantılı mobil paketler desteklenir.")
    try:
        with ProjectTree(resolved.parent) as tree:
            walker = tree.walk(reject_unsafe=False)
            try:
                entry = next(walker)
            finally:
                walker.close()
            package_entry = next((item for item in entry.files if item.name == resolved.name), None)
            if package_entry is None:
                raise ProjectRejected("Yalnızca standart dosya (.apk, .aab, .ipa) analiz edilebilir.")
            if package_entry.size > MAX_PACKAGE_BYTES:
                raise ProjectRejected("Mobil paket boyutu 100 MB sınırını aşıyor.")
            package_data = tree.read_bytes(package_entry, MAX_PACKAGE_BYTES, allow_empty=True)
    except ProjectTreeError as exc:
        raise ProjectRejected("Mobil paket bilgisi okunamadı.") from exc
    package_file = io.BytesIO(package_data)
    package_size = len(package_data)
    package_type = ext.lstrip(".")

    findings: list[dict[str, Any]] = []
    native_libs: list[str] = []
    dex_files: list[str] = []
    signature_files: list[str] = []
    embedded_secret_files: list[str] = []

    try:
        with package_file, zipfile.ZipFile(package_file, "r") as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                raise ProjectRejected("Paket içindeki dosya sayısı güvenli sınırı aşıyor.")
            total_uncompressed = sum(max(0, info.file_size) for info in infos)
            if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise ProjectRejected("Paket açılmış boyutu güvenli sınırı (Zip Bomb koruması) aşıyor.")

            for info in infos:
                name = info.filename
                lower_name = name.lower()
                if lower_name.endswith(".so"):
                    native_libs.append(name)
                elif lower_name.endswith(".dex"):
                    dex_files.append(name)
                elif lower_name.startswith("meta-inf/") and lower_name.endswith((".rsa", ".dsa", ".ec", ".sf")):
                    signature_files.append(name)
                elif "_codesignature/coderesources" in lower_name or lower_name.endswith("embedded.mobileprovision"):
                    signature_files.append(name)

                if lower_name.endswith((".env", ".pem", ".key", ".p12", ".pfx", ".keystore", ".jks")) or Path(lower_name).name in {"google-services.json", "googleservice-info.plist"}:
                    embedded_secret_files.append(name)
                    sev = "critical" if lower_name.endswith((".key", ".p12", ".pfx", ".keystore", ".jks", ".pem", ".env")) else "low"
                    findings.append(
                        _mobile_finding(
                            rule_id="SNIPER-MOB-PKG-01",
                            severity=sev,
                            masvs="MASVS-CRYPTO",
                            m_top10="M1",
                            title=f"Mobil paket arşivinde hassas anahtar veya yapılandırma dosyası: {Path(name).name}",
                            description="Uygulama paketi (.apk/.aab/.ipa) içinde doğrudan çıkarılabilecek özel anahtar, sertifika veya ortam dosyası bulundu.",
                            evidence=name[:240],
                            recommendation="Özel anahtar, .keystore ve .env dosyalarını derleme paketinden derhal çıkarın ve sızan anahtarları iptal edin.",
                            file_path=name,
                        )
                    )

                if (
                    lower_name.endswith("androidmanifest.xml")
                    or lower_name.endswith("info.plist")
                    or lower_name.endswith("embedded.mobileprovision")
                    or lower_name.endswith("network_security_config.xml")
                ) and info.file_size <= 2_000_000:
                    raw_bytes = zf.read(info.filename)
                    text = raw_bytes.decode("utf-8", errors="ignore")
                    if "<manifest" not in text and "<plist" not in text:
                        text = _extract_printable_strings(raw_bytes)
                    cfg_findings, _ = _audit_manifest_or_config_text(text, rel_path=name, app_profile="all")
                    findings.extend(cfg_findings)
                    if lower_name.endswith("androidmanifest.xml") and not cfg_findings:
                        for perm, sev, desc in DANGEROUS_ANDROID_PERMISSIONS:
                            if perm in text:
                                findings.append(
                                    _mobile_finding(
                                        rule_id="SNIPER-MOB-MAN-04",
                                        severity=sev,
                                        masvs="MASVS-CODE",
                                        m_top10="M6",
                                        title=f"Yüksek riskli Android izni talep ediliyor: {perm.split('.')[-1]}",
                                        description=f"Paket manifesti içinde {perm} ({desc}) tanımlanmış.",
                                        evidence=perm,
                                        recommendation="En az yetki ilkesine göre bu izni kaldırın.",
                                        file_path=name,
                                    )
                                )
    except zipfile.BadZipFile as exc:
        raise ProjectRejected("Geçersiz veya bozuk mobil paket arşivi.") from exc

    if not signature_files:
        findings.append(
            _mobile_finding(
                rule_id="SNIPER-MOB-PKG-02",
                severity="medium",
                masvs="MASVS-RESILIENCE",
                m_top10="M7",
                title="Mobil pakette kod imzası (Code Signature) üstverisi tespit edilmedi",
                description="Paket arşivinde META-INF imza dosyaları veya _CodeSignature/CodeResources bulunamadı.",
                evidence=f"{resolved.name} (imzasız veya yalnız v2/v3 blok imzalı)",
                recommendation="Dağıtım paketlerinin geçerli üretim sertifikasıyla imzalandığını doğrulayın.",
                file_path=resolved.name,
            )
        )

    score, grade, counts = calculate_score(findings)
    return {
        "format": "sniper-mobile-package-audit-v1",
        "package_name": resolved.name,
        "package_type": package_type,
        "score": score,
        "grade": grade,
        "counts": counts,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "masvs_summary": _build_masvs_summary(findings),
        "mobile_top10_summary": _build_top10_summary(findings),
        "archive_metadata": {
            "size_bytes": package_size,
            "dex_count": len(dex_files),
            "native_lib_count": len(native_libs),
            "native_libs": native_libs[:25],
            "signature_files": signature_files[:15],
            "embedded_sensitive_files": embedded_secret_files[:25],
        },
    }
