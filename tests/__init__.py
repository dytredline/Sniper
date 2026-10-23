"""Sniper testleri.

Denetim günlüğü anahtarı ve çapaları testlerde kullanıcının gerçek ``~/.config/sniper`` dizinine
yazılmasın: bazı testler proje yolu kuralı gereği veritabanını ev dizini altında oluşturur.
Açık bir ayar yoksa her test süreci kendi geçici anahtar/çapa dizinini kullanır.
"""
import atexit
import os
import shutil
import tempfile

if not os.environ.get("SNIPER_AUDIT_KEY_FILE"):
    _INTEGRITY_DIR = tempfile.mkdtemp(prefix="sniper-test-integrity-")
    os.environ["SNIPER_AUDIT_KEY_FILE"] = os.path.join(_INTEGRITY_DIR, "audit.key")
    os.environ.setdefault("SNIPER_AUDIT_ANCHOR_DIR", os.path.join(_INTEGRITY_DIR, "audit-anchors"))
    atexit.register(shutil.rmtree, _INTEGRITY_DIR, True)

# 20. tur: lisans toplayıcısı testlerde kullanıcının gerçek paket önbelleklerini (~/.m2, ~/.cargo, ~/.nuget,
# Go modül önbelleği, gem dizinleri) okumasın; önbellek testleri kendi geçici dizinini verir.
os.environ.setdefault("SNIPER_LICENSE_CACHE_HOME", "")

# 21. tur: öz sağlık raporu testlerde kullanıcının systemd oturumunu (systemctl --user show) sorgulamasın.
os.environ.setdefault("SNIPER_HEALTH_SYSTEMCTL", "0")

# 23. tur: CLI malware önbelleği yedeği (~/.cache/sniper) testlerde kapalı; önbellek testleri kendi dizinini verir.
os.environ.setdefault("SNIPER_CACHE_HOME", "")
