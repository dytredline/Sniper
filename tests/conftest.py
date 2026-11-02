import os
import shutil
import tempfile
import atexit

# Denetim anahtarı/çapaları kullanıcının ~/.config/sniper dizinine yazılmasın (server içe aktarılmadan önce).
_INTEGRITY_TMP = tempfile.mkdtemp(prefix="sniper-pytest-integrity-")
_DATA_TMP = tempfile.mkdtemp(prefix="sniper-pytest-data-")
os.chmod(_DATA_TMP, 0o700)
os.environ.setdefault("SNIPER_AUDIT_KEY_FILE", os.path.join(_INTEGRITY_TMP, "audit.key"))
os.environ.setdefault("SNIPER_AUDIT_ANCHOR_DIR", os.path.join(_INTEGRITY_TMP, "audit-anchors"))
os.environ.setdefault("SNIPER_DATA_DIR", _DATA_TMP)
atexit.register(shutil.rmtree, _INTEGRITY_TMP, ignore_errors=True)
atexit.register(shutil.rmtree, _DATA_TMP, ignore_errors=True)

import pytest  # noqa: E402
import server  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_limiter():
    """Save and replace global server.LIMITER with a fresh instance per test, then restore."""
    old_limiter = server.LIMITER
    server.LIMITER = server.RateLimiter()
    try:
        yield
    finally:
        server.LIMITER = old_limiter
