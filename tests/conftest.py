import os
import tempfile

# Denetim anahtarı/çapaları kullanıcının ~/.config/sniper dizinine yazılmasın (server içe aktarılmadan önce).
_INTEGRITY_TMP = tempfile.mkdtemp(prefix="sniper-pytest-integrity-")
os.environ.setdefault("SNIPER_AUDIT_KEY_FILE", os.path.join(_INTEGRITY_TMP, "audit.key"))
os.environ.setdefault("SNIPER_AUDIT_ANCHOR_DIR", os.path.join(_INTEGRITY_TMP, "audit-anchors"))

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
