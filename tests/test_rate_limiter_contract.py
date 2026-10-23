import pytest
import server


class TestRateLimiterContract:
    """Runtime contract test for RateLimiter behavior."""

    def test_limiter_accepts_two_then_rejects_third_for_same_key(self):
        limiter = server.RateLimiter(limit=2, window=60)
        key = "test-key"

        # First two requests for same key should be allowed
        assert limiter.allow(key) is True
        assert limiter.allow(key) is True

        # Third request for same key should be rejected
        assert limiter.allow(key) is False

    def test_limiter_treats_different_keys_independently(self):
        limiter = server.RateLimiter(limit=2, window=60)
        key1 = "key-a"
        key2 = "key-b"

        # Exhaust limit for key1
        assert limiter.allow(key1) is True
        assert limiter.allow(key1) is True
        assert limiter.allow(key1) is False

        # key2 should still be allowed (independent counter)
        assert limiter.allow(key2) is True
        assert limiter.allow(key2) is True
        assert limiter.allow(key2) is False
