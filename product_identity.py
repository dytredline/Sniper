"""Canonical public product identity.

Technical compatibility identifiers such as the existing environment-variable
prefix and signed artifact schema are intentionally versioned separately from
the public product name.
"""

PRODUCT_NAME = "VulKill"
PRODUCT_NAME_UPPER = "VULKILL"
PRODUCT_SLUG = "vulkill"
COMMUNITY_NAME = f"{PRODUCT_NAME} Community"
ENTERPRISE_NAME = f"{PRODUCT_NAME} Enterprise"


def public_identity() -> dict[str, str]:
    """Return the bounded identity exposed by runtime status surfaces."""

    return {
        "product_name": PRODUCT_NAME,
        "product_slug": PRODUCT_SLUG,
    }
