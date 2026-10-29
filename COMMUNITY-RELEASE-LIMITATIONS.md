# Community source distribution boundaries

This assembled tree is the Sniper Community source distribution.

Commercial delivery, customer-bound licensing, private installer, and native
binary-delivery implementation are intentionally absent. The web runtime uses
the small Community-only version and backup module included in this tree.

Maintainer-only evaluation fixtures, generated caches, database state,
evidence bundles, frozen artifacts, and machine/session-specific documentation
or tests are not copied into this source distribution.

Required runtime files are retained when they contain a machine-specific
literal, but the literal is normalized to a neutral Community placeholder in
the assembled tree. This prevents publishing a maintainer path. The source
archive does not contain third-party engine binaries: the rootless Community
setup installs the seven lock-declared local engines from verified downloads or
an explicit offline cache after license acceptance. Separate databases,
catalogs, and other optional inputs remain host-specific; their availability is
not implied by this archive.
