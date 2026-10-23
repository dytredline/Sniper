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
the assembled tree. This prevents publishing a maintainer path; it does not
install optional engines or prove that every legacy default is portable.
Operators must provide their own configured data and tool locations. Optional
engine availability remains host-specific and is not implied by this archive.
