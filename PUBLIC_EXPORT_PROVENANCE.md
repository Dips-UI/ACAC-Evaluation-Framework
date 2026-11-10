# Public export provenance

Created 2026-11-10 as a separate sanitized portfolio snapshot from an explicit allowlist of ACAC source, synthetic tests, public-safe specifications, schemas, and synthetic demonstration fixtures. No original `.git` directory, branch, tag, remote, review submission, adjudication record, owner decision record, private capture, benchmark, or staged migration candidate was copied.

The core validation and evaluation modules were copied without edits from the inspected local ACAC working tree. `acac/__main__.py` is intentionally narrowed in this export to expose only `demo`, `evaluate`, and `verify-bundle`; it omits local/controlled backup, reviewer lock, review comparison, and private manual/local experiment commands. Public-facing documentation was written for that reduced CLI surface.

`PUBLIC_EXPORT_ALLOWLIST.txt` is the complete exported file inventory. `PUBLIC_EXPORT_SHA256SUMS.txt` records SHA-256 for every listed file except itself.
