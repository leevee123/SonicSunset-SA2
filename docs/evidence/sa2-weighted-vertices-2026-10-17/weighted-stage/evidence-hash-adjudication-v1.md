# Two historical text-hash fields

PASS: both human reports match their sealed manifest CSV raw-file hashes. Their two human_report_sha256 fields instead exactly identify the same text with LF newlines. The finalizers write text with default Windows CRLF translation but hash human.encode(), which still contains LF. This accounts for every differing byte without changing report content.

The raw-byte identities and normalized-text identities are both retained in the CSV and AI companion. evidence-recheck-v1 remains unchanged with its strict raw-byte FAIL result. A new recheck may accept only these exact two LF-text fields after verifying this adjudication and sealed manifest identities; no other mismatch is waived. No original, frozen artifact, existing report, finalizer, manifest, repository file or database was changed.
