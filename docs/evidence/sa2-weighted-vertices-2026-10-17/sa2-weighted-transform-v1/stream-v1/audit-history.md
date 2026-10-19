# Final audit version history

`final_audit_v1.py` executed once. Its 309-case arithmetic replay, CRT comparisons, descriptor checks, core artifact checks and source rehashes completed before it stopped while formatting the ISO offset ledger: the JSON hexadecimal ISO base was a string and was added to an integer file offset.

`final_audit_v2.py` preserves the same audit and converts that metadata field with `int(value, 0)`. It also guards the already-frozen case manifest SHA-256 `2ec2e706c87cad90c67918b58a2c1481e1f973a2f8bd25d4da37f87d998f4a9f`. It executed once and passed. No original-word oracle, case schema, case bytes, engine code or original/frozen input changed to address this audit-only formatting failure.

The final paired results are `final-audit.md`, `final-audit.ai.md`, and `final-audit.ai.json`; complete original VA/DOL/ISO word evidence is `original-words-verified.csv`.
