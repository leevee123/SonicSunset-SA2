from pathlib import Path
import json

work = Path(__file__).resolve().parent
stage = work / 'transform-stage'
failure = {'status': 'schema_failure_before_completed_audit', 'version': 1, 'reason': 'preparation-source-digests.csv has an optional empty expected_sha256; v1 selected it before recorded sha256_before/after.', 'source_or_engine_mutation': False, 'correction': 'v2 selects the first populated recorded digest and verifies all populated digest columns agree; original v1 retained.'}
(stage / 'evidence-recheck-failure-v1.ai.json').write_text(json.dumps(failure, indent=2) + '\n')
(stage / 'evidence-recheck-failure-v1.md').write_text('# Evidence recheck v1 schema failure\n\nAn optional expected_sha256 cell was blank; v1 stopped before a completed audit. Recorded before/after digests were present. No source/engine changes. V2 chooses populated digests and requires agreement, preserving v1.\n')
source = (work / 'reverify_transform_evidence_v1.py').read_text()
source = source.replace("digest = row[hash_key]", "digest_columns = [k for k in ('sha256', 'expected_sha256', 'before_sha256', 'sha256_before', 'sha256_after') if k in keys and row.get(k)]\n                digest = row[digest_columns[0]]\n                assert all(row[k] == digest for k in digest_columns), (ledger, path)")
source = source.replace('evidence-recheck-v1', 'evidence-recheck-v2')
exec(compile(source, str(Path(__file__)), 'exec'))
