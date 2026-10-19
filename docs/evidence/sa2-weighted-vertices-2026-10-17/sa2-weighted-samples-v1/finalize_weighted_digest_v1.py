import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

out = Path(__file__).resolve().parent
sha = lambda data: hashlib.sha256(data).hexdigest()
rows = lambda path: list(csv.DictReader(path.open(newline='', encoding='utf-8-sig')))
assert not (out / 'storage-digest.ai.json').exists(), 'Do not rerun a completed version.'
report = json.loads((out / 'summary.ai.json').read_text())
assert report['result'] == 'passed'
expected = {r['name']: r['sha256'] for r in report['artifacts']}
input_names = ['weighted-packets.csv', 'weighted-records.csv', 'stored-first-streams.csv', 'category-destination-intersections.csv', 'post-declared-packet-windows.csv', 'same-stream-packet-order.csv']
input_hashes = []
for name in input_names:
    data = (out / name).read_bytes()
    assert sha(data) == expected[name]
    input_hashes.append({'name': name, 'sha256': sha(data), 'bytes': len(data)})
packets = rows(out / 'weighted-packets.csv')
records = rows(out / 'weighted-records.csv')
streams = rows(out / 'stored-first-streams.csv')
intersections = rows(out / 'category-destination-intersections.csv')
windows = rows(out / 'post-declared-packet-windows.csv')
weighted_streams = [r for r in streams if r['ordered_weighted_variants']]
pooled_pairs = [{key: row[key] for key in ('first_category', 'second_category', 'first_unique_destinations', 'second_unique_destinations', 'intersection_count')} for row in intersections if row['scope'] == 'pooled_across_all_stored_streams_no_binding_claim']
targets = defaultdict(list)
for row in records:
    targets[int(row['relative_destination_index'])].append(row)
target_rows = [{'relative_destination_index': target, 'stored_record_count': len(items), 'variant_counts': json.dumps(Counter(r['masked_variant_7bits'] for r in items), sort_keys=True), 'stream_offsets': ';'.join(sorted({r['stream_offset'] for r in items}, key=lambda v: int(v, 0))), 'packet_offsets': ';'.join(sorted({r['packet_offset'] for r in items}, key=lambda v: int(v, 0))), 'record_offsets': ';'.join(r['record_offset'] for r in items), 'scope': 'pooled stored occurrences only; no runtime call order or common allocation proved'} for target, items in sorted(targets.items())]
with (out / 'pooled-weighted-target-occurrences.csv').open('w', newline='', encoding='utf-8') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(target_rows[0]))
    writer.writeheader()
    writer.writerows(target_rows)
stats = {'version': 1, 'result': 'passed', 'weighted_stored_streams': len(weighted_streams), 'stored_weighted_variant_sequences': dict(Counter(r['ordered_weighted_variants'] for r in weighted_streams)), 'weighted_packet_count_distribution': dict(Counter(r['count'] for r in packets)), 'post_declared_following_same_stream_opcodes': dict(Counter(r['following_same_stream_opcode'] for r in windows)), 'pooled_category_pairs': pooled_pairs, 'pooled_weighted_destination_groups': len(target_rows), 'pooled_weighted_destinations_in_more_than_one_stream': sum(len({r['stream_offset'] for r in items}) > 1 for items in targets.values()), 'source_inputs_verified': len(input_hashes), 'native_lookahead_access_established_here': False, 'normalization_or_weight_sum_rule_inferred': False, 'runtime_order_or_binding_proved': False, 'script_runs': 'finalize_weighted_digest_v1.py once'}
for item in input_hashes:
    assert sha((out / item['name']).read_bytes()) == item['sha256']
digest = dict(stats, source_artifacts=input_hashes, absent_real_sample_values=['negative signed weights', 'weight256 and larger signed weights', 'zero packet count', 'masked variants3..127', 'destination65535'], observed_boundary_values={'weight0': report['zero_weight_records'], 'weight255': report['weight255_records']})
(out / 'storage-digest.ai.json').write_text(json.dumps(digest, indent=2) + '\n', encoding='utf-8')
lines = ['# Weighted sample storage digest v1', '', 'One run of finalize_weighted_digest_v1.py verified the complete audit\'s recorded input hashes and summarized stored target selectors. No native or engine code was executed.', '', 'Machine result: ' + json.dumps({k: v for k, v in stats.items() if k != 'pooled_category_pairs'}, separators=(',', ':')), '', '| Pooled category A | Pooled category B | A unique targets | B unique targets | Numeric intersection |', '|---|---|---:|---:|---:|']
lines.extend(f"| {r['first_category']} | {r['second_category']} | {r['first_unique_destinations']} | {r['second_unique_destinations']} | {r['intersection_count']} |" for r in pooled_pairs)
lines.extend(['', 'Pooled intersections do not supply any cross-stream execution order, common live scratch binding or initial contents. The earlier audit found zero target intersections between distinct packets within the same stored stream; these statements use different scopes.', '', 'Observed real boundaries include weight0 and255. No negative signed weights, weight256 or larger, zero packet count, variant3..127 or destination65535 occurs here. Their absence is bounded to this Sonic bank and does not constrain native supported values.', '', 'Every weighted record span exactly fills its declared packet data. The following 28 bytes are preserved as available original file bytes, commonly beginning with the next EOS or packet header. Whether the native pipeline reads any of those bytes, and whether a read is used, must come from the separate original-instruction audit. No weight sum or normalization statistic is computed.', '', 'pooled-weighted-target-occurrences.csv retains complete grouped record/packet/stream sites and variant counts for every pooled weighted target. Canonical per-packet and per-record raw bytes remain in weighted-packets.ai.json and the complete CSVs.'])
(out / 'storage-digest.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(json.dumps(stats, separators=(',', ':')))
