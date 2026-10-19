import csv
import hashlib
import itertools
import json
import math
import struct
from collections import Counter, defaultdict
from pathlib import Path

out = Path(__file__).resolve().parent
base = out.parents[1]
prior = base / 'work/sa2-payload-consumers'
sha = lambda data: hashlib.sha256(data).hexdigest()
number = lambda value: int(value, 0)
protected, schemas = {}, []
assert not (out / 'summary.ai.json').exists(), 'Do not rerun a completed version.'
def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
def protect(path, role, expected=None):
    path = path.resolve()
    digest = file_hash(path)
    assert expected is None or digest == expected, str(path)
    item = protected.setdefault(path, {'path': str(path), 'roles': set(), 'bytes_before': path.stat().st_size, 'sha256_before': digest, 'expected_sha256': expected or ''})
    assert item['sha256_before'] == digest
    item['roles'].add(role)
    if expected:
        assert not item['expected_sha256'] or item['expected_sha256'] == expected
        item['expected_sha256'] = expected
def read_csv(path):
    with path.open(newline='', encoding='utf-8-sig') as stream:
        reader = csv.DictReader(stream)
        values = list(reader)
        schemas.append({'path': str(path.resolve()), 'field_names': reader.fieldnames, 'rows': len(values), 'sha256': file_hash(path)})
        return values
def write(name, values, fields=None):
    if fields is None:
        fields = list(dict.fromkeys(key for row in values for key in row))
    with (out / name).open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(values)

inputs = ['first-stream-sample-packets.csv', 'first-stream-sample-records.csv', 'first-stream-sample-streams.csv', 'sample-payload-headers.csv', 'first-stream-original-mask-words.csv', 'first-stream-validation.ai.json', 'validate_first_stream_v1.py', 'consumer-source-artifacts.csv', 'input-artifacts.csv', 'weighted-source-field-words.csv']
for name in inputs:
    protect(prior / name, 'prior_complete_sample_evidence')
for row in read_csv(prior / 'input-artifacts.csv'):
    protect(Path(row['path']), 'recorded_original_input', row['sha256'])
for row in read_csv(prior / 'consumer-source-artifacts.csv'):
    protect(Path(row['path']), 'recorded_original_code_' + row['kind'], row['sha256'])
protect(base / 'work/sonicmdl-loader/sample-validation.ai.json', 'original_sample_validation')
protect(Path(__file__), 'audit_script')
decoded_path = base / 'work/sa2-bank-layout-v1/decoded-bank.bin'
decoded_sha = 'b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963'
compressed_sha = 'd8f90e6c724e709b8d3431e725a5db1d1a096bdf5118d2ecca9ad356e7862d99'
protect(decoded_path, 'protected_decoded_bank', decoded_sha)
decoded = decoded_path.read_bytes()
assert len(decoded) == 136360
assert decoded == (base / 'work/sa2-disc/sonicmdl.prs.decoded').read_bytes()
iso_path = base / 'work/sa2.iso'
protect(iso_path, 'fixed_original_ISO', 'c8f9db7c936fffed7a5ea12a099c39ad3197208731ebbe4bcdfc3cec9b350638')
sample = json.loads((base / 'work/sonicmdl-loader/sample-validation.ai.json').read_text())['sample']
with iso_path.open('rb') as disc:
    boot = disc.read(0x440)
    assert boot[:6] == b'GSNE8P' and boot[7] == 0
    fst_start, fst_size = struct.unpack_from('>II', boot, 0x424)
    disc.seek(fst_start)
    fst = disc.read(fst_size)
    fst_index = int(sample['fst_index'])
    type_name, stored_offset, stored_size = struct.unpack_from('>III', fst, fst_index * 12)
    string_start = struct.unpack_from('>I', fst, 8)[0] * 12 + (type_name & 0xffffff)
    fst_name = fst[string_start:fst.index(b'\0', string_start)].decode('ascii')
    assert fst_name == 'sonicmdl.prs' and stored_offset == number(sample['disc_offset']) and stored_size == sample['stored_bytes'] == 102331
    disc.seek(stored_offset)
    compressed = disc.read(stored_size)
assert sha(compressed) == compressed_sha and compressed == (base / 'work/sa2-disc/sonicmdl.prs').read_bytes()
cursor = control = remaining = 0
fresh = bytearray()
def byte():
    global cursor
    assert cursor < len(compressed)
    result = compressed[cursor]
    cursor += 1
    return result
def bit():
    global control, remaining
    if not remaining:
        control, remaining = byte(), 8
    value = control & 1
    control >>= 1
    remaining -= 1
    return value
while True:
    if bit():
        fresh.append(byte())
    else:
        if bit():
            word = byte() | byte() << 8
            if word == 0:
                break
            displacement = (word >> 3) - 8192
            count = (word & 7) + 2 if word & 7 else byte() + 1
        else:
            count, displacement = 2 + 2 * bit() + bit(), byte() - 256
        assert 0 <= len(fresh) + displacement < len(fresh)
        for _ in range(count):
            fresh.append(fresh[len(fresh) + displacement])
assert cursor == len(compressed) and fresh == decoded
dol = (base / 'work/sa2-disc/main.dol').read_bytes()
assert sha(dol) == 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'
mapping = json.loads((base / 'work/dol-elf-mapping-final.json').read_text())
def dol_offset(address):
    matches = [m['dol_offset'] + address - m['address'] for m in mapping['mappings'] if m['address'] <= address < m['address'] + m['size']]
    assert len(matches) == 1
    return matches[0]
mask_words = read_csv(prior / 'first-stream-original-mask-words.csv')
for row in mask_words:
    address = number(row['original_virtual_address'])
    assert dol_offset(address) == number(row['dol_offset'])
    assert struct.unpack_from('>I', dol, dol_offset(address))[0] == number(row['word'])
old_packets = read_csv(prior / 'first-stream-sample-packets.csv')
old_records = read_csv(prior / 'first-stream-sample-records.csv')
old_streams = read_csv(prior / 'first-stream-sample-streams.csv')
payloads = read_csv(prior / 'sample-payload-headers.csv')
packet_reference = {number(r['packet_decoded_offset']): r for r in old_packets}
record_reference = {number(r['record_decoded_offset']): r for r in old_records}
stream_reference = {number(r['stream_decoded_offset']): r for r in old_streams}
assert len(packet_reference) == len(old_packets) and len(record_reference) == len(old_records)
u32 = lambda offset: struct.unpack_from('>I', decoded, offset)[0]
owners = defaultdict(list)
for row in payloads:
    payload = number(row['payload_offset'])
    assert decoded[payload:payload + 24].hex() == row['raw_24_bytes']
    assert u32(payload) == number(row['stream_0'])
    if u32(payload):
        owners[u32(payload)].append(payload)

packets, weighted_records, all_records, scalar_words, streams = [], [], [], [], []
lookahead, destination_history = [], []
packet_sets = {}
weighted_nested = []
seen_packet_offsets, seen_record_offsets = set(), set()
for start, payload_owners in sorted(owners.items()):
    position, packet_order, total_records = start, 0, 0
    local_packets, local_history = [], {}
    for _ in range(10000):
        header = u32(position)
        opcode = header & 0xff
        reference = packet_reference[position]
        assert number(reference['raw_header']) == header and number(reference['stream_decoded_offset']) == start and number(reference['opcode']) == opcode
        seen_packet_offsets.add(position)
        item = {'stream_offset': hex(start), 'payload_offsets': ';'.join(map(hex, payload_owners)), 'packet_order_within_stored_stream': packet_order, 'packet_offset': hex(position), 'raw_header': hex(header), 'opcode': hex(opcode), 'terminal': opcode == 0xff, 'ordering': 'stored encoded sequence only; no invocation, node traversal or shared scratch binding proved'}
        if opcode == 0xff:
            end = position + 4
            assert reference['terminal'] == 'True' and decoded[position:end].hex() == reference['raw_span']
            item.update(declared_end_exclusive=hex(end), declared_span_bytes=4, raw_packet_bytes=decoded[position:end].hex(), packet_sha256=sha(decoded[position:end]))
            packets.append(item)
            local_packets.append(item)
            stream_old = stream_reference[start]
            assert number(stream_old['EOS_decoded_offset']) == position
            assert int(stream_old['consumed_bytes_through_EOS']) == end - start and stream_old['consumed_sha256'] == sha(decoded[start:end])
            streams.append({'stream_offset': hex(start), 'payload_offsets': item['payload_offsets'], 'EOS_offset': hex(position), 'declared_end_exclusive': hex(end), 'packet_count_including_EOS': len(local_packets), 'data_packet_count': len(local_packets) - 1, 'records': total_records, 'ordered_packet_offsets': ';'.join(r['packet_offset'] for r in local_packets), 'ordered_opcodes': ';'.join(r['opcode'] for r in local_packets), 'ordered_weighted_variants': ';'.join(str(r['masked_variant_7bits']) for r in local_packets if r['opcode'] == '0x2c'), 'stream_sha256': sha(decoded[start:end])})
            break
        info = u32(position + 4)
        count, first_scratch = info >> 16, info & 0xffff
        size_words, variant = header >> 16, (header & 0x7fff) >> 8
        end = position + 4 * (size_words + 1)
        assert position + 8 <= end <= len(decoded)
        stride = {0x23: 16, 0x29: 24, 0x2c: 28}.get(opcode)
        assert stride is not None, 'Unexpected Sonic opcode remains outside this record inventory.'
        records_end = position + 8 + count * stride
        assert records_end <= end
        assert number(reference['raw_info']) == info and int(reference['count_high16']) == count and int(reference['scratch_start_low16']) == first_scratch
        assert int(reference['encoded_size_high16_words']) == size_words and int(reference['variant_7bits_for_2c']) == variant
        assert number(reference['next_decoded_offset']) == end and int(reference['record_bytes_proven_for_sample_opcode']) == stride
        assert decoded[position:end].hex() == reference['raw_span']
        item.update(raw_info=hex(info), count=count, first_scratch_raw_u16=first_scratch, encoded_size_high16_words=size_words, header_low16_raw=hex(header & 0xffff), header_bit15_set=bool(header & 0x8000), masked_variant_7bits=variant, record_stride_bytes=stride, data_offset=hex(position + 8), records_end_exclusive=hex(records_end), declared_end_exclusive=hex(end), declared_span_bytes=end - position, declared_data_bytes=end - position - 8, unconsumed_tail_bytes=end - records_end, unconsumed_tail_raw=decoded[records_end:end].hex(), raw_packet_bytes=decoded[position:end].hex(), packet_sha256=sha(decoded[position:end]))
        packet_destinations = []
        nested_records = []
        for ordinal in range(count):
            offset = position + 8 + ordinal * stride
            seen_record_offsets.add(offset)
            old = record_reference[offset]
            assert number(old['packet_decoded_offset']) == position and number(old['stream_decoded_offset']) == start and int(old['ordinal']) == ordinal
            assert decoded[offset:offset + stride].hex() == old['raw_record']
            slot_count = 3 if opcode == 0x23 else 6
            words = struct.unpack_from('>' + str(slot_count) + 'I', decoded, offset)
            assert [number(v) for v in old['first_scalar_words'].split(';')] == list(words)
            weight = raw_weight = raw_destination = None
            if opcode == 0x2c:
                raw_weight, raw_destination = struct.unpack_from('>HH', decoded, offset + 24)
                weight = raw_weight if raw_weight < 0x8000 else raw_weight - 0x10000
                assert number(old['raw_weight_halfword']) == raw_weight and int(old['signed_weight_word24']) == weight
                assert int(old['u16_destination_word26']) == raw_destination
                relative_index = first_scratch + raw_destination
            else:
                relative_index = first_scratch + ordinal
            assert int(old['scratch_destination_index']) == relative_index
            packet_destinations.append(relative_index)
            category = '0x2c.variant' + str(variant) if opcode == 0x2c else hex(opcode)
            common = {'stream_offset': hex(start), 'packet_offset': hex(position), 'packet_order_within_stored_stream': packet_order, 'opcode': hex(opcode), 'masked_variant_7bits': variant, 'category': category, 'record_ordinal': ordinal, 'record_offset': hex(offset), 'record_bytes': stride, 'relative_destination_index': relative_index, 'relative_destination_byte_offset': relative_index * 0x20, 'destination_context': 'first_scratch+raw destination for2C; first_scratch+ordinal for23/29; no live base/capacity/binding supplied'}
            all_records.append(common)
            previous = local_history.get(relative_index)
            destination_history.append(dict(common, previous_stored_record_offset='' if previous is None else previous['record_offset'], previous_stored_packet_offset='' if previous is None else previous['packet_offset'], previous_stored_opcode='' if previous is None else previous['opcode'], previous_stored_variant='' if previous is None else previous['masked_variant_7bits'], previous_is_same_packet=previous is not None and previous['packet_offset'] == hex(position), storage_encounter_repeats_destination=previous is not None))
            local_history[relative_index] = common
            if opcode == 0x2c:
                weighted = dict(common, raw_header=hex(header), raw_info=hex(info), first_scratch_raw_u16=first_scratch, raw_record=decoded[offset:offset + stride].hex(), record_sha256=sha(decoded[offset:offset + stride]), raw_weight_halfword=hex(raw_weight), signed_weight=weight, raw_destination_u16=raw_destination, weight_file_offset=hex(offset + 24), destination_file_offset=hex(offset + 26), six_raw_source_words=';'.join(hex(word) for word in words))
                for index, word in enumerate(words):
                    weighted['source_word_' + str(index)] = hex(word)
                    value = struct.unpack('>f', struct.pack('>I', word))[0]
                    classification = 'nan' if math.isnan(value) else 'infinity' if math.isinf(value) else 'negative_zero' if value == 0 and math.copysign(1, value) < 0 else 'positive_zero' if value == 0 else 'finite_nonzero'
                    scalar_words.append({'packet_offset': hex(position), 'record_ordinal': ordinal, 'record_offset': hex(offset), 'word_index': index, 'file_offset': hex(offset + index * 4), 'raw_4_bytes': decoded[offset + index * 4:offset + index * 4 + 4].hex(), 'raw_u32': word, 'f32_candidate': repr(value), 'f32_candidate_class': classification, 'interpretation': 'candidate only; live GQR0/matrix not supplied'})
                weighted_records.append(weighted)
                nested_records.append(dict(weighted, source_words=list(words)))
        total_records += count
        packet_sets[position] = set(packet_destinations)
        item.update(unique_relative_destinations=len(packet_sets[position]), repeated_destination_records=count - len(packet_sets[position]), relative_destination_min=min(packet_destinations) if packet_destinations else '', relative_destination_max=max(packet_destinations) if packet_destinations else '')
        packets.append(item)
        local_packets.append(item)
        if opcode == 0x2c:
            window_end = min(end + 28, len(decoded))
            window = decoded[end:window_end]
            following_header = u32(end) if end + 4 <= len(decoded) else None
            lookahead.append({'stream_offset': hex(start), 'packet_offset': hex(position), 'last_record_offset': hex(records_end - stride) if count else '', 'declared_end_exclusive': hex(end), 'tail_within_declared_span_bytes': end - records_end, 'post_declared_window_offset': hex(end), 'post_declared_available_bytes_up_to28': len(window), 'post_declared_raw_bytes': window.hex(), 'post_declared_sha256': sha(window), 'following_same_stream_header': '' if following_header is None else hex(following_header), 'following_same_stream_opcode': '' if following_header is None else hex(following_header & 0xff), 'following_same_stream_is_EOS': following_header is not None and following_header & 0xff == 0xff, 'native_access_claim': 'none; file availability only; native lookahead belongs to original instruction audit'})
            weighted_nested.append(dict(item, records=nested_records, post_declared_28_bytes=window.hex()))
        packet_order += 1
        position = end
    else:
        raise AssertionError('Unbounded stored first stream.')
assert seen_packet_offsets == set(packet_reference) and seen_record_offsets == set(record_reference)
assert len(weighted_nested) == 83 and len(weighted_records) == 830
weighted_packets = [r for r in packets if r['opcode'] == '0x2c']
packet_intersections = []
for stream in streams:
    same_stream = [p for p in packets if p['stream_offset'] == stream['stream_offset'] and not p['terminal']]
    for earlier, later in itertools.combinations(same_stream, 2):
        overlap = packet_sets[number(earlier['packet_offset'])] & packet_sets[number(later['packet_offset'])]
        packet_intersections.append({'stream_offset': stream['stream_offset'], 'earlier_packet_offset': earlier['packet_offset'], 'earlier_opcode': earlier['opcode'], 'earlier_masked_variant': earlier['masked_variant_7bits'], 'later_packet_offset': later['packet_offset'], 'later_opcode': later['opcode'], 'later_masked_variant': later['masked_variant_7bits'], 'intersection_count': len(overlap), 'intersection_relative_indices': ';'.join(map(str, sorted(overlap))), 'ordering': 'encoded packet order in one stored stream only'})
duplicates = []
for packet in weighted_packets:
    values = [r for r in weighted_records if r['packet_offset'] == packet['packet_offset']]
    grouped = defaultdict(list)
    for row in values:
        grouped[row['relative_destination_index']].append(row)
    duplicates.extend({'packet_offset': packet['packet_offset'], 'masked_variant_7bits': packet['masked_variant_7bits'], 'relative_destination_index': destination, 'record_count': len(items), 'record_offsets': ';'.join(r['record_offset'] for r in items)} for destination, items in grouped.items() if len(items) > 1)
category_intersections = []
for scope, stream_start in [('pooled_across_all_stored_streams_no_binding_claim', None)] + [('same_stored_stream_only', r['stream_offset']) for r in streams]:
    selected = [r for r in all_records if stream_start is None or r['stream_offset'] == stream_start]
    categories = defaultdict(set)
    for row in selected:
        categories[row['category']].add(row['relative_destination_index'])
    for first, second in itertools.combinations(sorted(categories), 2):
        overlap = categories[first] & categories[second]
        category_intersections.append({'scope': scope, 'stream_offset': stream_start or '', 'first_category': first, 'second_category': second, 'first_unique_destinations': len(categories[first]), 'second_unique_destinations': len(categories[second]), 'intersection_count': len(overlap), 'intersection_relative_indices': ';'.join(map(str, sorted(overlap))), 'runtime_interpretation': 'none; target selectors only; no common allocation or initial state supplied'})
weight_histogram = Counter(r['signed_weight'] for r in weighted_records)
destination_histogram = Counter(r['raw_destination_u16'] for r in weighted_records)
boundary_rows = [{'field': 'signed_weight', 'value': value, 'record_count': weight_histogram[value]} for value in (-32768, -1, 0, 1, 127, 128, 254, 255, 256, 32767)] + [{'field': 'raw_destination_u16', 'value': value, 'record_count': destination_histogram[value]} for value in (0, 1, 255, 256, 508, 509, 65535)]
write('weighted-packets.csv', weighted_packets)
write('weighted-records.csv', weighted_records)
write('weighted-source-words.csv', scalar_words)
write('same-stream-packet-order.csv', packets)
write('stored-first-streams.csv', streams)
write('all-record-destination-selectors.csv', all_records)
write('same-stream-destination-history.csv', destination_history)
write('same-stream-packet-intersections.csv', packet_intersections, ['stream_offset', 'earlier_packet_offset', 'earlier_opcode', 'earlier_masked_variant', 'later_packet_offset', 'later_opcode', 'later_masked_variant', 'intersection_count', 'intersection_relative_indices', 'ordering'])
write('weighted-within-packet-duplicate-destinations.csv', duplicates, ['packet_offset', 'masked_variant_7bits', 'relative_destination_index', 'record_count', 'record_offsets'])
write('category-destination-intersections.csv', category_intersections)
write('post-declared-packet-windows.csv', lookahead)
write('weight-value-histogram.csv', [{'signed_weight': value, 'record_count': count} for value, count in sorted(weight_histogram.items())])
write('destination-value-histogram.csv', [{'raw_destination_u16': value, 'record_count': count} for value, count in sorted(destination_histogram.items())])
write('boundary-values.csv', boundary_rows)
write('input-schemas.csv', [dict(r, field_names=';'.join(r['field_names'])) for r in schemas])
source_digests = []
for path, item in sorted(protected.items(), key=lambda pair: str(pair[0])):
    digest = file_hash(path)
    assert digest == item['sha256_before'] and path.stat().st_size == item['bytes_before'], str(path)
    source_digests.append(dict(item, roles='|'.join(sorted(item['roles'])), bytes_after=path.stat().st_size, sha256_after=digest, unchanged=True))
write('source-digests.csv', source_digests)
stats = {'version': 1, 'result': 'passed', 'sample': 'GSNE8P rev0 sonicmdl.prs', 'original_ISO_sha256': protected[iso_path.resolve()]['sha256_before'], 'FST_index': fst_index, 'stored_ISO_offset': hex(stored_offset), 'stored_bytes': len(compressed), 'stored_sha256': sha(compressed), 'PRS_consumed_bytes': cursor, 'decoded_bytes': len(decoded), 'decoded_sha256': sha(decoded), 'stored_first_streams_crosschecked': len(streams), 'all_packet_rows_crosschecked': len(packets), 'all_record_rows_crosschecked': len(all_records), 'original_mask_instruction_rows_verified': len(mask_words), 'weighted_packets': len(weighted_packets), 'weighted_records': len(weighted_records), 'weighted_source_word_rows': len(scalar_words), 'packet_variants': dict(Counter(r['masked_variant_7bits'] for r in weighted_packets)), 'record_variants': dict(Counter(r['masked_variant_7bits'] for r in weighted_records)), 'packet_counts_min_max': [min(r['count'] for r in weighted_packets), max(r['count'] for r in weighted_packets)], 'zero_count_packets': sum(r['count'] == 0 for r in weighted_packets), 'unknown_variants_outside0_1_2': sum(r['masked_variant_7bits'] not in (0, 1, 2) for r in weighted_packets), 'first_scratch_words': dict(Counter(r['first_scratch_raw_u16'] for r in weighted_packets)), 'weighted_header_bit15_set_packets': sum(r['header_bit15_set'] for r in weighted_packets), 'weight_signed_min_max': [min(weight_histogram), max(weight_histogram)], 'weight_unique_values': len(weight_histogram), 'negative_weight_records': sum(r['signed_weight'] < 0 for r in weighted_records), 'zero_weight_records': weight_histogram[0], 'weight255_records': weight_histogram[255], 'weight256_records': weight_histogram[256], 'raw_destination_min_max': [min(destination_histogram), max(destination_histogram)], 'relative_destination_min_max': [min(r['relative_destination_index'] for r in weighted_records), max(r['relative_destination_index'] for r in weighted_records)], 'unique_weighted_relative_destinations': len({r['relative_destination_index'] for r in weighted_records}), 'within_packet_duplicate_destination_groups': len(duplicates), 'weighted_packets_with_declared_tail': sum(r['unconsumed_tail_bytes'] != 0 for r in weighted_packets), 'weighted_declared_tail_bytes': sum(r['unconsumed_tail_bytes'] for r in weighted_packets), 'post_declared_windows': len(lookahead), 'post_declared_available_bytes_histogram': dict(Counter(r['post_declared_available_bytes_up_to28'] for r in lookahead)), 'weighted_packets_followed_by_same_stream_EOS': sum(r['following_same_stream_is_EOS'] for r in lookahead), 'same_stream_packet_pairs': len(packet_intersections), 'same_stream_packet_pairs_with_destination_overlap': sum(r['intersection_count'] > 0 for r in packet_intersections), 'same_stream_weighted_mode_pairs_with_destination_overlap': sum(r['intersection_count'] > 0 and r['earlier_opcode'] == r['later_opcode'] == '0x2c' and r['earlier_masked_variant'] != r['later_masked_variant'] for r in packet_intersections), 'same_stream_2c_vs23_29_pairs_with_overlap': sum(r['intersection_count'] > 0 and (r['earlier_opcode'] == '0x2c') != (r['later_opcode'] == '0x2c') for r in packet_intersections), 'source_f32_candidate_classes': dict(Counter(r['f32_candidate_class'] for r in scalar_words)), 'protected_files_unchanged': len(source_digests), 'recorded_hashes_verified': sum(bool(r['expected_sha256']) for r in source_digests), 'native_or_engine_execution': False, 'normalizing_or_weight_sum_rule_inferred': False, 'runtime_node_stream_order_or_scratch_binding_proved': False, 'offset_space': 'decoded sonicmdl.prs bytes; compressed ISO offset recorded separately', 'script_runs': 'audit_weighted_samples_v1.py once', 'engine_files_changed': []}
oracle = {'summary': stats, 'packets': weighted_nested, 'ordering_contract': 'Only packet_order_within_stored_stream supplies order; do not execute these packets as a global file-sorted stream.', 'external_inputs_unknown': ['actual live matrix words', 'initial scratch bytes/allocation/base/capacity', 'GQR0/FPSCR live context', 'native caller/node traversal and repeated invocation order']}
(out / 'weighted-packets.ai.json').write_text(json.dumps(oracle, indent=2) + '\n', encoding='utf-8')
unknowns = ['Actual matrix inputs are external state, not these six raw record source words.', 'Weight normalization, sums, combined influence meaning and numerical results; no such rule is inferred.', 'Runtime matrix/node traversal, cross-stream order, cache/binding and prior scratch initialization/capacity.', 'The file proves exact declared spans and bytes after them; native pipeline accesses and unused/discarded loads require the separate original instruction audit.', 'Negative/boundary weights, other counts/variants and malformed inputs absent from this real sample remain unvalidated by this inventory.']
report = dict(stats, unknowns=unknowns, schemas=schemas, boundary_values=boundary_rows)
report['artifacts'] = [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': file_hash(p)} for p in sorted(out.iterdir()) if p.is_file() and p.name not in ('summary.md', 'summary.ai.json')]
(out / 'summary.ai.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
lines = ['# Real Sonic weighted record inventory v1', '', 'One run of audit_weighted_samples_v1.py passed. It rehashed the complete original ISO, verified its FST sonicmdl.prs entry, decoded the original compressed bytes again, and matched the protected decoded bank and all prior complete packet/record/stream CSV values. Input schemas and row counts were discovered by the script, not counted manually.', '', 'Machine result: ' + json.dumps(stats, separators=(',', ':')), '', '## Fields and canonical packet list', '', 'weighted-packets.csv and weighted-packets.ai.json are the canonical83-packet list. Each preserves raw header/info, exact decoded offset and declared span, masked variant=(header&7FFF)>>8, count=info>>16 and first-scratch word=info&FFFF. Every 28-byte2C record preserves six raw source words, signed16 weight at byte24dec, unsigned16 target at byte26dec and all raw bytes. Those six words are record inputs; they do not supply or prove the live matrix. Candidate f32 views are explicitly conditional on runtime format.', '', 'The original outer integer masks are0x8011D1D4 / DOL0x11A1D4; all72 previously selected original mask words were checked against the DOL. Original2C consumer0x8011DC98 / DOL0x11AC98 is independently audited for math; this inventory does not infer normalization or accumulation semantics.', '', '## Storage order and target selectors', '', 'same-stream-packet-order.csv preserves every header encountered by following the encoded next pointer within each independently identified stream, including EOS. same-stream-packet-intersections.csv and same-stream-destination-history.csv report target-selector intersections/repeats in that stored order. This is not a proof that a stream is invoked, that different streams share a live scratch allocation or that node traversal follows file order.', '', 'The relative target-selector arithmetic is first_scratch+raw_u16_target for2C and first_scratch+record ordinal for23/29; byte-offset views multiply that index by32. These are relative selectors and do not establish a live base, capacity, initialization or write meaning. Category intersections explicitly distinguish one stored stream from pooled across-stream sets.', '', '## Declared tails and possible lookahead bytes', '', 'Every weighted packet preserves declared tail bytes separately. post-declared-packet-windows.csv retains up to28bytes beginning at each declared end and names its following same-stream header/EOS. Available bytes after a packet are not part of its declared records and are not evidence that native code consumes them. The separate instruction audit must establish prefetch/load order and which results are discarded.', '', 'Complete raw CSVs retain all830 records,4980 source words, packet metadata, stream order, selectors/history/intersections, value histograms, boundary checks, post-declared windows, discovered schemas and unchanged input hashes.', '', 'Unknowns: ' + '; '.join(unknowns), '', 'No engine, repository, original carrier, frozen export, analysis database or processor language was modified. No native or engine execution occurred.']
(out / 'summary.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(json.dumps(stats, separators=(',', ':')))
