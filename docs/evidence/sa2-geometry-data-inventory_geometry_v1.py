import csv
import hashlib
import json
import re
import struct
from collections import Counter, defaultdict
from pathlib import Path

out = Path(__file__).resolve().parent
base = out.parents[1]
draw = base / 'work/sa2-draw-data-v1'
consumers = base / 'work/sa2-payload-consumers'
sha = lambda data: hashlib.sha256(data).hexdigest()
number = lambda value: int(value, 0)
rows = lambda path: list(csv.DictReader(path.open(newline='', encoding='utf-8-sig')))
protected = {}
assert not (out / 'summary.ai.json').exists(), 'Do not rerun a completed version.'

def protect(path, role, expected=None):
    path = path.resolve()
    data = path.read_bytes()
    digest = sha(data)
    assert expected is None or expected == digest, str(path)
    record = protected.setdefault(path, {'path': str(path), 'roles': set(), 'bytes_before': len(data), 'sha256_before': digest, 'expected_sha256': expected or ''})
    assert record['sha256_before'] == digest
    record['roles'].add(role)
    if expected:
        assert not record['expected_sha256'] or record['expected_sha256'] == expected
        record['expected_sha256'] = expected
    return data

def write(name, values, fields=None):
    if fields is None:
        fields = list(dict.fromkeys(key for row in values for key in row))
    with (out / name).open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(values)

protect(draw / 'summary.ai.json', 'prior_draw_inventory_report')
prior = json.loads((draw / 'summary.ai.json').read_text())
assert prior['result'] == 'passed'
prior_hashes = {r['name']: r['sha256'] for r in prior['artifacts']}
for name in ('commands.csv', 'geometry-40-42-raw-spans.csv', 'source-digests.csv'):
    protect(draw / name, 'prior_draw_inventory', prior_hashes[name])
for record in rows(draw / 'source-digests.csv'):
    protect(Path(record['path']), 'prior_protected_source', record['sha256_after'])
protect(Path(__file__), 'inventory_script')
decoded = protect(base / 'work/sa2-disc/sonicmdl.prs.decoded', 'original_decoded_bank', 'b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963')
assert len(decoded) == 136360
dol = protect(base / 'work/sa2-disc/main.dol', 'original_DOL', 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e')
mapping = json.loads((base / 'work/dol-elf-mapping-final.json').read_text())
def dol_offset(address):
    matches = [m['dol_offset'] + address - m['address'] for m in mapping['mappings'] if m['address'] <= address < m['address'] + m['size']]
    assert len(matches) == 1
    return matches[0]

def rotate_mask(begin, end):
    return sum(1 << (31 - bit) for bit in range(32) if (begin <= bit <= end if begin <= end else bit >= begin or bit <= end))

function_entries = {0x8011d594: ('plain_1_plus_high2', 'psVar2 = psVar2 + (param_3 >> 0xe & 3) + 1;'), 0x8011d6a4: ('plain_fallback_1_plus_high2', 'psVar2 = psVar2 + (param_3 >> 0xe & 3) + 1;'), 0x8011fef4: ('plain_alternate_1_plus_high2', 'psVar2 = psVar2 + (param_3 >> 0xe & 3) + 1;'), 0x8011d7b4: ('three_halfwords', 'psVar5 = psVar5 + 3;'), 0x8011d91c: ('three_fallback_plus_high2', 'psVar2 = psVar2 + (param_3 >> 0xe & 3) + 3;'), 0x8011fff4: ('three_alternate_plus_high2', 'psVar5 = psVar5 + (param_3 >> 0xe & 3) + 3;')}
source_rows = rows(consumers / 'consumer-source-artifacts.csv')
original_words = []
source_features = []
for entry, (layout, expression) in sorted(function_entries.items()):
    records = [r for r in source_rows if r['view'] == 'sda' and number(r['entry']) == entry and r['kind'] == 'pseudocode']
    assert len(records) == 1
    source = records[0]
    text = protect(Path(source['path']), 'reader_C_first', source['sha256']).decode('utf-8')
    assert expression in text and 'param_3 & 0x3fff' in text
    assert re.search(r'if \(\(int\)uVar\d+ < 0\)', text)
    assert re.search(r'uVar\d+ = -uVar\d+;', text)
    selected_lines = [(index, line.strip()) for index, line in enumerate(text.splitlines(), 1) if expression in line or 'param_3 & 0x3fff' in line or re.search(r'uVar\d+ = -uVar\d+;', line) or ' * 0x20)' in line or re.search(r'sVar\d+ = psVar\d+\[[12]\];', line)]
    source_features.extend({'entry': hex(entry), 'dol_entry_offset': hex(dol_offset(entry)), 'source_path': source['path'], 'source_sha256': source['sha256'], 'line': index, 'text': line, 'candidate_layout': layout} for index, line in selected_lines)
    address_values = [int(value, 16) for value in re.findall(r'[0-9a-fA-F]{8}', source['body_ranges'])]
    assert address_values and len(address_values) % 2 == 0
    lower14_mask_found = False
    for index in range(0, len(address_values), 2):
        start, finish = address_values[index:index + 2]
        assert start % 4 == 0 and finish % 4 == 3
        for address in range(start, finish + 1, 4):
            offset = dol_offset(address)
            word = struct.unpack_from('>I', dol, offset)[0]
            opcode = word >> 26
            item = {'entry': hex(entry), 'address': hex(address), 'dol_offset': hex(offset), 'word': hex(word), 'opcode': opcode, 'RT_RS': (word >> 21) & 31, 'RA': (word >> 16) & 31}
            if opcode in (14, 15, 40, 42):
                immediate = word & 0xffff
                item.update(immediate_u16=immediate, immediate_s16=immediate if immediate < 0x8000 else immediate - 0x10000)
            if opcode == 21:
                shift, begin, end = (word >> 11) & 31, (word >> 6) & 31, (word >> 1) & 31
                mask = rotate_mask(begin, end)
                item.update(shift=shift, mask_begin=begin, mask_end=end, mask=hex(mask))
                lower14_mask_found |= shift == 0 and mask == 0x3fff
            if opcode == 31:
                item.update(RB=(word >> 11) & 31, extended_opcode=(word >> 1) & 1023)
            original_words.append(item)
    assert lower14_mask_found, hex(entry)

commands = rows(draw / 'geometry-40-42-raw-spans.csv')
assert len(commands) == prior['geometry_commands'] == 73
u16 = lambda offset: struct.unpack_from('>H', decoded, offset)[0]
signed = lambda value: value if value < 0x8000 else value - 0x10000
packet_rows, run_rows, corner_rows, extra_rows, oracle = [], [], [], [], []
for source in sorted(commands, key=lambda row: number(row['offset'])):
    offset = number(source['offset'])
    header, size_word, info = (u16(offset + delta) for delta in (0, 2, 4))
    opcode = header & 0xff
    end = offset + 4 + size_word * 2
    assert opcode in (0x40, 0x41, 0x42)
    assert end == number(source['next_offset']) and decoded[offset:end].hex() == source['raw_bytes']
    assert sha(decoded[offset:end]) == source['raw_sha256']
    run_count, extra_count = info & 0x3fff, info >> 14
    assert run_count > 0 and extra_count == 0, 'This version validates the observed nonzero-count/zero-group-bit sample only.'
    stride = 1 + extra_count if opcode == 0x40 else 3
    layout = 'plain_one_index_plus_info_high2_extra_halfwords' if opcode == 0x40 else 'index_plus_two_raw_extra_halfwords'
    position = offset + 6
    parsed_runs = []
    packet_corner_count = 0
    for run_index in range(run_count):
        count_offset = position
        assert position + 2 <= end
        raw_count = u16(position)
        signed_count = signed(raw_count)
        assert signed_count != 0, 'A native do-while zero count cannot be interpreted as an empty run.'
        corner_count = abs(signed_count)
        position += 2
        corners_start = position
        assert position + corner_count * stride * 2 <= end, hex(offset)
        parsed_corners = []
        for corner_index in range(corner_count):
            start = position
            words = [u16(position + field * 2) for field in range(stride)]
            raw_index, signed_index = words[0], signed(words[0])
            position += stride * 2
            item = {'command_offset': hex(offset), 'run_index': run_index, 'corner_index': corner_index, 'file_offset': hex(start), 'byte_size': position - start, 'raw_bytes': decoded[start:position].hex(), 'index_raw_u16': raw_index, 'index_signed16': signed_index, 'index_scaled_32_signed_candidate': signed_index * 0x20, 'extra_raw_words': '|'.join(hex(word) for word in words[1:]), 'extra_signed16_views': '|'.join(str(signed(word)) for word in words[1:])}
            corner_rows.append(item)
            parsed_corners.append(item)
            extra_rows.extend({'command_offset': hex(offset), 'run_index': run_index, 'corner_index': corner_index, 'extra_index': field - 1, 'file_offset': hex(start + field * 2), 'raw_2_bytes': decoded[start + field * 2:start + field * 2 + 2].hex(), 'u16': words[field], 's16': signed(words[field]), 'semantics': 'unknown; raw halfword passed or skipped according to selected consumer'} for field in range(1, stride))
        packet_corner_count += corner_count
        run_record = {'command_offset': hex(offset), 'run_index': run_index, 'count_offset': hex(count_offset), 'raw_count_word': hex(raw_count), 'signed_count': signed_count, 'magnitude': corner_count, 'corner_stride_halfwords': stride, 'corners_offset': hex(corners_start), 'end_exclusive': hex(position), 'byte_size': position - count_offset, 'raw_bytes': decoded[count_offset:position].hex(), 'raw_sha256': sha(decoded[count_offset:position])}
        run_rows.append(run_record)
        parsed_runs.append(dict(run_record, corners=parsed_corners))
    tail = decoded[position:end]
    record = {'command_offset': hex(offset), 'header': hex(header), 'opcode': hex(opcode), 'encoded_size_halfwords': size_word, 'info_word': hex(info), 'info_low14_run_count': run_count, 'info_high2': extra_count, 'layout_candidate': layout, 'corner_stride_halfwords': stride, 'data_offset': hex(offset + 6), 'declared_end_exclusive': hex(end), 'candidate_consumed_end_exclusive': hex(position), 'candidate_consumed_data_bytes': position - offset - 6, 'candidate_corner_count': packet_corner_count, 'unconsumed_tail_offset': hex(position), 'unconsumed_tail_bytes': len(tail), 'unconsumed_tail_raw': tail.hex(), 'unconsumed_tail_sha256': sha(tail), 'raw_command_bytes': decoded[offset:end].hex(), 'raw_command_sha256': sha(decoded[offset:end]), 'raw_data_bytes': decoded[offset + 6:end].hex(), 'raw_data_sha256': sha(decoded[offset + 6:end]), 'assumption': 'isolated basic reader with raw info; native pending-group/shared-state selection unobserved'}
    packet_rows.append(record)
    oracle.append(dict(record, runs=parsed_runs))
assert sum(r['candidate_consumed_data_bytes'] + r['unconsumed_tail_bytes'] for r in packet_rows) == prior['geometry_raw_data_bytes']
assert sum(r['magnitude'] for r in run_rows) == len(corner_rows)
assert sum(2 + r['magnitude'] * r['corner_stride_halfwords'] * 2 for r in run_rows) == sum(r['candidate_consumed_data_bytes'] for r in packet_rows)
write('geometry-packets.csv', packet_rows)
write('geometry-runs.csv', run_rows)
write('geometry-corners.csv', corner_rows)
write('geometry-extra-halfwords.csv', extra_rows)
write('reader-source-features.csv', source_features)
write('reader-original-words.csv', original_words)
digests = []
for path, record in sorted(protected.items(), key=lambda pair: str(pair[0])):
    data = path.read_bytes()
    assert sha(data) == record['sha256_before'] and len(data) == record['bytes_before'], str(path)
    digests.append(dict(record, roles='|'.join(sorted(record['roles'])), sha256_after=sha(data), bytes_after=len(data), unchanged=True))
write('source-digests.csv', digests)
stats = {'version': 1, 'result': 'passed_candidate_basic_layouts', 'decoded_bytes': len(decoded), 'decoded_sha256': sha(decoded), 'geometry_commands': len(packet_rows), 'opcodes': dict(Counter(r['opcode'] for r in packet_rows)), 'commands_with_nonzero_info_high2': sum(r['info_high2'] != 0 for r in packet_rows), 'signed_run_records': len(run_rows), 'negative_signed_run_counts': sum(r['signed_count'] < 0 for r in run_rows), 'positive_signed_run_counts': sum(r['signed_count'] > 0 for r in run_rows), 'zero_signed_run_counts': sum(r['signed_count'] == 0 for r in run_rows), 'signed_run_count_min': min(r['signed_count'] for r in run_rows), 'signed_run_count_max': max(r['signed_count'] for r in run_rows), 'corner_records': len(corner_rows), 'corners_by_opcode': dict(Counter(next(p['opcode'] for p in packet_rows if p['command_offset'] == r['command_offset']) for r in corner_rows)), 'index_raw_min': min(r['index_raw_u16'] for r in corner_rows), 'index_raw_max': max(r['index_raw_u16'] for r in corner_rows), 'negative_signed_indices': sum(r['index_signed16'] < 0 for r in corner_rows), 'unique_raw_indices': len({r['index_raw_u16'] for r in corner_rows}), 'extra_halfword_rows': len(extra_rows), 'extra_halfword_signed_min': min(r['s16'] for r in extra_rows), 'extra_halfword_signed_max': max(r['s16'] for r in extra_rows), 'declared_geometry_data_bytes': prior['geometry_raw_data_bytes'], 'candidate_consumed_data_bytes': sum(r['candidate_consumed_data_bytes'] for r in packet_rows), 'unconsumed_tail_bytes': sum(r['unconsumed_tail_bytes'] for r in packet_rows), 'unconsumed_tail_lengths': dict(Counter(r['unconsumed_tail_bytes'] for r in packet_rows)), 'unconsumed_tail_raw_patterns': dict(Counter(r['unconsumed_tail_raw'] for r in packet_rows)), 'selected_reader_functions': len(function_entries), 'original_reader_instruction_words': len(original_words), 'protected_files_unchanged': len(digests), 'recorded_hashes_verified': sum(bool(r['expected_sha256']) for r in digests), 'offset_space': 'decoded sonicmdl.prs; original reader words have separate DOL offsets', 'native_execution': False, 'engine_execution': False, 'runtime_path_selected': False, 'topology_or_normalized_extra_field_meaning_inferred': False, 'engine_files_changed': [], 'script_runs': 'inventory_geometry_v1.py once'}
unknowns = ['Actual runtime parser pending-group state, header overrides, consumer branch and cache/caller ordering.', 'Topology, winding, normalized attribute meanings and any relation between signed run count sign and rendering output.', 'Meaning of remaining tail bytes; they are preserved as unconsumed bytes under the basic candidate layout.', 'Scratch availability/initialization, complete vertex data, numeric transforms and FIFO transcript.', 'Opcode42 and nonzero info-high2 inner layouts have source observations but no real sample validation here.']
summary = dict(stats, candidate_contract={'run_count': 'info & 0x3fff; only observed nonzero counts validated', 'run_prefix': 'BE signed16; magnitude determines number of corner records in these native readers', 'plain_stride_halfwords': '1+((info>>14)&3), equal1 for all seven sample opcode40 commands', 'three_word_stride_halfwords': '3 in D7B4; 3+((info>>14)&3) in D91C/FFF4, equal3 in all sample opcode41 commands', 'corner_index': 'first BE signed16 used with *0x20 in reader C; both signed and unsigned raw views retained', 'extra_fields': 'raw halfwords only; no normalized interpretation', 'tail': 'all remaining declared bytes preserved; not silently discarded or semantically named', 'context': 'basic isolated reader with raw info; no claim of native branch or pending-state selection'}, unknowns=unknowns)
(out / 'geometry-oracle.ai.json').write_text(json.dumps({'summary': stats, 'packets': oracle}, indent=2) + '\n', encoding='utf-8')
summary['artifacts'] = [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())} for p in sorted(out.iterdir()) if p.is_file() and p.name not in ('summary.md', 'summary.ai.json')]
(out / 'summary.ai.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
lines = ['# Real Sonic inner geometry inventory v1', '', 'One run of inventory_geometry_v1.py passed for all 73 basic candidate layouts. This validates a raw file decomposition against the frozen native readers, without establishing the actual runtime consumer branch or topology.', '', 'Machine result: ' + json.dumps(stats, separators=(',', ':')), '', '## Source and context', '', 'C was read first. 0x8011D594 / DOL 0x11A594, 0x8011D6A4 / DOL 0x11A6A4 and 0x8011FEF4 / DOL 0x11CEF4 read each signed run count, use its magnitude and advance corner records by 1+((info>>14)&3) halfwords. 0x8011D7B4 / DOL 0x11A7B4 advances by three halfwords; 0x8011D91C / DOL 0x11A91C and 0x8011FFF4 / DOL 0x11CFF4 use 3+((info>>14)&3). Each uses info&0x3FFF as its run counter and signed first-halfword index times 0x20. Raw words for all six recorded function bodies were extracted from the original DOL and the lower14 rotate-mask instruction was checked in each body. Exact C features and original addresses are retained in CSV.', '', 'All real sample info high bits are zero. Consequently these observed candidate strides agree across their listed fallbacks. Applying the isolated reader directly to each raw command is an explicit validation context; pending groups, global header overrides and actual consumer selection remain unknown.', '', 'The native loops are do-while. This validator does not coerce zero run or zero corner counts into empty lists; the real sample contains neither. Negative signed run counts are preserved alongside magnitude; no topology or winding interpretation is assigned to their sign.', '', '## Raw output', '', 'geometry-packets.csv retains complete command/data bytes, encoded bounds, candidate consumed bounds and every unconsumed tail byte. geometry-runs.csv retains signed/raw count words and exact spans. geometry-corners.csv retains each first index as raw u16 and signed16, the signed scaled-address candidate, and all extra raw halfwords. geometry-extra-halfwords.csv expands those extras with exact file offsets. geometry-oracle.ai.json nests the same packets/runs/corners for an independent implementation to compare. reader-source-features.csv, reader-original-words.csv and source-digests.csv preserve provenance.', '', 'The term corner identifies a record position within this candidate layout. It does not establish a triangle, strip, vertex identity, UV interpretation or native scratch bounds.', '', 'Unknowns: ' + '; '.join(unknowns), '', 'No engine, repository, original carrier, frozen export, analysis database or processor language was modified. No native or engine execution occurred.']
(out / 'summary.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(json.dumps(stats, separators=(',', ':')))
