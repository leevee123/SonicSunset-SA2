import csv
import hashlib
import json
import re
import struct
from collections import Counter, defaultdict, deque
from pathlib import Path

out = Path(__file__).resolve().parent
base = out.parents[1]
sha = lambda data: hashlib.sha256(data).hexdigest()
number = lambda value: int(value, 0)
rows = lambda path: list(csv.DictReader(path.open(newline='', encoding='utf-8-sig')))
protected = {}
limits = {'candidate_files': 64, 'decoded_bytes_per_file': 8 * 1024 * 1024, 'decoded_bytes_total': 128 * 1024 * 1024, 'table_entries_per_file': 4096, 'unique_nodes_per_file': 20000, 'local_commands_per_entry': 10000, 'unique_commands_per_file': 100000, 'first_stream_packets': 10000, 'collected_streams_host_bound': 4}
assert not (out / 'summary.ai.json').exists(), 'Do not rerun a completed version.'

def file_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()

def protect(path, role, expected=None):
    path = path.resolve()
    digest = file_sha(path)
    assert expected is None or digest == expected, str(path)
    item = protected.setdefault(path, {'path': str(path), 'roles': set(), 'sha256_before': digest, 'bytes_before': path.stat().st_size, 'expected_sha256': expected or ''})
    assert item['sha256_before'] == digest
    item['roles'].add(role)
    if expected:
        assert not item['expected_sha256'] or item['expected_sha256'] == expected
        item['expected_sha256'] = expected

def write(name, values, fields=None):
    if fields is None:
        fields = list(dict.fromkeys(key for row in values for key in row))
    with (out / name).open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(values)

class ScanError(Exception):
    def __init__(self, reason, offset=None):
        self.reason, self.offset = reason, offset
        super().__init__(reason + ('' if offset is None else ' @' + hex(offset)))

def require(condition, reason, offset=None):
    if not condition:
        raise ScanError(reason, offset)

loader = base / 'work/sonicmdl-loader'
for name in ('input-artifacts.csv', 'loader-source-artifacts.csv', 'filename-source-artifacts.csv', 'filename-source-references.csv', 'original-filename-strings.csv'):
    protect(loader / name, 'prior_loader_evidence')
for row in rows(loader / 'input-artifacts.csv'):
    protect(Path(row['path']), 'recorded_loader_input', row['sha256'])
for name in ('loader-source-artifacts.csv', 'filename-source-artifacts.csv'):
    for row in rows(loader / name):
        protect(Path(row['path']), 'recorded_original_code_' + row['kind'], row['sha256'])
for row in rows(loader / 'filename-source-references.csv'):
    assert Path(row['source_path']).read_text().splitlines()[int(row['line']) - 1].strip() == row['text']
protect(base / 'work/sa2-payload-consumers/consumer-source-artifacts.csv', 'consumer_source_manifest')
for row in rows(base / 'work/sa2-payload-consumers/consumer-source-artifacts.csv'):
    if row['entry'] in ('0x8011ccf8', '0x80120158'):
        protect(Path(row['path']), 'recorded_group_parser_source', row['sha256'])
protect(base / 'work/prs-validation.csv', 'prior_all_PRS_validation')
protect(Path(__file__), 'search_script')
iso_path = base / 'work/sa2.iso'
protect(iso_path, 'original_ISO_full_digest')
dol = (base / 'work/sa2-disc/main.dol').read_bytes()
assert sha(dol) == 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'
mapping = json.loads((base / 'work/dol-elf-mapping-final.json').read_text())
def original_offset(address):
    matches = [m['dol_offset'] + address - m['address'] for m in mapping['mappings'] if m['address'] <= address < m['address'] + m['size']]
    assert len(matches) == 1
    return matches[0]
name_map = dol[original_offset(0x801764b8):original_offset(0x801764b8) + 256]
fold = lambda value: bytes(name_map[b] for b in value)
literal_rows = []
literal_names = defaultdict(list)
for row in rows(loader / 'original-filename-strings.csv'):
    offset = number(row['dol_offset'])
    value = bytes.fromhex(row['bytes'])
    assert dol[offset:offset + len(value)] == value and dol[offset + len(value)] == 0
    assert original_offset(number(row['virtual_address'])) == offset
    if value.upper().endswith(b'MDL.PRS'):
        item = dict(row, matching_rule='original literal ends MDL.PRS; name alone does not prove bank format')
        if not any(r['dol_offset'] == item['dol_offset'] for r in literal_rows):
            literal_rows.append(item)
            literal_names[fold(value)].append(item)
prs_expected = {r['path']: r for r in rows(base / 'work/prs-validation.csv')}
fst_rows = []
with iso_path.open('rb') as disc:
    boot = disc.read(0x440)
    assert boot[:6] == b'GSNE8P' and boot[7] == 0
    dol_iso, fst_iso, fst_size = struct.unpack_from('>III', boot, 0x420)
    disc.seek(dol_iso)
    assert disc.read(len(dol)) == dol
    disc.seek(fst_iso)
    fst = disc.read(fst_size)
    root_count = struct.unpack_from('>I', fst, 8)[0]
    string_base = root_count * 12
    directories = [('', root_count)]
    for index in range(1, root_count):
        while index >= directories[-1][1]:
            directories.pop()
        type_name, start, length = struct.unpack_from('>III', fst, index * 12)
        name_offset = string_base + (type_name & 0xffffff)
        name = fst[name_offset:fst.index(b'\0', name_offset)].decode('ascii')
        path = directories[-1][0] + name
        if type_name >> 24:
            directories.append((path + '/', length))
        else:
            fst_rows.append({'fst_index': index, 'path': path, 'basename': name, 'fst_entry_iso_offset': hex(fst_iso + index * 12), 'fst_name_iso_offset': hex(fst_iso + name_offset), 'stored_file_iso_offset': hex(start), 'stored_file_bytes': length})
candidates = [r for r in fst_rows if r['basename'].upper().endswith('MDL.PRS')]
assert len(candidates) <= limits['candidate_files']

def decode_prs(data):
    cursor = 0
    control = remaining = 0
    output = bytearray()
    def byte():
        nonlocal cursor
        require(cursor < len(data), 'PRS source EOF', cursor)
        value = data[cursor]
        cursor += 1
        return value
    def bit():
        nonlocal control, remaining
        if not remaining:
            control, remaining = byte(), 8
        value = control & 1
        control >>= 1
        remaining -= 1
        return value
    while True:
        if bit():
            output.append(byte())
        else:
            if bit():
                word = byte() | byte() << 8
                if word == 0:
                    return bytes(output), cursor
                displacement = (word >> 3) - 8192
                count = (word & 7) + 2 if word & 7 else byte() + 1
            else:
                count = 2 + 2 * bit() + bit()
                displacement = byte() - 256
            require(0 <= len(output) + displacement < len(output), 'PRS invalid source displacement', cursor)
            require(len(output) + count <= limits['decoded_bytes_per_file'], 'decoded byte host bound', cursor)
            for _ in range(count):
                output.append(output[len(output) + displacement])
        require(len(output) <= limits['decoded_bytes_per_file'], 'decoded byte host bound', cursor)

assets, errors, tables, nodes_all, payloads_all, streams_all, commands_all, groups, group_streams = [], [], [], [], [], [], [], [], []
total_decoded = 0
sample_folder = out / 'samples'
sample_folder.mkdir(exist_ok=True)
for candidate in candidates:
    path = candidate['path']
    record = dict(candidate)
    matches = literal_names.get(fold(candidate['basename'].encode()), [])
    record['original_literal_VAs'] = '|'.join(r['virtual_address'] for r in matches)
    record['candidate_selection'] = 'FST basename ends MDL.PRS' + ('; exact original-folded DOL literal match' if matches else '; no literal in bounded prior literal set')
    record['stage'] = stage = 'PRS_decode'
    data = None
    try:
        with iso_path.open('rb') as disc:
            disc.seek(number(candidate['stored_file_iso_offset']))
            compressed = disc.read(candidate['stored_file_bytes'])
        require(len(compressed) == candidate['stored_file_bytes'], 'ISO candidate truncated')
        record['stored_sha256'] = sha(compressed)
        data, consumed = decode_prs(compressed)
        total_decoded += len(data)
        require(total_decoded <= limits['decoded_bytes_total'], 'total decoded host bound')
        expected = prs_expected[path]
        require(len(data) == int(expected['decompressed_size']) and sha(data) == expected['sha256'], 'prior PRS decoded identity mismatch')
        require(consumed == int(expected['consumed_size']), 'prior PRS consumed-size mismatch')
        require(number(expected['disc_offset']) == number(candidate['stored_file_iso_offset']) and int(expected['compressed_size']) == len(compressed), 'prior PRS FST identity mismatch')
        record.update(decoded_bytes=len(data), decoded_sha256=sha(data), prs_consumed_bytes=consumed, prs_trailing_bytes=len(compressed) - consumed)
        stem = str(candidate['fst_index']).zfill(4) + '-' + candidate['basename']
        (sample_folder / (stem + '.stored.bin')).write_bytes(compressed)
        decoded_path = sample_folder / (stem + '.decoded.bin')
        decoded_path.write_bytes(data)
        record['decoded_sample_path'] = str(decoded_path)
        def get32(offset):
            require(0 <= offset and offset + 4 <= len(data), 'u32 outside decoded file', offset)
            return struct.unpack_from('>I', data, offset)[0]
        def get16(offset):
            require(0 <= offset and offset + 2 <= len(data), 'u16 outside decoded file', offset)
            return struct.unpack_from('>H', data, offset)[0]
        def pointer(word, minimum, label, alignment=4):
            require(word == 0 or not word & 0x80000000 and word % alignment == 0 and word + minimum <= len(data), 'outside aligned self-contained candidate domain: ' + label, word)
        stage = 'candidate_table_and_nodes'
        table = []
        position = 0
        for _ in range(limits['table_entries_per_file']):
            identifier = get32(position)
            if identifier == 0xffffffff:
                break
            identifier = identifier if identifier < 0x80000000 else identifier - 0x100000000
            root = get32(position + 4)
            pointer(root, 0x34, 'table root')
            table.append({'path': path, 'entry_offset': hex(position), 'id_signed': identifier, 'raw_root_word': hex(root)})
            position += 8
        else:
            raise ScanError('table host bound without sentinel', position)
        require(bool(table), 'empty candidate table')
        node_rows, payloads, visited, active = {}, {}, set(), set()
        stack = [(number(r['raw_root_word']), False) for r in reversed(table) if number(r['raw_root_word'])]
        while stack:
            node, leaving = stack.pop()
            if leaving:
                active.remove(node)
                continue
            require(node not in active, 'active linked-node cycle in candidate', node)
            if node in visited:
                continue
            visited.add(node)
            active.add(node)
            require(len(visited) <= limits['unique_nodes_per_file'], 'unique node host bound', node)
            payload, first, second = get32(node + 4), get32(node + 0x2c), get32(node + 0x30)
            pointer(payload, 8, 'node payload')
            pointer(first, 0x34, 'node A')
            pointer(second, 0x34, 'node B')
            node_rows[node] = {'path': path, 'node_offset': hex(node), 'raw_52_bytes': data[node:node + 0x34].hex(), 'payload_word': hex(payload), 'link_A_word': hex(first), 'link_B_word': hex(second)}
            if payload:
                first_stream, second_stream = get32(payload), get32(payload + 4)
                pointer(first_stream, 4, 'payload+0')
                pointer(second_stream, 2, 'payload+4', 2)
                payloads[payload] = {'path': path, 'payload_offset': hex(payload), 'raw_8_bytes': data[payload:payload + 8].hex(), 'stream0_candidate': hex(first_stream), 'stream4_candidate': hex(second_stream)}
            stack.append((node, True))
            for child in (second, first):
                if child:
                    stack.append((child, False))
        require(bool(node_rows) and bool(payloads), 'no linked nodes or payloads in candidate')
        tables.extend(table)
        nodes_all.extend(node_rows.values())
        payloads_all.extend(payloads.values())
        record.update(table_entries=len(table), sentinel_offset=hex(position), unique_nodes=len(node_rows), unique_payloads=len(payloads))
        stage = 'candidate_stream0_outer_checks'
        first_starts = sorted({number(r['stream0_candidate']) for r in payloads.values()} - {0})
        first_pass = 0
        for start in first_starts:
            offset = start
            try:
                for _ in range(limits['first_stream_packets']):
                    header = get32(offset)
                    if header & 0xff == 0xff:
                        break
                    get32(offset + 4)
                    end = offset + 4 * ((header >> 16) + 1)
                    require(offset < end <= len(data), 'first-stream encoded skip outside candidate', offset)
                    offset = end
                else:
                    raise ScanError('first-stream packet host bound', start)
                first_pass += 1
            except ScanError as error:
                errors.append({'path': path, 'stage': stage, 'entry_offset': hex(start), 'error_offset': '' if error.offset is None else hex(error.offset), 'reason': error.reason})
        record.update(first_stream_entries=len(first_starts), first_stream_outer_pass=first_pass)
        stage = 'candidate_stream4_outer_scan'
        second_starts = sorted({number(r['stream4_candidate']) for r in payloads.values()} - {0})
        queue = deque(second_starts)
        entries, asset_commands = {}, {}
        while queue:
            start = queue.popleft()
            if start in entries:
                continue
            offset = start
            local = []
            pending = None
            entry_record = {'path': path, 'entry_offset': hex(start), 'entry_role': 'payload+4 candidate' if start in second_starts else 'following cache definition pointer'}
            try:
                for order in range(limits['local_commands_per_entry']):
                    header = get16(offset)
                    opcode = header & 0xff
                    item = {'path': path, 'offset': hex(offset), 'header': hex(header), 'opcode': hex(opcode), 'entry_offset': hex(start), 'local_order': order}
                    if header == 0xff:
                        end, kind = offset + 2, 'exact_00ff_return'
                    elif opcode == 4:
                        end, kind = offset + 2, 'cache_define_following_pointer_and_return'
                        item.update(cache_slot=header >> 8, cache_body_offset=hex(end))
                        queue.append(end)
                    elif opcode == 5:
                        end, kind = offset + 2, 'cache_reference_then_conditional_local_resume'
                        item.update(cache_slot=header >> 8)
                    elif opcode < 8:
                        end, kind = offset + 2, 'single_halfword'
                    elif opcode < 0x10:
                        end, kind = offset + 4, 'two_halfwords'
                        item['argument_raw'] = hex(get16(offset + 2))
                    elif opcode < 0x40:
                        size_word = get16(offset + 2)
                        signed_size = size_word if size_word < 0x8000 else size_word - 0x10000
                        require(signed_size >= 0, 'negative state size outside bounded scan domain', offset + 2)
                        end, kind = offset + 4 + signed_size * 2, 'signed_size_operation'
                        item['size_word'] = hex(size_word)
                    else:
                        size_word, info = get16(offset + 2), get16(offset + 4)
                        end, kind = offset + 4 + size_word * 2, 'geometry_40_42' if opcode <= 0x42 else 'other_high_operation'
                        signed_info = info if info < 0x8000 else info - 0x10000
                        expression = (signed_info & 0xffffffff) >> 14
                        item.update(size_word=hex(size_word), info_word=hex(info), raw_info_high2=info >> 14, original_pending_expression=expression, data_offset=hex(offset + 6), data_bytes=end - offset - 6)
                    require(offset < end <= len(data), 'second-stream encoded skip outside candidate', offset)
                    item.update(next_offset=hex(end), classification=kind, raw_bytes=data[offset:end].hex(), raw_sha256=sha(data[offset:end]))
                    require(len(asset_commands) < limits['unique_commands_per_file'] or offset in asset_commands, 'unique command host bound', offset)
                    asset_commands.setdefault(offset, item)
                    local.append(item)
                    if pending is not None and kind in ('geometry_40_42', 'other_high_operation'):
                        pending['streams'].append(item)
                        if len(pending['streams']) - 1 >= pending['required_additional_streams']:
                            pending.update(status='collected_required_streams_on_local_stored_path', final_command_offset=hex(offset), local_end_exclusive=hex(end))
                            groups.append(pending)
                            pending = None
                    elif pending is None and kind == 'geometry_40_42' and item['original_pending_expression']:
                        expression = item['original_pending_expression']
                        pending = {'path': path, 'entry_offset': hex(start), 'trigger_offset': hex(offset), 'trigger_info_word': item['info_word'], 'required_additional_streams': expression, 'streams': [item], 'cache_reference_encountered_during_collection': False, 'status': 'pending_incomplete'}
                        if expression + 1 > limits['collected_streams_host_bound']:
                            pending['status'] = 'signed_pending_expression_exceeds_collection_host_bound'
                            groups.append(pending)
                            pending = None
                    if pending is not None and opcode == 5:
                        pending['cache_reference_encountered_during_collection'] = True
                    if kind in ('exact_00ff_return', 'cache_define_following_pointer_and_return'):
                        if pending is not None:
                            pending['status'] = 'native_local_return_before_group_completed'
                            groups.append(pending)
                        entry_record.update(status='outer_scan_completed_static_local_path', return_kind=kind, end_exclusive=hex(end), commands=len(local), raw_sha256=sha(data[start:end]))
                        break
                    offset = end
                else:
                    raise ScanError('local command host bound', start)
            except ScanError as error:
                entry_record.update(status='bounded_scan_error', error_offset='' if error.offset is None else hex(error.offset), reason=error.reason, commands=len(local))
                errors.append({'path': path, 'stage': stage, 'entry_offset': hex(start), 'error_offset': entry_record['error_offset'], 'reason': error.reason})
                if pending is not None:
                    pending['status'] = 'scan_error_before_group_completed'
                    groups.append(pending)
            entries[start] = entry_record
        streams_all.extend(entries.values())
        commands_all.extend(asset_commands.values())
        record.update(stream4_payload_entries=len(second_starts), stream4_local_entries=len(entries), stream4_entries_completed=sum(r['status'] == 'outer_scan_completed_static_local_path' for r in entries.values()), unique_stream4_commands=len(asset_commands), geometry_commands=sum(r['classification'] == 'geometry_40_42' for r in asset_commands.values()), nonzero_pending_geometry_commands=sum(r['classification'] == 'geometry_40_42' and r['original_pending_expression'] != 0 for r in asset_commands.values()), stage='bounded_candidate_scan_finished')
    except (ScanError, KeyError) as error:
        record.update(stage=stage, status='candidate_unaccepted_or_host_bound', reason=str(error))
        errors.append({'path': path, 'stage': stage, 'entry_offset': '', 'error_offset': '' if not isinstance(error, ScanError) or error.offset is None else hex(error.offset), 'reason': str(error)})
    else:
        record['status'] = 'candidate_scanned_not_runtime_proven'
    assets.append(record)

group_rows = []
for index, group in enumerate(groups):
    group_id = 'group-' + str(index).zfill(4)
    group['group_id'] = group_id
    group_rows.append({k: value for k, value in group.items() if k != 'streams'} | {'collected_streams': len(group['streams']), 'stream_command_offsets': '|'.join(r['offset'] for r in group['streams']), 'stream_data_offsets': '|'.join(r['data_offset'] for r in group['streams'])})
    group_streams.extend(dict(group_id=group_id, collected_stream_index=stream_index, **item) for stream_index, item in enumerate(group['streams']))
write('original-model-name-literals.csv', literal_rows)
write('original-loader-name-source-references.csv', rows(loader / 'filename-source-references.csv'))
write('candidate-assets.csv', assets)
write('candidate-table-entries.csv', tables)
write('candidate-linked-nodes.csv', nodes_all)
write('candidate-payload-pointers.csv', payloads_all)
write('candidate-local-streams.csv', streams_all)
write('candidate-stream4-commands.csv', commands_all)
write('group-candidates.csv', group_rows, list(dict.fromkeys(key for row in group_rows for key in row)) or ['group_id', 'path', 'status'])
write('group-collected-streams.csv', group_streams, list(dict.fromkeys(key for row in group_streams for key in row)) or ['group_id', 'path', 'offset'])
write('scan-errors.csv', errors, ['path', 'stage', 'entry_offset', 'error_offset', 'reason'])
digests = []
for path, item in sorted(protected.items(), key=lambda pair: str(pair[0])):
    digest = file_sha(path)
    assert digest == item['sha256_before'] and path.stat().st_size == item['bytes_before'], str(path)
    digests.append(dict(item, roles='|'.join(sorted(item['roles'])), sha256_after=digest, bytes_after=path.stat().st_size, unchanged=True))
write('source-digests.csv', digests)
complete_groups = [g for g in groups if g['status'] == 'collected_required_streams_on_local_stored_path' and len(g['streams']) >= 2]
stats = {'version': 1, 'result': 'bounded_scan_complete', 'disc_id': boot[:6].decode(), 'disc_revision': boot[7], 'disc_bytes': iso_path.stat().st_size, 'disc_sha256': protected[iso_path.resolve()]['sha256_before'], 'FST_iso_offset': hex(fst_iso), 'FST_bytes': fst_size, 'FST_sha256': sha(fst), 'FST_file_entries': len(fst_rows), 'candidate_selection': 'all FST basenames ending MDL.PRS, case-insensitive; cross-referenced with bounded prior original DOL literal set', 'limits': limits, 'model_name_literal_offsets': len(literal_rows), 'candidate_assets': len(candidates), 'candidates_with_literal_match': sum(bool(r['original_literal_VAs']) for r in assets), 'candidate_statuses': dict(Counter(r['status'] for r in assets)), 'decoded_bytes_total': total_decoded, 'bank_candidate_table_entries': len(tables), 'bank_candidate_unique_nodes': len(nodes_all), 'bank_candidate_unique_payloads': len(payloads_all), 'local_stream_entries': len(streams_all), 'local_stream_statuses': dict(Counter(r['status'] for r in streams_all)), 'unique_asset_command_rows': len(commands_all), 'geometry_commands': sum(r['classification'] == 'geometry_40_42' for r in commands_all), 'geometry_info_high2': dict(Counter(r['raw_info_high2'] for r in commands_all if r['classification'] == 'geometry_40_42')), 'nonzero_pending_group_candidates': len(groups), 'group_candidate_statuses': dict(Counter(g['status'] for g in groups)), 'groups_collecting_at_least_two_streams': len(complete_groups), 'positive_group_asset_paths': sorted({g['path'] for g in complete_groups}), 'scan_errors': len(errors), 'scan_error_stages': dict(Counter(r['stage'] for r in errors)), 'protected_files_unchanged': len(digests), 'recorded_hashes_verified': sum(bool(r['expected_sha256']) for r in digests), 'offset_space': 'table/node/payload/command/group offsets are decoded asset file bytes; separate compressed asset ISO offsets identify storage only', 'native_execution': False, 'runtime_cache_or_caller_order_inferred': False, 'engine_files_changed': [], 'script_runs': 'search_group_samples_v1.py once'}
unknowns = ['Whether candidate assets are reached, which native caller/consumer is selected and the live parser/global state.', 'Actual runtime cache initialization, bindings, mutation and caller order; local continuation after a reference is conditional on its call returning.', 'Topology, attributes, complete inner multi-stream layout, pointer-array capacities/aliases, transforms and FIFO behavior.', 'PRS files outside the explicit MDL.PRS basename boundary, other regions/revisions and malformed native behavior.']
(out / 'sample-groups.ai.json').write_text(json.dumps({'summary': stats, 'groups': groups}, indent=2) + '\n', encoding='utf-8')
summary = dict(stats, unknowns=unknowns, decision='A model-like filename only selects a candidate. Each stage is independently validated or rejected within stated host bounds; rejection is not proof of another native format. Storage sequence is not execution order.')
summary['artifacts'] = [{'name': str(p.relative_to(out)), 'bytes': p.stat().st_size, 'sha256': file_sha(p)} for p in sorted(out.rglob('*')) if p.is_file() and p.name not in ('summary.md', 'summary.ai.json')]
(out / 'summary.ai.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
lines = ['# Bounded search for real grouped drawing data v1', '', 'One run of search_group_samples_v1.py finished the stated scan. Original ISO bytes, every selected PRS identity and protected source digests were checked. This is static asset evidence, not game execution.', '', 'Machine result: ' + json.dumps(stats, separators=(',', ':')), '', '## Search boundary and source', '', 'The search selects every original FST basename ending MDL.PRS and cross-references the original DOL model-name literals previously recorded in sonicmdl-loader. SONICMDL.PRS and METALSONICMDL.PRS have original decompiled calls to 0x80050210 in the retained source-reference CSV; matching other names alone does not establish a loader or consumer. No other PRS basename is scanned.', '', 'Each selected file is decoded with the verified PRS grammar (0x800D2684), then checked against its prior full-disc PRS validation SHA256, length, consumed bytes and ISO location. A candidate table is read as BE8-byte records until FFFFFFFF. Each reachable self-contained node/payload pointer is separately bounded according to the known 0x80050210 / 0x8002F88C path; the aligned, low-positive, self-contained domain is a conservative scan policy, not a new native guarantee. Unique-node traversal is a structural inventory, not a reproduction of native repeated visit counts.', '', 'Drawing local scans use 0x8011CCF8: exact 00FF returns; command04 stores the following pointer and returns; command05 records an unresolved cache call then conditionally resumes at the next halfword. Every following definition pointer is scanned as a separate candidate entry. No cache is implicitly initialized and no same-slot definition is selected as its target.', '', 'A positive pending candidate uses the original sign-extended info expression, not merely unsigned high2. Values4000..7FFF produce one additional collected stream; bit15-set expressions exceed this bounded collection domain and are retained separately. Completed groups mean only that the required following geometry commands occur on a validated local stored path. Live global flags and emitter selection are not proved.', '', '## Assets', '', '| FST asset | Final scan status | Decoded bytes | Pending commands |', '|---|---|---:|---:|']
lines.extend(f"| {r['path']} | {r['status']} | {r.get('decoded_bytes', '')} | {r.get('nonzero_pending_geometry_commands', '')} |" for r in assets)
lines.extend(['', 'Raw output includes all candidate identities, table records, linked nodes, both payload pointer words, local stream boundaries, command bytes, group candidates, collected stream bytes, exact errors and source digests. samples/ preserves every selected compressed and decoded carrier. Asset ISO offsets refer to compressed storage; internal offsets remain decoded-file offsets.', '', 'Unknowns: ' + '; '.join(unknowns), '', 'No engine, repository, original carrier, frozen export, analysis database or processor language was modified. No native game or engine execution occurred.'])
(out / 'summary.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(json.dumps(stats, separators=(',', ':')))
