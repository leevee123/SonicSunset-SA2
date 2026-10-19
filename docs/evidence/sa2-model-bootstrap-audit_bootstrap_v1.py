import csv
import hashlib
import json
import re
import struct
from collections import Counter
from pathlib import Path

out = Path(__file__).resolve().parent
base = out.parents[1]
prior = base / 'work/sa2-model-setup-v1'
sha = lambda data: hashlib.sha256(data).hexdigest()
rows = lambda path: list(csv.DictReader(path.open(newline='', encoding='utf-8-sig')))
number = lambda value: int(value, 0)
signed16 = lambda value: value if value < 0x8000 else value - 0x10000
protected = {}
assert not (out / 'summary.ai.json').exists(), 'Do not rerun a completed version.'
def protect(path, expected=None):
    path = path.resolve()
    data = path.read_bytes()
    assert expected is None or sha(data) == expected, str(path)
    protected[path] = {'path': str(path), 'sha256_before': sha(data), 'bytes_before': len(data), 'expected_sha256': expected or ''}
    return data
def write(name, values, fields=None):
    if fields is None:
        fields = list(dict.fromkeys(key for row in values for key in row))
    with (out / name).open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(values)
for row in rows(out / 'preparation-source-digests.csv'):
    protect(Path(row['path']), row['sha256_after'])
for name in ('added-original-words.csv', 'added-source-artifacts.csv', 'preparation-source-digests.csv', 'preparation.ai.json'):
    protect(out / name)
protect(Path(__file__))
dol = protect(base / 'work/sa2-disc/main.dol', 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e')
mapping = json.loads((base / 'work/dol-elf-mapping-final.json').read_text())
def offset(address):
    matches = [m['dol_offset'] + address - m['address'] for m in mapping['mappings'] if m['address'] <= address < m['address'] + m['size']]
    assert len(matches) <= 1
    return matches[0] if matches else None
def location(address):
    pos = offset(address)
    return {'VA': hex(address), 'DOL_offset': '' if pos is None else hex(pos), 'ISO_offset': '' if pos is None else hex(0x1e700 + pos)}
words = rows(prior / 'original-words.csv') + rows(out / 'added-original-words.csv')
by_address = {}
by_owner = {}
for row in words:
    address = number(row['original_virtual_address'])
    pos = offset(address)
    assert pos == number(row['dol_file_offset'])
    assert struct.unpack_from('>I', dol, pos)[0] == number(row['word'])
    row['iso_offset'] = hex(0x1e700 + pos)
    assert address not in by_address or by_address[address]['word'] == row['word']
    by_address[address] = row
    by_owner.setdefault(number(row['owner']), []).append(row)
write('original-words.csv', words)
constants = rows(prior / 'bootstrap-constants.csv')
for row in constants:
    address = number(row['VA'])
    assert number(row['DOL_offset']) == offset(address)
    assert dol[offset(address):offset(address) + 4].hex() == row['word']
write('original-constants.csv', constants)

copy_events, copy_word_views = [], []
for owner in (0x801057c4, 0x801057f8, 0x8010582c):
    fprs = {}
    load_addresses, store_addresses = [], []
    word_order = 0
    for record in by_owner[owner]:
        address, word = number(record['original_virtual_address']), number(record['word'])
        opcode, reg, base_reg = word >> 26, (word >> 21) & 31, (word >> 16) & 31
        if opcode in (56, 60):
            disp = word & 0xfff
            disp = disp if disp < 0x800 else disp - 0x1000
            width_flag, quantizer = (word >> 15) & 1, (word >> 12) & 7
            assert width_flag == 0 and quantizer == 0
            if opcode == 56:
                assert base_reg == 3
                fprs[reg] = [(disp, lane) for lane in (0, 1)]
                load_addresses.append(address)
                copy_events.append(dict(owner=hex(owner), **location(address), operation='PSQ_load_pair', base_register='r3_source', offset=hex(disp), FPR=reg, GQR=quantizer, W=width_flag, constraint='lane byte locations depend on GQR0 load type/scale'))
            else:
                assert base_reg == 4
                store_addresses.append(address)
                copy_events.append(dict(owner=hex(owner), **location(address), operation='PSQ_store_pair', base_register='r4_destination', offset=hex(disp), FPR=reg, GQR=quantizer, W=width_flag, constraint='stored size/value depend on GQR0 store type/scale'))
                for lane, (source_offset, source_lane) in enumerate(fprs[reg]):
                    copy_word_views.append(dict(owner=hex(owner), word_order=word_order, store_VA=hex(address), binary32_source_offset=hex(source_offset + source_lane * 4), binary32_destination_offset=hex(disp + lane * 4), store_kind='PSQ_pair_lane', constraint='GQR0 load/store type0 ordinary binary32 layout; numeric/NaN effects not validated'))
                    word_order += 1
        elif opcode == 48:
            disp = signed16(word & 0xffff)
            assert base_reg == 3
            fprs[reg] = [(disp, 0)]
            load_addresses.append(address)
            copy_events.append(dict(owner=hex(owner), **location(address), operation='scalar_lfs', base_register='r3_source', offset=hex(disp), FPR=reg, constraint='scalar single load; GQR0 does not select its format'))
        elif opcode == 52:
            disp = signed16(word & 0xffff)
            assert base_reg == 4 and len(fprs[reg]) == 1
            source_offset, source_lane = fprs[reg][0]
            assert source_lane == 0
            store_addresses.append(address)
            copy_events.append(dict(owner=hex(owner), **location(address), operation='scalar_stfs', base_register='r4_destination', offset=hex(disp), FPR=reg, constraint='scalar single store'))
            copy_word_views.append(dict(owner=hex(owner), word_order=word_order, store_VA=hex(address), binary32_source_offset=hex(source_offset), binary32_destination_offset=hex(disp), store_kind='scalar_stfs', constraint='ordinary scalar single load/store; numeric/NaN effects not validated'))
            word_order += 1
    assert max(load_addresses) < min(store_addresses)
assert [number(r['binary32_source_offset']) for r in copy_word_views if r['owner'] == '0x801057c4'] == list(range(0, 48, 4))
assert [number(r['binary32_source_offset']) for r in copy_word_views if r['owner'] == '0x801057f8'] == [0, 4, 8, 16, 20, 24, 32, 36, 40]
assert [number(r['binary32_source_offset']) for r in copy_word_views if r['owner'] == '0x8010582c'] == list(range(0, 32, 4))
write('copy-memory-instructions.csv', copy_events)
write('conditional-binary32-upload-order.csv', copy_word_views)

def mask(begin, end):
    return sum(1 << (31 - bit) for bit in range(32) if (begin <= bit <= end if begin <= end else bit >= begin or bit <= end))
def wrapper_trace(owner, index, mode):
    regs = [0] * 32
    regs[1], regs[3], regs[4], regs[5] = 0x80010000, 0x81200000, index & 0xffffffff, mode & 0xffffffff
    memory = {}
    pc, compare = owner, 0
    events = []
    for _ in range(100):
        record = by_address[pc]
        word, mnemonic = number(record['word']), record['mnemonic']
        opcode = word >> 26
        rt, ra, rb = (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        imm = signed16(word & 0xffff)
        following = pc + 4
        if opcode in (14, 15):
            regs[rt] = ((regs[ra] if ra else 0) + (imm << 16 if opcode == 15 else imm)) & 0xffffffff
        elif opcode == 7:
            regs[rt] = (regs[ra] * imm) & 0xffffffff
        elif opcode in (10, 11):
            left = regs[ra]
            if opcode == 11 and left & 0x80000000:
                left -= 0x100000000
            right = word & 0xffff if opcode == 10 else imm
            compare = -1 if left < right else 1 if left > right else 0
        elif opcode in (24, 25):
            regs[ra] = regs[rt] | ((word & 0xffff) << (16 if opcode == 25 else 0))
        elif opcode == 21:
            shift, begin, end = (word >> 11) & 31, (word >> 6) & 31, (word >> 1) & 31
            value = regs[rt]
            rotated = ((value << shift) | (value >> ((32 - shift) & 31))) & 0xffffffff
            regs[ra] = rotated & mask(begin, end)
        elif opcode == 31:
            xo = (word >> 1) & 1023
            if xo == 444:
                regs[ra] = regs[rt] | regs[rb]
            elif xo == 339:
                regs[rt] = 0
            else:
                assert xo == 467
        elif opcode in (36, 37, 38):
            target = (regs[ra] + imm) & 0xffffffff
            memory[target] = regs[rt]
            if opcode == 37:
                regs[ra] = target
            if target == 0xcc008000:
                width = 1 if opcode == 38 else 4
                value = regs[rt] & (0xff if width == 1 else 0xffffffff)
                events.append(dict(event='destination_store', **location(pc), destination=hex(target), byte_width=width, value=hex(value), big_endian_bytes=value.to_bytes(width, 'big').hex()))
        elif opcode == 32:
            regs[rt] = memory.get((regs[ra] + imm) & 0xffffffff, 0)
        elif opcode == 18:
            displacement = word & 0x03fffffc
            if displacement & 0x02000000:
                displacement -= 0x04000000
            target = (displacement if word & 2 else pc + displacement) & 0xffffffff
            if word & 1:
                assert target in (0x801057c4, 0x801057f8, 0x8010582c)
                events.append(dict(event='copy_helper_call', **location(pc), helper=hex(target), source=hex(regs[3]), destination=hex(regs[4])))
            else:
                following = target
        elif opcode == 16:
            take = compare != 0 if mnemonic == 'bne' else compare < 0 if mnemonic == 'blt' else None
            assert take is not None
            displacement = word & 0xfffc
            if displacement & 0x8000:
                displacement -= 0x10000
            if take:
                following = (pc + displacement) & 0xffffffff
        else:
            assert opcode == 19 and mnemonic == 'blr'
            return events
        pc = following
    raise AssertionError('wrapper trace bound')

wrapper_cases, wrapper_events = [], []
test_indices = [0, 1, 0x2a, 0x3f, 0x40, 0x41, 0xffff, 0x40000000, 0xffffffff]
for owner in (0x80105850, 0x8010588c, 0x80105908):
    for index in test_indices:
        for mode in ((0, 1, 2, 0xffffffff) if owner == 0x80105908 else (0,)):
            events = wrapper_trace(owner, index, mode)
            stores = [r for r in events if r['event'] == 'destination_store']
            calls = [r for r in events if r['event'] == 'copy_helper_call']
            assert [r['byte_width'] for r in stores] == [1, 4] and stores[0]['value'] == '0x10' and len(calls) == 1
            if owner == 0x80105850:
                expected, helper = ((index << 2) & 0xffffffff) | 0xb0000, 0x801057c4
            elif owner == 0x8010588c:
                expected, helper = ((index * 3 + 0x400) & 0xffffffff) | 0x80000, 0x801057f8
            else:
                address = ((index << 2) if index < 0x40 else (index - 0x40) * 4 + 0x500) & 0xffffffff
                expected, helper = address | ((7 if mode == 1 else 11) << 16), 0x801057c4 if mode == 0 else 0x8010582c
            assert number(stores[1]['value']) == expected and number(calls[0]['helper']) == helper
            case_id = hex(owner) + '-' + hex(index) + '-' + hex(mode)
            wrapper_cases.append({'case_id': case_id, 'owner': hex(owner), 'index_u32': hex(index), 'mode_u32': hex(mode), 'control_word': hex(expected), 'copy_helper': hex(helper), 'conditional_binary32_payload_words': sum(r['owner'] == hex(helper) for r in copy_word_views), 'scope': 'synthetic integer instruction model; no PSQ/MMIO execution'})
            wrapper_events.extend(dict(case_id=case_id, event_order=order, **event) for order, event in enumerate(events))
write('upload-wrapper-cases.csv', wrapper_cases)
write('upload-wrapper-events.csv', wrapper_events)

matrix_fprs, matrix_permutation, matrix_events = {}, [], []
for row in by_owner[0x8011c18c]:
    address, word = number(row['original_virtual_address']), number(row['word'])
    mnemonic = row['mnemonic']
    if mnemonic == 'psq_l':
        reg, base_reg = (word >> 21) & 31, (word >> 16) & 31
        disp, width_flag, quantizer = word & 0xfff, (word >> 15) & 1, (word >> 12) & 7
        assert base_reg == 5 and width_flag == 0 and quantizer == 0
        matrix_fprs[reg] = [(disp, 0), (disp, 1)]
        matrix_events.append(dict(**location(address), event='source_pair_load', source_base='old_global_pointer', offset=hex(disp), FPR=reg))
    elif mnemonic.startswith('ps_merge'):
        rd, ra, rb = (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        selector = {'ps_merge00': (0, 0), 'ps_merge01': (0, 1), 'ps_merge11': (1, 1)}[mnemonic]
        matrix_fprs[rd] = [matrix_fprs[ra][selector[0]], matrix_fprs[rb][selector[1]]]
    elif mnemonic == 'psq_st':
        reg, base_reg, disp = (word >> 21) & 31, (word >> 16) & 31, word & 0xfff
        assert base_reg == 6 and (word >> 15) & 1 == 0 and (word >> 12) & 7 == 0
        matrix_events.append(dict(**location(address), event='destination_pair_store', destination_base='old_global_pointer+0x30 modulo32', offset=hex(disp), FPR=reg))
        for lane, (source_disp, source_lane) in enumerate(matrix_fprs[reg]):
            matrix_permutation.append(dict(store_VA=hex(address), destination_component=(disp // 4) + lane, binary32_destination_offset=hex(disp + 4 * lane), load_pair_offset=hex(source_disp), load_lane=source_lane, binary32_source_offset=hex(source_disp + source_lane * 4), source_component=source_disp // 4 + source_lane, constraint='paired-lane origin; binary32 offsets conditional on GQR0 type0 layout'))
assert [r['source_component'] for r in matrix_permutation] == [0, 4, 8, 1, 5, 9, 2, 6, 10, 3, 7, 11]
assert number(by_address[0x8011c19c]['word']) == 0x90c40000
assert number(by_address[0x8011c1a0]['word']) == 0x4bffffa0
matrix_events = [dict(**location(0x8011c194), event='read_global_pointer', global_pointer_VA='0x803ae0c4'), dict(**location(0x8011c19c), event='write_global_pointer_before_source_loads', global_pointer_VA='0x803ae0c4', value='old+0x30 modulo32'), dict(**location(0x8011c1a0), event='branch_to_shared_copy_block', target='0x8011c140')] + matrix_events
write('matrix-lane-permutation.csv', matrix_permutation)
write('matrix-memory-order.csv', matrix_events)

setup_rows = by_owner[0x8011d2f4]
setup_calls = []
for row in setup_rows:
    address, word = number(row['original_virtual_address']), number(row['word'])
    if word >> 26 == 18 and word & 1:
        displacement = word & 0x03fffffc
        if displacement & 0x02000000:
            displacement -= 0x04000000
        setup_calls.append(dict(order=len(setup_calls), **location(address), target=hex((address + displacement) & 0xffffffff), condition='unconditional before gate' if address < 0x8011d394 else 'only state at D388 has bit00100000 clear'))
expected_targets = [0x80100d44] * 3 + [0x80102ef8, 0x80105850, 0x8010588c, 0x800ed7cc, 0x800ed798, 0x800ed368, 0x800ed368, 0x80105908]
assert [number(r['target']) for r in setup_calls] == expected_targets
arguments = [('r3=0;r4=9;r5=1;r6=4;r7=0', ''), ('r3=0;r4=10;r5=0;r6=4;r7=0', ''), ('r3=0;r4=11;r5=1;r6=5;r7=0', ''), ('r3=1', ''), ('r3=80357880;r4=0', ''), ('r3=80357880;r4=0', ''), ('r3=frameSP+68', 'f1=f2=wordBF000000(-0.5);f3=word00000000(0)'), ('r3=frameSP+38', 'f1=f2=word3F000000(0.5);f3=word3F800000(1)'), ('r3=frameSP+68;r4=80357880;r5=frameSP+08', ''), ('r3=frameSP+38;r4=frameSP+08;r5=frameSP+08', ''), ('r3=frameSP+08;r4=2A;r5=0', '')]
for row, (gprs, fprs) in zip(setup_calls, arguments):
    row.update(caller_GPR_arguments=gprs, caller_FPR_arguments_under_startup_r2=fprs)
write('setup-call-order.csv', setup_calls)
state_stores = []
for address, register, displacement, value in ((0x8011d358, 3, -0x7180, 0), (0x8011d360, 0, -0x717c, 0xffffffff), (0x8011d364, 3, -0x7178, 0)):
    word = number(by_address[address]['word'])
    assert word >> 26 == 36 and (word >> 21) & 31 == register and (word >> 16) & 31 == 13 and signed16(word & 0xffff) == displacement
    state_stores.append(dict(**location(address), base='live r13', displacement=hex(displacement), value=hex(value), label_under_startup_r13=hex((0x803b52c0 + displacement) & 0xffffffff), meaning='unknown state word; FFFFFFFF is not zero'))
write('setup-state-stores.csv', state_stores)
static_locations = []
bss_start, bss_size = struct.unpack_from('>II', dol, 0xd8)
for address, byte_count, role in ((0x80357880, 48, 'setup upload source'), (0x803ae0c4, 4, 'C18C current pointer word'), (0x803ae0e8, 4, 'setup gate state label under startup r13'), (0x803ae140, 12, 'three setup state labels under startup r13')):
    pos = offset(address)
    static_locations.append(dict(**location(address), requested_bytes=byte_count, role=role, original_file_backed=pos is not None, original_file_bytes='' if pos is None else dol[pos:pos + byte_count].hex(), inside_header_BSS=bss_start <= address and address + byte_count <= bss_start + bss_size, runtime_initialization_or_ownership='unknown from bounded scopes'))
write('static-source-locations.csv', static_locations)
digests = []
for path, row in sorted(protected.items(), key=lambda pair: str(pair[0])):
    data = path.read_bytes()
    assert sha(data) == row['sha256_before'] and len(data) == row['bytes_before'], str(path)
    digests.append(dict(row, sha256_after=sha(data), bytes_after=len(data), unchanged=True))
write('source-digests.csv', digests)
stats = {'version': 1, 'result': 'passed_bounded_original_audit', 'original_instruction_rows_verified': len(words), 'distinct_original_VAs': len(by_address), 'selected_scopes': len(by_owner), 'setup_direct_calls': len(setup_calls), 'setup_state_word_stores': len(state_stores), 'copy_memory_instructions': len(copy_events), 'conditional_binary32_upload_components': dict(Counter(r['owner'] for r in copy_word_views)), 'synthetic_integer_wrapper_cases': len(wrapper_cases), 'synthetic_wrapper_events': len(wrapper_events), 'matrix_permuted_components': len(matrix_permutation), 'matrix_source_component_order': [r['source_component'] for r in matrix_permutation], 'protected_files_unchanged': len(digests), 'recorded_hashes_verified': sum(bool(r['expected_sha256']) for r in digests), 'native_game_execution': False, 'project_or_ProgramDB_opens': 0, 'GQR0_or_FPSCR_runtime_value_proved': False, 'matrix_source_ownership_or_initialization_proved': False, 'engine_files_changed': [], 'scripts': ['prepare_bootstrap_v1.py once', 'audit_bootstrap_v1.py once']}
facts = {'setup': '8011D2F4: three D44 calls with raw arguments,2EF8(1), state writes0/FFFFFFFF/0,5850(source80357880,index0),588C(same,index0),then optional path if live SDA-71D8 bit00100000 clear; optional ED7CC/ED798/ED368 twice/5908(stack08,2A,0),fresh state reload OR00100000.', 'wrappers': 'Each5850/588C/5908 writes byte10 then32-bit control toCC008000 BEFORE copy helper source loads.5850=((index<<2)mod32)|B0000→57C4.588C=(3*index+400 mod32)|80000→57F8.5908 address=index<40?index*4:(index-40)*4+500 mod32,OR ((mode==1?7:B)<<16);mode0→57C4,allnonzero→582C. No GPU names inferred.', 'copy': '57C4 loads six GQR0 pairs offsets00/08/10/18/20/28 then stores six pairs repeatedly at destination+0.57F8 loads pairs00/10/20 and scalars08/18/28 then alternating pair/scalar stores at destination+0.582C loads four pairs00/08/10/18 then four stores at destination+0. All loads precede first store.', 'C18C': 'Absolute803AE0C4 pointer read,advanced+30 and stored BEFORE source loads,then shared blockC140 loads six GQR0 pairs/reorders lanes/stores six pairs at old+30. Binary32-layout lane-source order0,4,8,1,5,9,2,6,10,3,7,11. This is lane provenance,not unqualified raw-bit/numeric/runtime equivalence.'}
unknowns = ['Actual GQR0 load/store format and scales, FPSCR/NI/NaN behavior and exact numeric results; other agents audit those scopes.', 'Initialization, ownership, capacity and lifetime of80357880 data and803AE0C4 pointed storage.', 'Live r2/r13 context; SDA labels/constants here use documented startup-base assumptions.', 'Caller closure, mode meanings, GPU interpretation, topology, transforms and successful retail execution.', 'C18C pointer/data aliasing can alter unread source when global pointer word aliases source; no nonalias assumption is elevated to native guarantee.']
summary = dict(stats, facts=facts, unknowns=unknowns, source_selection_limit='Root selected-pseudocode.md is truncated for large functions despite complete labels; full frozen C hashes and original words were used. New structural excerpts are labelled partial.')
summary['artifacts'] = [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())} for p in sorted(out.iterdir()) if p.is_file() and p.name not in ('summary.md', 'summary.ai.json')]
(out / 'summary.ai.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
lines = ['# Original model bootstrap and upload audit v1', '', 'One run each of prepare_bootstrap_v1.py and audit_bootstrap_v1.py passed. The existing project-free DumpSonicLoader parsed four added scopes; no Program or project was opened. Full C was checked first and exact original words establish store/call order where generated C loses repeated MMIO writes or paired-lane details.', '', 'Machine result: ' + json.dumps(stats, separators=(',', ':')), '', '## Verified setup order', '', facts['setup'], '', 'The three state writes are not three zero clears: the middle value is FFFFFFFF. The optional-path gate and final OR use separate original loads of live r13-71D8; no stale entry-state value is substituted. The stack frame base is post-prologue SP, with blocks at+68,+38,+08. The second ED368 call has output equal its second input. ED368 arithmetic is not reconstructed here.', '', '## Upload instruction sequences', '', facts['wrappers'], '', facts['copy'], '', 'For ordinary GQR0 load/store type0 binary32 layout, the source component orders are12 sequential words for57C4; offsets00,04,08,10,14,18,20,24,28 for57F8;8 sequential words for582C. A paired store has two lanes at adjacent format-dependent byte locations, and repeated stores use the same destination base. No PSQ packet length or float values are asserted for other live quantization formats. Mode values other than0/1 retain the original5908 mismatch between its B<<16 control field and8-component helper; the audit does not normalize that behavior.', '', 'At the setup call sites, index0 gives controls000B0000 and00080400. The conditional5908 index2A/mode0 call gives000B00A8. These are byte10 followed by the corresponding BE32 control, then the original helper payload operations. The integer model checked boundary/wrap indices and mode values without executing MMIO or floating instructions.', '', '## Current pointer and lane conversion', '', facts['C18C'], '', 'The shared copy block8011C140..188 precedes the named entry8011C18C and is included in its frozen recorded body. The pointer update at8011C19C precedes the branch8011C1A0, so source initialization cannot be inferred from that update. All source pair loads precede the first destination pair store. Lane provenance is exact at the instruction level; binary32 byte offsets and matrix-shaped interpretations require an explicit GQR0 contract. Source storage ownership/init remains unknown.', '', 'Complete raw CSVs retain VA/DOL/ISO locations, all742 instruction rows, source constants, setup calls/stores, copy events, conditional upload component order, integer wrapper cases/events, pointer memory order and lane permutation. source-digests.csv preserves unchanged input hashes.', '', 'Unknowns: ' + '; '.join(unknowns), '', 'No engine/repository/original/frozen/database/language changes. No native game or engine execution. No leaked original source encountered.']
(out / 'summary.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(json.dumps(stats, separators=(',', ':')))
