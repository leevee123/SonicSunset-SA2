import csv
import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]


def rows(path):
    with Path(path).open(newline='', encoding='utf-8') as stream:
        return list(csv.DictReader(stream))


def save(name, values, fields=None):
    with (OUT / name).open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields or list(values[0]))
        writer.writeheader()
        writer.writerows(values)


raw = rows(OUT / 'original-words.csv')
words = {int(row['va'], 16): row for row in raw}
expected = {
    0x8011CD00: 0x9421FF80, 0x8011CD04: 0x39610080,
    0x8011CD14: 0x3B000000, 0x8011CD18: 0x3AE00000,
    0x8011CD28: 0x3BC10030, 0x8011CD2C: 0x3BE10010,
    0x8011CE80: 0x56E3103A, 0x8011CE84: 0x7E9E192E,
    0x8011CE94: 0x7C1F192E, 0x8011CE98: 0x7EE0BB78,
    0x8011CE9C: 0x3AF70001, 0x8011CEA0: 0x7C00C000,
    0x8011CEA4: 0x40800014,
    0x8011CF2C: 0x574093BE, 0x8011CF38: 0x7C180378,
    0x8011CF3C: 0x92810030, 0x8011CF4C: 0x90010010,
    0x8011CF5C: 0x3AE00001, 0x8011CF60: 0x7F96E378,
    0x8011D130: 0x38610030, 0x8011D134: 0x7EA4AB78,
    0x8011D138: 0x7F45D378, 0x8011D13C: 0x38C10010,
    0x8011D140: 0x7F07C378, 0x8011D144: 0x48003015,
    0x8011D168: 0x381BFFFF, 0x8011D16C: 0x5400083C,
    0x8011D170: 0x7E940214, 0x8011D174: 0x3B000000,
    0x8011D178: 0x3AE00000, 0x8011D180: 0x900D8E8C,
    0x8011CAD4: 0x818D8EC0, 0x8011CAE0: 0x38600000,
    0x8011CAE4: 0x7D8803A6, 0x8011CAE8: 0x4E800021,
}
for address, value in expected.items():
    assert int(words[address]['word'], 16) == value, hex(address)


def signed16(value):
    return value if value < 0x8000 else value - 0x10000


def rotate(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def ppc_mask(start, end):
    return sum(1 << (31 - bit) for bit in range(start, end + 1))


"""/* Compute the pending domain from the actual RLWINM fields. This preserves
sign extension instead of replacing the outer value with raw two-bit groups. */"""
instruction = int(words[0x8011CF2C]['word'], 16)
shift, start, end = (instruction >> 11) & 31, (instruction >> 6) & 31, (instruction >> 1) & 31
domains = []
for info in range(0x10000):
    signed = signed16(info)
    pending = rotate(signed & 0xFFFFFFFF, shift) & ppc_mask(start, end)
    assert pending == (signed & 0xFFFFFFFF) >> 14
    domains.append({'raw_info': hex(info), 'signed_info': signed, 'original_pending': pending, 'total_entries_if_completed': pending + 1, 'raw_high2': info >> 14, 'low14': info & 0x3FFF})
save('exhaustive-info-pending-domain.csv', domains)
partitions = [{'first_raw_info': hex(min(row['raw_value'] for row in values)), 'last_raw_info': hex(max(row['raw_value'] for row in values)), 'pending': pending, 'entry_count_if_completed': pending + 1, 'cases': len(values)} for pending in sorted({row['original_pending'] for row in domains}) for values in [[{'raw_value': int(row['raw_info'], 16)} for row in domains if row['original_pending'] == pending]]]
assert [row['pending'] for row in partitions] == [0, 1, 0x3FFFE, 0x3FFFF]

"""/* Derive stack storage boundaries from original instructions and the shared
save family. A non-overlap window is not a native capacity or bounds check. */"""
frame_size = -signed16(int(words[0x8011CD00]['word'], 16) & 0xFFFF)
type_base = int(words[0x8011CD2C]['word'], 16) & 0xFFFF
pointer_base = int(words[0x8011CD28]['word'], 16) & 0xFFFF
save_rows = []
for index in range(12):
    address = 0x8010AFB0 + index * 4
    value = int(words[address]['word'], 16)
    register = (value >> 21) & 31
    stack_offset = frame_size + signed16(value & 0xFFFF)
    save_rows.append({'register': register, 'new_SP_offset': hex(stack_offset), 'save_va': hex(address), 'save_word': f'{value:08x}'})
save_start = min(int(row['new_SP_offset'], 16) for row in save_rows)
independent_slots = min((pointer_base - type_base) // 4, (save_start - pointer_base) // 4)
assert (frame_size, type_base, pointer_base, save_start, independent_slots) == (0x80, 0x10, 0x30, 0x50, 8)
save('saved-register-layout.csv', save_rows)
stack_rows = []
for index in range(24):
    type_offset = type_base + index * 4
    pointer_offset = pointer_base + index * 4
    stack_rows.append({'index': index, 'type_SP_offset': hex(type_offset), 'pointer_SP_offset': hex(pointer_offset), 'within_independent_slot_window': index < independent_slots, 'type_aliases_first_pointer_window': pointer_base <= type_offset < save_start, 'pointer_saved_register_alias': next((row['register'] for row in save_rows if int(row['new_SP_offset'], 16) == pointer_offset), ''), 'not_native_capacity_check': True})
save('stack-slot-overlap.csv', stack_rows)

"""/* Exhaustively validate type classification and cursor arithmetic. Values
are original modulo32 calculations; host containment requirements are separate. */"""
types = []
for opcode in range(256):
    difference = (0x42 - opcode) & 0xFFFFFFFF
    leading = 32 - difference.bit_length() if difference else 32
    kind = leading >> 5
    assert kind == int(opcode == 0x42)
    types.append({'raw_opcode': hex(opcode), 'stored_type': kind, 'geometry_collection_candidate': opcode >= 0x40})
save('exhaustive-opcode-types.csv', types)
cursors = []
for size in range(0x10000):
    packet = 0x81001000
    data = packet + 6
    original = (data + (((size - 1) & 0xFFFFFFFF) << 1)) & 0xFFFFFFFF
    assert original == (packet + 4 + size * 2) & 0xFFFFFFFF
    cursors.append({'raw_size': size, 'packet': hex(packet), 'data': hex(data), 'original_next': hex(original), 'declared_next_formula': hex(packet + 4 + size * 2), 'size_zero_info_overlaps_next': size == 0})
save('exhaustive-geometry-cursors.csv', cursors)

"""/* Generate bounded synthetic collector examples, excluding opaque state
helpers/callback execution. These illustrate bindings, not retail traversal. */"""
cases = [
    ('first41_last42_different_info', [(0x100, 0x41, 0x4005, 9), (0x200, 0x42, 0x0007, 11)]),
    ('first42_last41_negative_last_info', [(0x300, 0x42, 0x4002, 5), (0x400, 0x41, 0xC009, 5)]),
    ('first_unsupported43_last42', [(0x500, 0x43, 0x4001, 5), (0x600, 0x42, 0x0003, 5)]),
    ('first42_last_unsupported43', [(0x700, 0x42, 0x4001, 5), (0x800, 0x43, 0x0002, 5)]),
    ('first_info_negative_independent_window_only', [(0x900 + index * 0x20, 0x41, 0x8001 if index == 0 else 1, 5) for index in range(9)]),
]
traces = []
for case, packets in cases:
    pending = 0
    index = 0
    pointers = []
    kinds = []
    for ordinal, (packet, opcode, info, size) in enumerate(packets):
        before_pending, before_index = pending, index
        action = ''
        if not pending:
            pending = (signed16(info) & 0xFFFFFFFF) >> 14
            if pending:
                pointers = [packet + 6]
                kinds = [int(opcode == 0x42)]
                index = 1
                action = 'first_store_and_defer'
            else:
                action = 'single_draw_stage'
        elif index >= independent_slots:
            action = 'HOST_MODEL_STOP_before_aliasing_store; native_has_no_guard'
        else:
            pointers.append(packet + 6)
            kinds.append(int(opcode == 0x42))
            old_index = index
            index += 1
            action = 'append_and_defer' if old_index < pending else 'append_then_draw_stage'
        traces.append({'case': case, 'ordinal': ordinal, 'packet_offset': hex(packet), 'raw_opcode': hex(opcode), 'raw_info': hex(info), 'pending_before': before_pending, 'index_before': before_index, 'pending_after_collect': pending, 'index_after_collect': index, 'action': action, 'ordered_data_pointers': '|'.join(hex(value) for value in pointers), 'ordered_types': '|'.join(str(value) for value in kinds), 'last_info_if_grouped_call': hex(signed16(info) & 0xFFFFFFFF) if action == 'append_then_draw_stage' else '', 'last_info_low14_if_grouped_call': info & 0x3FFF if action == 'append_then_draw_stage' else '', 'next_outer_cursor': hex(packet + 4 + size * 2), 'native_execution': False})
        if action.startswith('HOST_MODEL_STOP'):
            break
        if action.endswith('draw_stage'):
            pending = 0
            index = 0
save('synthetic-collector-bindings.csv', traces)

guards = rows(OUT / 'input-source-hashes.csv')
for row in guards:
    assert hashlib.sha256((ROOT / row['path']).read_bytes()).hexdigest() == row['sha256'], row['path']
    row['final_unchanged'] = True
save('source-hash-guards.csv', guards)
anchors = sorted(set(expected) | {0x8011CCF8, 0x8011CE68, 0x8011CE6C, 0x8011CE74, 0x8011CE78, 0x8011CEC0, 0x8011CEE0, 0x8011CF1C, 0x8011CF28, 0x8011CF68, 0x8011D184, 0x8011D18C, 0x8011D194, 0x80120158, 0x8011CAC4, 0x8011CAD0, 0x8011CAD8, 0x8011CADC})
save('canonical-collector-sites.csv', [words[address] for address in anchors])
result = {'info_cases': len(domains), 'pending_partitions': partitions, 'opcode_cases': len(types), 'cursor_cases': len(cursors), 'synthetic_cases': len(cases), 'synthetic_trace_rows': len(traces), 'frame': {'bytes': frame_size, 'types_new_SP': hex(type_base), 'pointers_new_SP': hex(pointer_base), 'saved_GPRs_start': hex(save_start), 'saved_GPRs_end_exclusive': hex(frame_size), 'saved_LR_new_SP': hex(frame_size + 4), 'independent_nonoverlap_slots': independent_slots, 'native_capacity_asserted': False, 'native_guard_found': False}, 'callback': {'original_va': '0x8011cae8', 'r13_displacement': '-0x7140', 'VA_under_startup_r13': hex(0x803B52C0 - 0x7140), 'argument_r3': 0, 'gate': '0x8011CAAC reached AND SDA-71D8&0x80000 nonzero AND callback pointer nonnull', 'C_loss': 'generatedC ||true/null-target branch contradicted by original instructions'}, 'source_guards_unchanged': len(guards), 'limitations': ['Integer/table/frame audit only; no target CPU execution.', 'Synthetic binding examples omit opaque state-helper/callback effects.', 'Independent storage window is not intended/native capacity.', 'No real nonzero-pending geometry sample has been validated.']}
(OUT / 'integer-validation.ai.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
(OUT / 'integer-validation.md').write_text(f"# Collector integer validation\n\n65,536 info values, 256 opcodes and 65,536 encoded sizes checked from the original masks/arithmetic. Frame-derived independent storage window: {independent_slots} entries; no native capacity assertion or bounds check. {len(cases)} synthetic cases/{len(traces)} trace rows, not runtime observations. All {len(guards)} source guards unchanged. Full raw CSV retains each case.\n", encoding='utf-8')
print(json.dumps(result, separators=(',', ':')))
