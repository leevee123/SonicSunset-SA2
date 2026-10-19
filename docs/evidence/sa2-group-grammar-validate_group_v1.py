"""Once-only bounded original-integer cursor model and explicit raw group oracle."""
import collections
import csv
import hashlib
import json
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
assert not (OUT / 'validation.ai.json').exists()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def rows(path):
    with Path(path).open(newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


def save(name, values):
    keys = list(dict.fromkeys(k for r in values for k in r))
    with (OUT / name).open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, keys)
        w.writeheader()
        w.writerows(values)


def s(value, bits=16):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def mask(mb, me):
    return sum(1 << (31 - i) for i in range(32) if (mb <= i <= me if mb <= me else i >= mb or i <= me))


def rot(value, shift):
    return ((value << shift) | (value >> ((32 - shift) % 32))) & 0xffffffff


native = {int(r['va'], 16): int(r['word'], 16) for r in rows(OUT / 'original-words.csv')}


class Memory:
    def __init__(self, case):
        self.case, self.bytes, self.events = case, {}, []

    def put(self, address, data):
        for i, b in enumerate(data):
            self.bytes[address + i] = b

    def access(self, kind, address, size, value=None, site=0):
        address &= 0xffffffff
        if kind == 'write':
            self.put(address, int(value & ((1 << (8 * size)) - 1)).to_bytes(size, 'big'))
        else:
            if 0x700000 <= address < 0x900100:
                value = 0
            else:
                assert all(address + i in self.bytes for i in range(size)), (self.case, hex(site), hex(address), size)
                value = int.from_bytes(bytes(self.bytes[address + i] for i in range(size)), 'big')
        self.events.append({'case': self.case, 'event': len(self.events), 'kind': kind, 'address': hex(address), 'size': size, 'value': hex(value & ((1 << (size * 8)) - 1)), 'site': hex(site)})
        return value


def model(mem, slots, runs, extra, start=0x8012021c, stop=0x801203c8, max_steps=2000000):
    regs, cr, ctr = [0] * 32, [False, False, False, False], 0
    regs[27], regs[28], regs[29], regs[30] = slots, 0x800000, runs, extra
    regs[26], regs[31] = slots, 1
    pc, steps = start, 0
    while pc != stop:
        assert steps < max_steps, ('host instruction budget', mem.case)
        steps += 1
        w = native[pc]
        op, d, a, b, xo = w >> 26, (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31, (w >> 1) & 1023
        immediate, next_pc = s(w & 65535), pc + 4
        if op in [32, 42]:
            addr = ((regs[a] if a else 0) + immediate) & 0xffffffff
            value = mem.access('read', addr, 4 if op == 32 else 2, site=pc)
            regs[d] = value if op == 32 else s(value) & 0xffffffff
        elif op == 36:
            mem.access('write', ((regs[a] if a else 0) + immediate) & 0xffffffff, 4, regs[d], pc)
        elif op == 14:
            regs[d] = ((regs[a] if a else 0) + immediate) & 0xffffffff
        elif op == 21:
            regs[a] = rot(regs[d], b) & mask((w >> 6) & 31, (w >> 1) & 31)
        elif op == 28:
            regs[a] = regs[d] & (w & 65535)
            cr = [False, regs[a] != 0, regs[a] == 0, False]
        elif op in [10, 11] or op == 31 and xo in [0, 32]:
            unsigned = op == 10 or op == 31 and xo == 32
            left = regs[a] if unsigned else s(regs[a], 32)
            right = (w & 65535 if unsigned else immediate) if op in [10, 11] else (regs[b] if unsigned else s(regs[b], 32))
            cr = [left < right, left > right, left == right, False]
        elif op == 31 and xo == 444:
            regs[a] = regs[d] | regs[b]
        elif op == 31 and xo == 266:
            regs[d] = (regs[a] + regs[b]) & 0xffffffff
        elif op == 31 and xo == 104:
            regs[d] = (-regs[a]) & 0xffffffff
        elif op == 31 and xo == 467:
            assert a | (b << 5) == 9
            ctr = regs[d]
        elif op == 18:
            if w & 1:
                # Scope: calls are opaque, input-memory mutation and FP/MMIO effects excluded.
                pass
            else:
                target = s(w & 0x3fffffc, 26)
                next_pc = (target if w & 2 else pc + target) & 0xffffffff
        elif op == 16:
            if not d & 4:
                ctr = (ctr - 1) & 0xffffffff
            ctr_ok = bool(d & 4) or ((ctr != 0) != bool(d & 2))
            cond_ok = bool(d & 16) or cr[a] == bool(d & 8)
            if ctr_ok and cond_ok:
                target = s(w & 0xfffc)
                next_pc = (target if w & 2 else pc + target) & 0xffffffff
        elif op == 48:
            # FP loads are outside the cursor/read-order proof, as are their outputs.
            pass
        else:
            raise AssertionError(('unsupported original integer model instruction', hex(pc), hex(w)))
        pc = next_pc
    return [int.from_bytes(bytes(mem.bytes[slots + 4 * j + i] for i in range(4)), 'big') for j in range(extra + 1)], steps


def reference(mem, slots, runs, extra):
    assert runs > 0, 'host zero outer-count rejection'
    for _ in range(runs):
        ptr = mem.access('read', slots, 4, site=0x8012021c)
        mem.access('write', slots, 4, ptr + 2, 0x80120224)
        count = s(mem.access('read', ptr, 2, site=0x80120228))
        for j in range(1, extra + 1):
            base = slots + j * 4
            ptr = mem.access('read', base, 4)
            mem.access('write', base, 4, ptr + 2)
        assert count != 0, 'host zero run-count rejection'
        for _ in range(abs(count)):
            ptr = mem.access('read', slots, 4)
            mem.access('write', slots, 4, ptr + 2)
            index = s(mem.access('read', ptr, 2))
            mem.access('read', (0x800000 + index * 32 + 24) & 0xffffffff, 4)
            for j in range(extra + 1):
                base = slots + 4 * j
                if j:
                    ptr = mem.access('read', base, 4)
                    mem.access('write', base, 4, ptr + 2)
                for _ in range(2):
                    ptr = mem.access('read', base, 4)
                    mem.access('write', base, 4, ptr + 2)
                    mem.access('read', ptr, 2)
    return [int.from_bytes(bytes(mem.bytes[slots + j * 4 + i] for i in range(4)), 'big') for j in range(extra + 1)]


events, comparisons = [], []
for extra in [0, 1, 2, 7, 8, 9, 15, 16, 17]:
    for equal in [False, True]:
        case = f'explicit_k{extra}_' + ('equal_streams' if equal else 'distinct_streams')
        memories = [Memory(case), Memory(case)]
        slots = 0x200000
        for m in memories:
            for j in range(extra + 1):
                ptr = 0x100000 + (0 if equal else 0x100 * j)
                m.put(slots + j * 4, struct.pack('>I', ptr))
                # Secondary count/index values deliberately disagree with stream zero.
                count = 65534 if j == 0 or equal else 0x7fff
                m.put(ptr, struct.pack('>13H', count, 65535, 0x1111, 0x2222, 2, 0x3333, 0x4444, 1, 3, 0x5555, 0x6666, 0, 0))
        a, steps = model(memories[0], slots, 2, extra)
        b = reference(memories[1], slots, 2, extra)
        norm = lambda m: [(r['kind'], r['address'], r['size'], r['value']) for r in m.events]
        assert a == b and norm(memories[0]) == norm(memories[1]), case
        events.extend(memories[0].events)
        comparisons.append({'case': case, 'extra_streams_k': extra, 'streams': extra + 1, 'equal_data_pointers': equal, 'runs': 2, 'records': 3, 'original_integer_steps': steps, 'memory_events': len(memories[0].events), 'final_cursor_values': ';'.join(hex(v) for v in a), 'result': 'ordered reads/writes match independent reference', 'qualification': 'synthetic explicit data/state; native calls FP MMIO/input alias effects excluded'})

# Focused original prefixes demonstrate why native pointer-array/data alias is excluded.
alias_results = []
for name, start, stop, read_site in [('slot0_count_alias', 0x8012021c, 0x8012022c, 0x80120228), ('slot0_index_alias', 0x80120320, 0x80120334, 0x8012032c), ('slot0_pair_alias', 0x80120378, 0x80120388, 0x80120384)]:
    m = Memory(name)
    slots, data = 0x1fffc, 0x1fffe
    m.put(slots, struct.pack('>I', data))
    before = int.from_bytes(bytes(m.bytes[data + i] for i in range(2)), 'big')
    _, steps = model(m, slots, 1, 0, start, stop)
    observed = next(r for r in m.events if r['site'] == hex(read_site))
    assert before == 0xfffe and int(observed['value'], 16) == 0
    events.extend(m.events)
    alias_results.append({'case': name, 'pointer_slot_address': hex(slots), 'data_read_address': hex(data), 'before_u16': hex(before), 'after_original_store_read_u16': observed['value'], 'read_site': hex(read_site), 'original_integer_steps': steps, 'result': 'write-before-read changes pointed bytes; immutable snapshot would differ'})

# A real-data explicit group repeats each actual paired packet as two independent streams.
# It does not assert any retail grouping or draw selection; no grouped sample was discovered.
sample_path = ROOT / 'work/sa2-disc/sonicmdl.prs.decoded'
sample = sample_path.read_bytes()
assert sha(sample) == 'b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963'
packet_path = ROOT / 'work/sa2-draw-grammar-v1/sample-unique-packets.csv'
packets = [r for r in rows(packet_path) if r['opcode'] in ['0x41', '0x42']]
real_runs, real_records, real_cases = [], [], []
for p in packets:
    packet, start, end, info = (int(p[k], 16) for k in ['offset', 'data_offset', 'next_offset', 'raw_info'])
    cursors = [start, start]
    run_count = info & 0x3fff
    records = 0
    for run in range(run_count):
        headers = []
        for stream in range(2):
            ptr = cursors[stream]
            headers.append(struct.unpack_from('>H', sample, ptr)[0])
            cursors[stream] += 2
        magnitude = abs(s(headers[0]))
        assert magnitude
        real_runs.append({'packet_offset': hex(packet), 'run': run, 'first_count_raw': hex(headers[0]), 'first_count_s16': s(headers[0]), 'used_magnitude': magnitude, 'secondary_count_raw_not_consumed_by_native': hex(headers[1])})
        for record in range(magnitude):
            for stream in range(2):
                ptr = cursors[stream]
                assert ptr + 6 <= end
                index, first, second = struct.unpack_from('>HHH', sample, ptr)
                real_records.append({'packet_offset': hex(packet), 'run': run, 'record': record, 'stream': stream, 'offset': hex(ptr), 'index_raw': hex(index), 'index_read_by_native': stream == 0, 'pair_first_raw': hex(first), 'pair_second_raw': hex(second), 'raw_hex': sample[ptr:ptr + 6].hex()})
                cursors[stream] += 6
            records += 1
    assert cursors[0] == cursors[1] <= end
    real_cases.append({'packet_offset': hex(packet), 'explicit_group_stream_offsets': f'{hex(start)};{hex(start)}', 'information_from_completing_command': hex(info), 'runs': run_count, 'records': records, 'stream_end_offsets': ';'.join(hex(v) for v in cursors), 'padding_per_stream': end - cursors[0], 'qualification': 'real bytes with hypothetical duplicate-stream caller input; not observed/native selected group'})

domain = []
for info in range(65536):
    group = (s(info) & 0xffffffff) >> 14
    domain.append({'raw_info': hex(info), 'outer_k': group, 'callee_masked_run_count': info & 0x3fff, 'masked_inner_skip_bits': info >> 14})
unrolled = [{'k': k, 'blocks8': k >> 3, 'tail': k & 7, 'slots_touched': ';'.join(str(i) for i in range(1, k + 1))} for k in range(257)]
assert all((r['blocks8'] * 8 + r['tail']) == r['k'] for r in unrolled)
stack_overlap = [{'flag_index': i, 'flag_relative_offset': hex(0x10 + 4 * i), 'pointer_slot_alias': (0x10 + 4 * i - 0x30) // 4 if i >= 8 else '', 'qualification': 'original caller stack-relative addresses only; no safe native capacity inferred'} for i in range(24)]
save('ordered-model-events.csv', events)
save('ordered-model-cases.csv', comparisons)
save('native-alias-prefix-cases.csv', alias_results)
save('real-explicit-group-cases.csv', real_cases)
save('real-explicit-group-runs.csv', real_runs)
save('real-explicit-group-records.csv', real_records)
save('outer-information-domain.csv', domain)
save('unrolled-secondary-header-domain.csv', unrolled)
save('caller-stack-array-overlap.csv', stack_overlap)
save('validation-input-sha256.csv', [{'path': str(p), 'sha256': sha(p.read_bytes())} for p in [sample_path, packet_path, OUT / 'original-words.csv', Path(__file__)]])
summary = {'result': 'passed', 'ordered_model_cases': len(comparisons), 'ordered_model_steps': sum(r['original_integer_steps'] for r in comparisons), 'ordered_model_events': sum(r['memory_events'] for r in comparisons), 'alias_prefix_cases': len(alias_results), 'all_model_events': len(events), 'unrolled_k_cases': len(unrolled), 'outer_information_cases': len(domain), 'outer_k_domain_counts': dict(collections.Counter(r['outer_k'] for r in domain)), 'real_explicit_duplicate_stream_cases': len(real_cases), 'real_first_stream_runs': len(real_runs), 'real_first_stream_records': sum(r['records'] for r in real_cases), 'real_stream_record_rows': len(real_records), 'observed_retail_groups': 0, 'real_data_qualification': 'Explicit hypothetical pairs of real packet bytes; not actual group selection.', 'zero_counts': 'Original do-while,algebraic2^32ifmemorysurvives;hostreject,notexecuted', 'original_integer_model_limits': ['Only original2021C..203C8 structural integer operations', 'FP loads ignored; scratch word24 reads supplied zero', 'Calls opaque/no input-memory side effects or volatile-clobber behavior modeled', 'NoMMIO/nativeCPU/exceptions modeled'], 'engine_changes': [], 'native_execution': False, 'project_opens': 0}
(OUT / 'validation.ai.json').write_text(json.dumps(summary, indent=2) + '\n')
(OUT / 'validation.md').write_text('# Grouped reader validation\n\nOne once-only bounded original-integer cursor model matched an independent ordered-memory reference across18 synthetic equal/distinct-stream cases. Three original-word prefixes demonstrate native cursor-array/data alias changes. Real Sonic paired packets were reused as explicit hypothetical duplicate-stream groups; they are not observed retail groups. Full counts, scope exclusions and complete events are in the AI twin and CSV.\n')
print(json.dumps(summary, separators=(',', ':')))
