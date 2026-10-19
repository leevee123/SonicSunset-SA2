import csv
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

out = Path(__file__).resolve().parent
base = out.parents[1]
sha = lambda data: hashlib.sha256(data).hexdigest()
number = lambda value: int(value, 0)
rows = lambda path: list(csv.DictReader(path.open(newline='', encoding='utf-8-sig')))
assert not (out / 'control-traces.ai.json').exists(), 'Do not rerun a completed version.'
summary = json.loads((out / 'summary.ai.json').read_text())
assert summary['result'] == 'passed'
expected = {r['name']: r['sha256'] for r in summary['artifacts']}
protected = {}
def protect(path, role, digest=None):
    path = path.resolve()
    data = path.read_bytes()
    assert digest is None or sha(data) == digest, str(path)
    protected[path] = {'path': str(path), 'role': role, 'sha256_before': sha(data), 'bytes_before': len(data), 'expected_sha256': digest or ''}
    return data

protect(out / 'summary.ai.json', 'passed_inventory_report')
for name in ('commands.csv', 'cache-reference-candidates.csv', 'local-invocation-spans.csv'):
    protect(out / name, 'independent_inventory', expected[name])
protect(Path(__file__), 'control_trace_script')
decoded = protect(base / 'work/sa2-disc/sonicmdl.prs.decoded', 'original_decoded_bank', summary['decoded_sha256'])
for record in rows(out / 'source-digests.csv'):
    protect(Path(record['path']), 'inventory_protected_source', record['sha256_after'])
commands = {number(r['offset']): r for r in rows(out / 'commands.csv')}
for offset, record in commands.items():
    end = number(record['next_offset'])
    assert struct.unpack_from('>H', decoded, offset)[0] == number(record['header'])
    assert decoded[offset:end].hex() == record['raw_bytes']
    assert sha(decoded[offset:end]) == record['raw_sha256']

cases = []
raw_steps = []
transitions = []
def trace(case_id, root, initial_cache, kind, definition_offset=None, reference_offset=None):
    cache = dict(initial_cache)
    steps = []
    active = set()
    blocked = []
    def transition(event, depth, offset, slot='', target=''):
        transitions.append({'case_id': case_id, 'event_order': sum(r['case_id'] == case_id for r in transitions), 'event': event, 'call_depth': depth, 'offset': hex(offset), 'slot': slot, 'target': hex(target) if isinstance(target, int) else target})
    def walk(entry, depth):
        if entry in active:
            blocked.append({'reason': 'active_entry_cycle_host_stop', 'offset': hex(entry), 'call_depth': depth})
            return False
        if depth >= 64:
            blocked.append({'reason': 'depth_host_bound', 'offset': hex(entry), 'call_depth': depth})
            return False
        active.add(entry)
        transition('enter', depth, entry)
        position = entry
        for _ in range(10000):
            if position not in commands:
                blocked.append({'reason': 'not_in_validated_command_inventory', 'offset': hex(position), 'call_depth': depth})
                active.remove(entry)
                return False
            record = commands[position]
            header = struct.unpack_from('>H', decoded, position)[0]
            opcode, slot = header & 0xff, header >> 8
            end = number(record['next_offset'])
            step = {'offset': hex(position), 'call_depth': depth, 'entry_offset': hex(entry), 'header': hex(header), 'next_offset': hex(end), 'byte_size': int(record['byte_size']), 'raw_sha256': record['raw_sha256'], 'raw_bytes': record['raw_bytes'], 'size_word': record.get('size_word', ''), 'count_word': record.get('count_word', ''), 'classification': record['classification']}
            raw_steps.append(dict(case_id=case_id, step_order=len(steps), **step))
            steps.append(step)
            if header == 0xff:
                transition('return_exact_00ff', depth, position)
                active.remove(entry)
                return True
            if opcode == 4:
                cache[slot] = end
                transition('cache_store_following_pointer', depth, position, slot, end)
                transition('return_after_definition', depth, position)
                active.remove(entry)
                return True
            if opcode == 5:
                if slot not in cache:
                    blocked.append({'reason': 'unseeded_cache_slot', 'offset': hex(position), 'slot': slot, 'call_depth': depth})
                    transition('unseeded_cache_call_stop', depth, position, slot)
                    active.remove(entry)
                    return False
                target = cache[slot]
                transition('cache_call_explicit_known_value', depth, position, slot, target)
                if not walk(target, depth + 1):
                    active.remove(entry)
                    return False
                transition('resume_after_cache_call', depth, end, slot)
            position = end
        blocked.append({'reason': 'command_count_host_bound', 'offset': hex(position), 'call_depth': depth})
        active.remove(entry)
        return False
    completed = walk(root, 0)
    cases.append({'case_id': case_id, 'case_kind': kind, 'root_offset': hex(root), 'initial_cache': {str(k): hex(v) for k, v in sorted(initial_cache.items())}, 'steps': steps, 'final_cache': {str(k): hex(v) for k, v in sorted(cache.items())}, 'status': 'completed_static_control' if completed else 'blocked_unknown_or_host_bound', 'blocked': blocked, 'definition_offset': hex(definition_offset) if definition_offset is not None else '', 'reference_offset': hex(reference_offset) if reference_offset is not None else '', 'retail_binding_or_order_claim': False})

definitions = sorted((r for r in commands.values() if number(r['opcode']) == 4), key=lambda row: number(row['offset']))
for index, record in enumerate(definitions):
    offset = number(record['offset'])
    trace('definition-' + str(index).zfill(3), offset, {}, 'definition_root_empty_explicit_cache', definition_offset=offset)
candidates = rows(out / 'cache-reference-candidates.csv')
for index, record in enumerate(candidates):
    reference = number(record['reference_offset'])
    definition = number(record['definition_offset'])
    target = number(record['candidate_body_offset'])
    slot = int(record['slot'])
    assert target == definition + 2
    assert number(commands[definition]['opcode']) == 4 and number(commands[reference]['opcode']) == 5
    assert number(commands[definition]['header']) >> 8 == number(commands[reference]['header']) >> 8 == slot
    trace('candidate-' + str(index).zfill(3), reference, {slot: target}, 'reference_with_one_explicit_candidate_seed', definition, reference)

def write(name, values, fields=None):
    if fields is None:
        fields = list(dict.fromkeys(key for row in values for key in row))
    with (out / name).open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(values)

raw_cases = [{k: json.dumps(v, separators=(',', ':')) if isinstance(v, (dict, list)) else v for k, v in record.items() if k != 'steps'} | {'step_count': len(record['steps'])} for record in cases]
write('control-trace-cases.csv', raw_cases)
write('control-trace-steps.csv', raw_steps)
write('control-trace-transitions.csv', transitions)
digests = []
for path, record in sorted(protected.items(), key=lambda pair: str(pair[0])):
    data = path.read_bytes()
    assert sha(data) == record['sha256_before'] and len(data) == record['bytes_before']
    digests.append(dict(record, sha256_after=sha(data), bytes_after=len(data), unchanged=True))
write('control-trace-source-digests.csv', digests)
stats = {'version': 1, 'result': 'passed', 'definition_root_cases': len(definitions), 'explicit_candidate_seed_cases': len(candidates), 'cases': len(cases), 'statuses': dict(Counter(r['status'] for r in cases)), 'ordered_command_steps': len(raw_steps), 'control_transitions': len(transitions), 'max_call_depth': max(r['call_depth'] for r in raw_steps), 'blocked_cases': sum(bool(r['blocked']) for r in cases), 'protected_files_unchanged': len(digests), 'all_command_bytes_match_original_decoded_bank': True, 'native_execution': False, 'engine_execution': False, 'implicit_cache_initialization': False, 'retail_binding_or_execution_order_claim': False, 'source': '0x8011CCF8; exact 00FF and 04 return; 05 recursively calls explicit cache value then continues locally', 'offset_space': 'decoded sonicmdl.prs', 'script_runs': 'reference_control_traces_v1.py once'}
report = {'summary': stats, 'cases': cases, 'unknowns': ['Actual retail cache contents, caller order and which candidate binds each reference.', 'Rendering, shared global-state effects, vertex scratch data and native callback/ABI behavior.'], 'artifacts': [{'name': name, 'sha256': sha((out / name).read_bytes()), 'bytes': (out / name).stat().st_size} for name in ('reference_control_traces_v1.py', 'control-trace-cases.csv', 'control-trace-steps.csv', 'control-trace-transitions.csv', 'control-trace-source-digests.csv')]}
(out / 'control-traces.ai.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
(out / 'control-traces.md').write_text('# Explicit-seed Sonic second-stream control references v1\n\nOne run of reference_control_traces_v1.py passed. These are synthetic callers over real command bytes, suitable for comparison with a separate control-only implementation. They do not establish game draw order, initial cache state or actual bindings.\n\nMachine result: ' + json.dumps(stats, separators=(',', ':')) + '\n\nEach of the 15 definition-root cases begins at its real definition command with an explicitly empty cache. Each of the 113 candidate cases begins at a real reference command, with exactly its matching slot seeded to one in-file definition\'s following pointer. Other slots remain unknown. Commands, nested call depth, headers, raw spans and SHA256 values are preserved in order. Definitions store the following pointer and return; exact 00FF returns; references invoke the explicitly supplied entry and resume if it returns. Missing slots or cycles would stop at the exact site without substitution.\n\ncontrol-traces.ai.json exposes cases with root_offset, initial_cache, ordered steps and final_cache. Complete raw CSVs retain case metadata, command steps, control transitions and unchanged source digests. No original, frozen, repository or engine files were modified; no engine or native execution occurred.\n', encoding='utf-8')
print(json.dumps(stats, separators=(',', ':')))
