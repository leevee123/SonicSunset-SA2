import ast
import csv
import hashlib
import json
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
V2 = OUT / 'word-audit-v2'
sources = {}


def read(path):
    path = Path(path)
    data = path.read_bytes()
    sources[str(path.relative_to(ROOT))] = hashlib.sha256(data).hexdigest()
    return data


def rows(path):
    return list(csv.DictReader(read(path).decode('utf-8-sig').splitlines()))


def save(name, values, fields=None):
    with (OUT / name).open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields or list(values[0]))
        writer.writeheader()
        writer.writerows(values)


"""/* Use the corrected v2 decoder column and retain the original word evidence.
The earlier v1 raw bytes were right, but its convenience decoder arguments were reversed. */"""
raw = rows(V2 / 'bounded-original-words.csv')
words = {int(row['va'], 16): row for row in raw}
for row in raw:
    decoded = ast.literal_eval(row['decode'])
    assert decoded['opcode'] == int(row['word'], 16) >> 26
    row['decoded'] = decoded['decoded']

checks = {
    0x8011CD0C: 0x7C741B78, 0x8011CD10: 0x7C952378,
    0x8011CD14: 0x3B000000, 0x8011CD18: 0x3AE00000,
    0x8011CD20: 0x900D8E8C,
    0x8011CD30: 0x3C608035, 0x8011CD34: 0x3BA37A58,
    0x8011CD90: 0x5780C63E, 0x8011CD94: 0x7C000734,
    0x8011CD98: 0x5404103A, 0x8011CD9C: 0x3C608035,
    0x8011CDA0: 0x38037A58, 0x8011CDA4: 0x7C602214,
    0x8011CDA8: 0x92830000, 0x8011CDAC: 0x806D8E34,
    0x8011CDB0: 0x38030001, 0x8011CDB4: 0x900D8E34,
    0x8011CDB8: 0x480003DC,
    0x8011CDBC: 0x5780C63E, 0x8011CDC0: 0x7C000734,
    0x8011CDC4: 0x5400103A, 0x8011CDC8: 0x7C7D0214,
    0x8011CDCC: 0x80630000, 0x8011CDD0: 0x7EA4AB78,
    0x8011CDD4: 0x4BFFFF25, 0x8011CDD8: 0x806D8E34,
    0x8011CDDC: 0x3803FFFF, 0x8011CDE0: 0x900D8E34,
    0x8011CDE4: 0x480003A0,
    0x8011D184: 0xAB940000, 0x8011D188: 0x3A940002,
    0x8011D18C: 0x2C1C00FF, 0x8011D190: 0x4082FBB0,
    0x8011D410: 0x4E800020,
    0x801205B8: 0x3CA08012, 0x801205BC: 0x38A5D414,
    0x8012177C: 0x7CBF2B78, 0x8012178C: 0x93E3000C,
    0x801217F0: 0x807F0004, 0x80121810: 0x8184000C,
    0x80121818: 0x4E800021,
}
for address, value in checks.items():
    assert int(words[address]['word'], 16) == value, hex(address)

"""/* Exhaustively check the 16-bit header extraction against the actual rotate
and mask fields. The 256-value index domain does not establish allocated extent. */"""
def rotate(value, amount):
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF


indices = set()
terminals = []
for header in range(0x10000):
    loaded = header if header < 0x8000 else header - 0x10000
    index = rotate(loaded & 0xFFFFFFFF, 24) & 0xFF
    assert index == header >> 8
    indices.add(index)
    if loaded == 0xFF:
        terminals.append(header)
assert len(indices) == 256 and terminals == [0xFF]

"""/* Validate every retained initial control stop against decoded retail bytes.
File order is deliberately not used as a cache execution-order substitute. */"""
decoded_path = ROOT / 'work/sa2-disc/sonicmdl.prs.decoded'
decoded = read(decoded_path)
assert len(decoded) == 136360
assert hashlib.sha256(decoded).hexdigest() == 'b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963'
controls = rows(OUT / 'initial-sample-cache-controls.csv')
for row in controls:
    position = int(row['offset'], 16)
    header = struct.unpack_from('>H', decoded, position)[0]
    assert header == int(row['header'], 16)
    assert header & 0xFF in (4, 5)
    assert header >> 8 == int(row['cache_index'])
    row['original_decoded_file'] = str(decoded_path.relative_to(ROOT))
    row['original_decoded_sha256'] = hashlib.sha256(decoded).hexdigest()
    row['runtime_va'] = ''
    row['iso_offset'] = ''
    row['offset_kind'] = 'PRS-decoded source offset; no direct compressed ISO mapping or runtime binding asserted'
save('validated-initial-cache-controls.csv', controls)
inventory = rows(OUT / 'initial-sample-cache-indices.csv')
assert sum(int(row['definition_stops']) for row in inventory) == 15
assert sum(int(row['reference_stops']) for row in inventory) == 15

"""/* Recheck every selected original/C/ASM/metadata source hashed by the v2
word audit. The larger C-search manifest is retained as read-time provenance. */"""
guards = rows(V2 / 'word-audit-source-hashes.csv')
for row in guards:
    current = hashlib.sha256(read(ROOT / row['path'])).hexdigest()
    assert current == row['sha256'], row['path']
    row['final_unchanged'] = True
save('selected-source-hash-guards.csv', guards)
read(OUT / 'discovery-source-hashes.csv')
read(OUT / 'named-reference-lines.csv')
read(OUT / 'incoming-direct-calls.csv')
node_path = ROOT / 'work/sa2-node-consumers/node-consumers.ai.json'
if node_path.exists():
    read(node_path)

anchors = [0x8011CCF8, 0x8011CD0C, 0x8011CD10, 0x8011CD20,
           0x8011CD90, 0x8011CDA8, 0x8011CDB4, 0x8011CDB8,
           0x8011CDCC, 0x8011CDD0, 0x8011CDD4, 0x8011CDE0,
           0x8011D184, 0x8011D188, 0x8011D18C,
           0x8011D2F4, 0x8011D410, 0x8011D414, 0x8011D484,
           0x8011D4EC, 0x8011D554, 0x80120584, 0x80121764,
           0x8012178C, 0x801217B0, 0x801217F0, 0x80121818,
           0x8011867C, 0x801199B0, 0x8010AFB0, 0x8010AFFC]
save('canonical-evidence-sites.csv', [words[address] for address in anchors])
reference_rows = rows(V2 / 'all-text-explicit-cache-references.csv')
counter_rows = [row for row in reference_rows if 'counter_sda' in row['kind']]
assert {int(row['va'], 16) for row in counter_rows} == {0x8011CDAC, 0x8011CDB4, 0x8011CDD8, 0x8011CDE0}

def site(address):
    row = words[address]
    return f"`{row['va']}` / DOL `{row['dol_file_offset']}` / ISO `{row['iso_file_offset']}`"


word_audit = json.loads(read(V2 / 'word-audit.ai.json'))
result = {
    'status': 'bounded original-code cache-lifecycle audit complete; not runtime initialization or draw-equivalence proof',
    'DOL_sha256': word_audit['DOL_sha256'],
    'scope': {'primary_C_files': 4405, 'startup_SDA_C_files': 4406, 'original_text_words': 376848, 'bounded_function_helper_scopes': 14, 'bounded_original_words': 700, 'ASM_rows_compared_across_views': 915, 'selected_sources_final_unchanged': len(guards)},
    'table': {'base_va': '0x80357a58', 'input_header': 'big-endian signed lha, exact terminal 0x00ff tested first', 'index': '(raw_header >> 8) & 0xff', 'stride_bytes': 4, 'index_domain_count': len(indices), 'addressable_end_exclusive': '0x80357e58', 'allocated_entry_count': None, 'file_backing': 'DOL BSS; no DOL/ISO bytes', 'runtime_initial_contents': 'unknown', 'overlap_caveat': '0x8011867c uses 0x80357c60; 0x801199b0 points unrelated fields at 0x80357c80/0x80357cf8/0x80357d70/0x80357de8, all within the full index-addressable span'},
    'command4': {'sites': ['0x8011cd90', '0x8011cda8', '0x8011cdb4', '0x8011cdb8'], 'operations': ['index from upper header byte', 'table[index] = address immediately following the command halfword', 'increment 32-bit SDA -0x71cc word by one', 'return from current interpreter invocation'], 'native_table_bounds_check': False},
    'command5': {'sites': ['0x8011cdbc', '0x8011cdcc', '0x8011cdd0', '0x8011cdd4', '0x8011cde0', '0x8011cde4'], 'operations': ['load table[index] with no NULL or initialization test', 'recursive 0x8011ccf8(r3=cached pointer, r4=current saved r4 context)', 'after recursive return decrement SDA -0x71cc word by one', 'resume caller at halfword following command5'], 'max_depth_or_cycle_guard_observed': False},
    'entry_frame': {'sites': ['0x8011cd0c', '0x8011cd10', '0x8011cd14', '0x8011cd18', '0x8011cd20'], 'facts': ['original r3 held in r20 and r4 in r21; save helper writes only GPR20..31 stack slots', 'fresh invocation resets r24/r23 local control state and global SDA -0x7174 (startup address0x803ae14c)', 'fresh invocation does not explicitly clear cache table/counter', 'recursive entry changes shared 0x803ae14c; no per-invocation restoration shown']},
    'counter': {'startup_assumption': 'r13=0x803b52c0', 'displacement': '-0x71cc', 'va_if_assumption': '0x803ae0f4', 'explicit_main_text_access_sites': [row['va'] for row in counter_rows], 'reset_proved': False, 'meaning': 'unknown; operation is increment on definition and decrement after reference return, not proved recursion depth or live-entry count'},
    'caller_order': [
        {'entry': '0x8011d414', 'facts': ['call0x8011c18c', 'save0x803ae15c context', 'if payload+0 nonnull call0x8011d1d4', 'call0x801160e4', 'if payload+4 nonnull call0x8011ccf8 with saved context', 'return zero']},
        {'entry': '0x8011d554', 'facts': ['setup0x8011d2f4 once', 'traverse0x8011dfc0 with callback0x8011d484', 'finish0x8011d410']},
        {'entry': '0x8011d484', 'facts': ['conditionally forward payload to0x8011d414; no explicit cache reset']},
        {'entry': '0x8011d4ec', 'facts': ['gate then setup0x8011d2f4, payload dispatcher0x8011d414, finish0x8011d410']},
        {'entry': '0x80120584', 'facts': ['setup0x8011d2f4', 'pass0x8011d414 in r5 into0x80121764', 'finish0x8011d410']},
        {'entry': '0x80121764', 'facts': ['preserve incoming r3/r5', 'call0x80113b10 with original r4', 'store callback in current provider+0x0c', 'call0x801217b0 with original r3; full FP/register ABI not reconstructed']},
        {'entry': '0x801217b0', 'facts': ['transform helper calls then optional shared callback0x803ae048(node)', 'reload payload+4 and nodeflags; payload nonnull and flag8 clear invokes current provider+0x0c with r3=payload', 'live link+0x2c recursive traversal', 'restore helper0x801160e4', 'live link+0x30 loop', 'callback and link mutation effects remain possible']},
    ],
    'reset_boundary': 'Named-symbol search plus explicit original forms proves no reset in the inspected wrapper bodies, not absence of bulk aliases, helper side effects, REL writes, or runtime initialization.',
    'sample': {'decoded_sha256': hashlib.sha256(decoded).hexdigest(), 'decoded_bytes': len(decoded), 'validated_initial_controls': len(controls), 'definition_stops': 15, 'reference_stops': 15, 'indices': inventory, 'execution_order_claimed': False},
    'unknowns': ['native reserved table extent', 'initial/reset values and actual cache lifetime', 'which concrete definition is active at an arbitrary reference', 'global counter purpose and consumers through aliases', 'all indirect or module callers/writes', 'caller/root/culling/custom-callback state at runtime', 'recursive cycles and maximum depth', 'full second-stream GPU/state semantics and full FP/return ABI'],
    'artifact_corrections': ['word-audit-v2 is authoritative. Earlier v1 convenience decode column used reversed decoder arguments; raw bytes/mapping/ASM comparisons were unaffected. Do not use earlier decoded columns or their derived windows.', 'Earlier discovery.md wording of256 slots is an addressable index domain only, not a native allocation extent. This report supersedes that wording.'],
    'changes': {'engine': [], 'repo_docs': [], 'originals_or_frozen_exports': []},
}
(OUT / 'cache-lifecycle.ai.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')

human = f"""# Original second-stream draw-cache lifecycle — bounded audit

This audit establishes the operations and bounded caller order around `0x8011CCF8`. It does **not** establish runtime initialization, a reserved table allocation, model execution order, or draw equivalence. No engine, repository, original, frozen export, Ghidra project, or language file was changed. No game code was run.

## Cache operation proved by original instructions

The interpreter entry is {site(0x8011CCF8)}. Original `lha` at {site(0x8011D184)} reads a halfword; {site(0x8011D188)} advances the stream pointer by two; {site(0x8011D18C)} tests exact `0x00FF` before command dispatch. Exhaustively checking all65,536 halfwords against the original rotate/mask fields gives256 upper-byte indices and exactly one terminal (`0x00FF`).

The index is `(raw_header >> 8) & 0xFF`, and the table-entry address is `0x80357A58 + index*4`. The full index domain reaches exclusive `0x80357E58`; this is an **addressable span**, not proof of256 allocated entries. The base lies in original DOL BSS, so it has no canonical DOL/ISO data bytes. Runtime zeroing was not investigated or claimed. At `0x8011867C`, generated C passes `0x80357C60` to file/parser helpers; `0x801199B0` stores pointers to `0x80357C80`, `0x80357CF8`, `0x80357D70`, `0x80357DE8` in other globals. These lie inside the full index domain. Their naming/uses do not prove table ownership or safe native bounds.

Command4 extracts the index at {site(0x8011CD90)}. At {site(0x8011CDA8)}, it stores the already advanced stream pointer, so the cached pointer begins **after** the definition command. It increments the32-bit word at SDA displacement `-0x71CC` and stores it at {site(0x8011CDB4)}. It branches directly to the current invocation's return epilogue at {site(0x8011CDB8)}. It does not execute the cached body during this definition invocation, and no table bounds/validity check is shown.

Command5 loads the selected cached pointer at {site(0x8011CDCC)}, places the current saved second argument in r4 at {site(0x8011CDD0)}, and recurses at {site(0x8011CDD4)}. There is no NULL/defined-entry test between load and recursive call. After the recursive return it decrements the same SDA word and stores it at {site(0x8011CDE0)}, then resumes the caller's already advanced pointer at the next halfword. No recursion-depth/cycle guard appears in this path.

Original entry words hold incoming r3 in r20 and incoming r4 in r21 ({site(0x8011CD0C)}; {site(0x8011CD10)}). The audited `0x8010AFB0`/`0x8010AFFC` helpers only save/restore GPR20..31 stack slots; the generated pair-return/void signatures are not trusted. A recursive invocation creates fresh local control state and clears SDA `-0x7174` at {site(0x8011CD20)} (`0x803AE14C` under startup r13). It does not explicitly clear the table or counter. The shared clear is not a restored per-frame value in this function.

## Counter, reset, and lifetime limit

Under startup `r13=0x803B52C0`, SDA `-0x71CC` is `0x803AE0F4`. All376,848 original main-DOL text words were scanned for the exact applicable r13-relative immediate forms: only `0x8011CDAC`, `0x8011CDB4`, `0x8011CDD8`, `0x8011CDE0` match, the two load/store pairs above. Two table low-half materializations match, both in the interpreter. Two original direct branches target the interpreter, from its recursive site and dispatcher `0x8011D414`. There are no aligned literal pointer words equal to the interpreter/table/counter in the original DOL. These are **bounded explicit-form results**, not alias or indirect-call completeness proofs.

The8,811-file primary/SDA generated-C named-symbol scan likewise finds the counter only in the interpreter. `0x8011D2F4` resets other globals `0x803AE140/144/148`, not an explicit table/counter store; `0x8011D410` is an original `blr` at {site(0x8011D410)}. None of the inspected wrapper bodies explicitly resets this cache. Helper aliases, bulk clears, REL writes, and runtime startup state remain outside the proof. The counter's purpose is unknown: increment on definition and decrement after cached invocation do not by themselves prove recursion depth or number of active definitions. No reset or specific frame/model lifetime is inferred.

## Caller order supported by code

At {site(0x8011D414)}, the dispatcher first calls `0x8011C18C`, saves `0x803AE15C`, processes nonnull payload+0 via `0x8011D1D4`, calls `0x801160E4`, and then processes nonnull payload+4 via `0x8011CCF8` with the saved context. This proves order **within a dispatcher invocation** only.

`0x8011D554` calls setup `0x8011D2F4` once, traverses `0x8011DFC0` with callback `0x8011D484`, then calls finish `0x8011D410`. The callback may gate out the dispatcher. The previously audited live links, flags and callbacks control node order. `0x8011D4EC` instead gates, then runs setup→dispatcher→finish for its forwarded payload. These paths do not supply a file-order rule.

An additional bounded provider path begins at {site(0x80120584)}: setup→`0x80121764`→finish. Original words `0x801205B8/BC` place `0x8011D414` in r5. In `0x80121764`, the callback is saved, `0x80113B10` is called with incoming r4, then the callback is stored into current provider+0x0C at {site(0x8012178C)} before `0x801217B0(original r3)`. The full floating-point/register ABI remains unknown.

In `0x801217B0`, transform helpers precede an optional shared callback (`0x803AE048(node)`); payload+4 and flags are then read live. A nonnull payload with node flag8 clear invokes current provider+0x0C, with r3 still holding that payload (`0x801217F0` through {site(0x80121818)}). Live link+0x2C recursion follows, then `0x801160E4`, then live link+0x30 iteration. No root selection, callback side effects, cache ownership or runtime equivalence is inferred from this path.

## Retail sample and validation result

Original decoded SONICMDL is136,360 bytes, SHA256`b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963`. All30 initial cache/control stops from the earlier bounded scan were rechecked against exact big-endian bytes:15 definitions and15 references. Index0 has8 definitions/8 references; index1 has7/7. Repeated indices establish why an arbitrary reference cannot be assigned a definition by index or file order alone. This inventory stops at each initial cache operation; it is not a dynamic trace and does not establish later cached-body contents.

Original DOL SHA256`{word_audit['DOL_sha256']}`; all8 original header mappings and segment hashes agree with retained mapping metadata. The14 bounded function/helper scopes retain700 original words, and915 retained ASM rows across the two views agree byte-for-byte and offset-for-offset. All{len(guards)} selected hashed source/metadata inputs remain unchanged at final guard. Complete raw CSV and source hashes are retained; canonical VA/DOL/ISO sites are in `canonical-evidence-sites.csv`. Sample offsets are decoded PRS offsets; no artificial ISO/runtime mapping is assigned to them.

## Unknowns and artifact status

Native allocated extent, initial/reset values, lifetime, active definition at each runtime reference, global-counter meaning/alias consumers, all indirect/module callers, concrete caller/root/culling state, recursive-cycle limits and second-stream state/GPU effects remain unknown. Conservative integration must keep caller/cache state explicit and must not claim native initialization or rendering.

`word-audit-v2/` is authoritative. The earlier v1 convenience decoder column reversed its arguments; original words and mapping/ASM comparisons were unaffected. Earlier decoded columns and their derived windows are superseded. The early discovery wording “256 slots” is superseded by the256-value addressable-domain distinction above. The final report and corrected v2 evidence are the handoff sources.
"""
(OUT / 'cache-lifecycle.md').write_text(human, encoding='utf-8')
save('final-report-source-hashes.csv', [{'path': path, 'sha256': sha} for path, sha in sorted(sources.items())])
manifest = []
for path in sorted(OUT.rglob('*')):
    if not path.is_file() or path.name.startswith('manifest.'):
        continue
    relative = str(path.relative_to(OUT))
    status = 'current'
    if path.parent == OUT and path.name in ('bounded-original-words.csv', 'all-text-explicit-cache-references.csv', 'all-text-interpreter-branches.csv', 'cache-register-control-windows.csv', 'word-audit.ai.json', 'word-audit.md', 'site-inspection.ai.json', 'site-inspection.md'):
        status = 'superseded decoder column; use word-audit-v2 and final report'
    if path.name in ('discovery.ai.json', 'discovery.md'):
        status = 'initial addressable-domain inventory; final report corrects allocation wording'
    manifest.append({'path': relative, 'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'status': status})
save('manifest.csv', manifest)
(OUT / 'manifest.ai.json').write_text(json.dumps({'files': manifest, 'engine_changes': [], 'source_unchanged_guard_count': len(guards)}, indent=2) + '\n', encoding='utf-8')
(OUT / 'manifest.md').write_text(f"# Cache audit manifest\n\n{len(manifest)} files, complete SHA256/size/status in `manifest.csv` and AI twin. Use `cache-lifecycle.md`, `cache-lifecycle.ai.json`, corrected `word-audit-v2/`, canonical-site and validated-sample CSVs. Superseded decoder columns are identified explicitly. No engine/repository/original/frozen files changed; {len(guards)} selected source guards pass.\n", encoding='utf-8')
print(json.dumps({'status': 'ready', 'report': str((OUT / 'cache-lifecycle.md').resolve()), 'selected_sources_unchanged': len(guards), 'original_words': len(raw), 'sample_controls_verified': len(controls), 'exhaustive_headers': 65536, 'native_allocation_extent': 'unknown', 'runtime_reset': 'unknown'}, separators=(',', ':')))
