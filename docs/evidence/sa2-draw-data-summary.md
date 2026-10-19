# Real Sonic second-stream data inventory v1

One run of inventory_draw_data_v1.py passed. The original decoded bank, frozen original-code digests, original DOL instruction words and prior initial command CSV matched. This is static file evidence, without a rendering or gameplay claim.

All command and stream addresses in these CSVs are decoded sonicmdl.prs file offsets. Native code addresses are identified separately.

Machine result: {"version":1,"result":"passed","decoded_bytes":136360,"decoded_sha256":"b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963","source_artifacts_verified":105,"prior_original_instruction_rows_verified":2427,"parser_original_instruction_rows":301,"protected_files":124,"recorded_hashes_verified":117,"all_protected_sources_unchanged":true,"payload_headers_checked":115,"nonzero_payload_stream4_entries":64,"prior_initial_command_rows_crosschecked":198,"local_invocation_entries_including_cached_bodies":79,"cached_body_entries":15,"local_return_kinds":{"exact_00ff_return":64,"cache_define_following_pointer_and_return":15},"unique_physical_commands":289,"local_command_occurrences":289,"unique_command_opcodes":{"0x11":13,"0x40":7,"0xff":64,"0x4":15,"0x5":15,"0x8":55,"0x41":66,"0x17":6,"0x14":3,"0x13":30,"0x0":15},"command_halfword_rows":21021,"unique_physical_command_bytes":42042,"physical_command_overlap_pairs":0,"cache_definitions":15,"cache_references":15,"cache_slots":2,"cache_candidate_pairs":113,"cache_slots_with_multiple_definitions":2,"references_without_in_file_definition":0,"geometry_commands":73,"geometry_opcodes":{"0x41":66,"0x40":7},"geometry_count_low14":{"28":1,"15":3,"3":5,"11":4,"4":7,"6":8,"148":1,"40":1,"7":1,"27":4,"16":2,"23":1,"1":8,"57":1,"8":2,"2":7,"49":1,"13":2,"5":2,"17":5,"14":1,"12":3,"10":1,"18":1,"43":1},"geometry_count_high2":{"0":73},"geometry_count_bit15_set_commands":0,"geometry_raw_data_bytes":40582,"geometry_original_group_expression_differences_in_sample":0,"all_u16_group_expression_cases_checked":65536,"all_u16_group_expression_differs_from_raw_high2":32768,"original_parser":"0x8011CCF8 / DOL 0x119CF8","offset_space":"decoded sonicmdl.prs file offsets; never observed runtime addresses","script_runs":"inventory_draw_data_v1.py once","runtime_execution_observed":false,"topology_or_attribute_semantics_inferred":false,"global_cache_initialized_or_file_order_executed":false,"engine_files_changed":[]}

## Boundaries and cache evidence

0x8011CCF8 loads a signed header and returns on exact 00FF (0x8011D184/18C). Low-byte command 4 stores the following pointer (0x8011CDA8) and branches to return (0x8011CDB8). Command 5 loads the current global slot and recursively calls the parser (0x8011CDCC/D4), then resumes locally. Accordingly, cached bodies are separate entries; a cache call continuation is conditional on the unresolved call returning.

The cache table below lists stored addresses in numeric order only. It establishes neither draw order nor a target binding.

| Slot | Definitions | References | Definition offsets | Candidate body offsets | Reference offsets |
|---:|---:|---:|---|---|---|
| 0 | 8 | 8 | 0x26d0|0xb890|0x10f60|0x129f8|0x15648|0x17b4c|0x1856c|0x1b41c | 0x26d2|0xb892|0x10f62|0x129fa|0x1564a|0x17b4e|0x1856e|0x1b41e | 0x1c38|0xaeb0|0xbb98|0x125c0|0x15210|0x157c8|0x181f4|0x192f4 |
| 1 | 7 | 7 | 0xe0e8|0xf9ac|0x1645c|0x17234|0x19a50|0x1a3fc|0x1ad00 | 0xe0ea|0xf9ae|0x1645e|0x17236|0x19a52|0x1a3fe|0x1ad02 | 0xd4d0|0xed94|0x15d0c|0x16ae4|0x196d8|0x19ff4|0x1a8f8 |

## Geometry raw fields

Geometry 40..42 rows preserve the full encoded span, the raw unsigned size at +2, signed and unsigned count views at +4, and all data halfwords from +6. The native skip is command +4+2*size, following 0x8011CE68 and 0x8011D168..170. The state-operation size at 0x8011CE28 is signed; it is retained separately.

The count word is loaded with lha at 0x8011CE6C. The group-state expression at 0x8011CF2C rotates its sign-extended value and masks it; it is not universally the raw unsigned high two bits. All 65536 u16 patterns were checked against the corresponding unsigned-right-shift expression. Child record skip expressions such as (param_3 >> 14)&3 are distinct. This report does not replace either expression with an inferred intended count.

Raw evidence: commands.csv; local-invocation-spans.csv; command-occurrences.csv; command-halfwords.csv; geometry-40-42-raw-spans.csv; cache-local-sequences.csv; cache-slots.csv; cache-reference-candidates.csv; physical-command-overlaps.csv; original-parser-words.csv; source-digests.csv.

## Decisions and unknowns

- Stop each native local invocation at exact 00FF or a cache definition, preserving that consumed byte span.
- Queue the following pointer of each definition as a separate cached-body entry, rather than treating the definition as fallthrough.
- For references, record the local continuation if the external cache call returns; do not resolve or execute the call.
- Report every same-slot definition/reference pair as a static candidate only, without assuming file order or initial cache state.
- Retain geometry 40..42 headers, sizes, raw count fields and every data halfword; do not name topology or attributes.
- Keep unsigned count high2 separate from the sign-extended original group-state expression.

Unknowns: Runtime cache contents before invocation, initialization, lifetime, mutations and actual caller order.; Whether any static reference is reached and which definition supplies its runtime target.; Geometry topology, attribute/material meanings, scratch contents/capacity and runtime state overrides.; Full inner geometry grammar, grouped-command execution and exact FIFO transcript.; Other files, versions, malformed data and live behavior.

No engine, repository, original carrier, frozen export, analysis database or processor language was modified. No native execution was performed.
