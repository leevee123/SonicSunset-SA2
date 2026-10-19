# Sonic bank raw layout inventory v1

One run of inventory_bank_v1.py passed. The original decoded sonicmdl.prs and existing table/node/payload CSV values matched byte for byte. This is a file inventory, without a geometry or gameplay claim.

All offsets below and in the CSVs are decoded-file offsets. The compressed file and ISO use different offset spaces.

Machine result: {"decoded_bytes":136360,"decoded_sha256":"b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963","protected_files":60,"recorded_hashes_verified":52,"all_protected_files_unchanged":true,"table_entries":64,"unique_nodes":200,"recursive_visits_crosschecked":688,"node_candidate_field_rows":2000,"unique_payload_headers":115,"payload_pointer_word_rows":230,"payload_zero_words":66,"unique_nonzero_payload_inner_targets":164,"shared_target_offsets_all_roles":44,"shared_payload_header_offsets":0,"shared_inner_target_offsets":0,"minimum_footprint_overlap_pairs":0,"inner_targets_inside_proven_minimum_footprints":0,"candidate_span_shorter_than_minimum_rows":0}

The prior loader evidence is 0x80050210 and linked-pointer converter 0x8002F88C; this task uses immutable exported source hashes rather than opening an analysis project.

## Candidate node field interpretations

These are raw bit interpretations, not established meanings. A finite float pattern does not prove that a field is a float.

| Node field | Unique raw words | Unsigned range | Finite f32 candidate range | f32 candidate classes |
|---|---:|---|---|---|
| 0x0 | 13 | 4..30 | 5.605193857299268e-45..4.203895392974451e-44 | {"finite_nonzero": 200} |
| 0x8 | 49 | 0..3201458455 | -0.41089698672294617..2.7580230236053467 | {"finite_nonzero": 122, "negative_zero": 31, "positive_zero": 47} |
| 0xc | 35 | 0..3218930114 | -1.7263720035552979..5.244298934936523 | {"finite_nonzero": 56, "negative_zero": 65, "positive_zero": 79} |
| 0x10 | 29 | 0..3209856324 | -0.8223459720611572..0.8223459720611572 | {"finite_nonzero": 39, "negative_zero": 57, "positive_zero": 104} |
| 0x14 | 28 | 0..4294967208 | 0.0..4.704158944738411e-42 | {"finite_nonzero": 17, "nan": 15, "positive_zero": 168} |
| 0x18 | 31 | 0..4294966694 | 0.0..5.1749952287515494e-42 | {"finite_nonzero": 18, "nan": 16, "positive_zero": 166} |
| 0x1c | 66 | 0..4294967044 | 0.0..4.636476228911522e-41 | {"finite_nonzero": 37, "nan": 43, "positive_zero": 120} |
| 0x20 | 1 | 1065353216..1065353216 | 1.0..1.0 | {"finite_nonzero": 200} |
| 0x24 | 1 | 1065353216..1065353216 | 1.0..1.0 | {"finite_nonzero": 200} |
| 0x28 | 1 | 1065353216..1065353216 | 1.0..1.0 | {"finite_nonzero": 200} |

## Spans, aliases and overlap

The 115 payload-header rows retain their first eight bytes, both raw pointer words and every byte up to the next known start. Candidate payload partitions range from 24 to 24 bytes. The 164 unique nonzero inner targets retain their first raw word and full candidate spans, ranging from 4 to 12228 bytes.

Next-known-offset spans partition the known address set. They are inspection bounds and cannot establish native record sizes or prove that pointed resources are disjoint. Physical overlap is checked separately only among the loader-proven minimum footprints; raw pointer aliases are checked separately by their incoming word sites.

Raw evidence: table-entries.csv; nodes.csv; node-field-values.csv; node-field-aggregates.csv; node-field-bits-histogram.csv; payload-spans.csv; inner-target-spans.csv; pointer-words.csv; shared-pointers.csv; minimum-footprint-overlaps.csv; inner-target-minimum-containment.csv; known-offset-partitions.csv; candidate-span-shorter-than-minimum.csv; source-digests.csv. decoded-bank.bin is an exact copy of the protected input.

## Decisions and unknowns

- Use original bytes, never the synthetic relocated view.
- Report BE u32 and f32 interpretations without field names or geometry guesses.
- Use next distinct known start or file end only as a candidate partition boundary; it is not a declared record length.
- Minimum footprints are table entries 8 bytes, sentinel word 4 bytes, nodes 0x34 bytes and payload headers 8 bytes, exactly the prior loader evidence.
- Raw next-boundary spans and an exact decoded-bank copy preserve bytes for consumer tracing.

Unknowns: Meanings of node +00/+08..+28 fields.; Full node and payload structures and their declared lengths.; Meaning of inner pointed data and its first raw word.; Native consumers, drawing, transforms, geometry, animation, ownership and live allocation address.; Runtime execution and gameplay behavior..

No engine, repository, frozen exporter or project files changed. No native execution was performed.
