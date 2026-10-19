# Real sonicmdl sample validation

One run of validate_sample_v1.py passed. Original ISO FST/file/DOL bytes, PRS decoding, immutable C/ASM hashes and original words matched. The exact loader relocation order was simulated on the real decoded bytes with synthetic base81000000 and initially empty registry; this was not retail execution.

- result: passed
- sample: {'fst_index': 2428, 'path': 'sonicmdl.prs', 'entry_iso_offset': '0x2042d0', 'name_iso_offset': '0x20dc97', 'disc_offset': '0x479024a4', 'stored_bytes': 102331}
- compressed_sha256: d8f90e6c724e709b8d3431e725a5db1d1a096bdf5118d2ecca9ad356e7862d99
- decoded_bytes: 136360
- decoded_sha256: b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963
- prs_consumed: 102331
- padding_read_bytes: 5
- sector_reservation_bytes: 102400
- compressed_scratch_address: 0x811e6e60
- copy_round4_bytes: 136360
- DOL_iso_offset: 0x1e700
- request_literal: SONICMDL.PRS
- request_literal_va: 0x8017494c
- request_literal_dol_offset: 0x17194c
- request_literal_iso_offset: 0x19004c
- name_compare_table_va: 0x801764b8
- name_compare_matches_real_FST: True
- source_artifacts: 42
- export_ASM_rows_verified: 863
- independent_original_words_verified: 195
- table_entries: 64
- sentinel_offset: 0x200
- sentinel_first_word: 0xffffffff
- sentinel_following_word_unread: 0x0
- eligible_ids: 64
- duplicate_ids: {}
- relative_root_words: 64
- zero_root_words: 0
- absolute_root_words: 0
- unique_linked_nodes: 200
- recursive_visits: 688
- opaque_two_word_payloads: 115
- relocation_stores: 529
- synthetic_base: 0x81000000
- synthetic_post_relocation_sha256: 7d67b1ed6d86009780b34cd52bd767f57fca364126711e62331fa0165914a90c
- runtime_execution_observed: False

Unknowns: Actual allocation address/callback implementation and registry prior contents; Opaque payload structures beyond its two adjusted words; Node fields other than+4,+2C,+30 and true structure boundaries; Geometry/drawing/animation semantics; Indirect loader callers and successful runtime I/O.
