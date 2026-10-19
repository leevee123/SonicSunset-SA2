# Real Sonic inner geometry inventory v1

One run of inventory_geometry_v1.py passed for all 73 basic candidate layouts. This validates a raw file decomposition against the frozen native readers, without establishing the actual runtime consumer branch or topology.

Machine result: {"version":1,"result":"passed_candidate_basic_layouts","decoded_bytes":136360,"decoded_sha256":"b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963","geometry_commands":73,"opcodes":{"0x41":66,"0x40":7},"commands_with_nonzero_info_high2":0,"signed_run_records":952,"negative_signed_run_counts":277,"positive_signed_run_counts":675,"zero_signed_run_counts":0,"signed_run_count_min":-60,"signed_run_count_max":42,"corner_records":6561,"corners_by_opcode":{"0x41":6371,"0x40":190},"index_raw_min":0,"index_raw_max":508,"negative_signed_indices":0,"unique_raw_indices":509,"extra_halfword_rows":12742,"extra_halfword_signed_min":-1,"extra_halfword_signed_max":256,"declared_geometry_data_bytes":40582,"candidate_consumed_data_bytes":40510,"unconsumed_tail_bytes":72,"unconsumed_tail_lengths":{"0":37,"2":36},"unconsumed_tail_raw_patterns":{"":37,"0000":36},"selected_reader_functions":6,"original_reader_instruction_words":378,"protected_files_unchanged":129,"recorded_hashes_verified":127,"offset_space":"decoded sonicmdl.prs; original reader words have separate DOL offsets","native_execution":false,"engine_execution":false,"runtime_path_selected":false,"topology_or_normalized_extra_field_meaning_inferred":false,"engine_files_changed":[],"script_runs":"inventory_geometry_v1.py once"}

## Source and context

C was read first. 0x8011D594 / DOL 0x11A594, 0x8011D6A4 / DOL 0x11A6A4 and 0x8011FEF4 / DOL 0x11CEF4 read each signed run count, use its magnitude and advance corner records by 1+((info>>14)&3) halfwords. 0x8011D7B4 / DOL 0x11A7B4 advances by three halfwords; 0x8011D91C / DOL 0x11A91C and 0x8011FFF4 / DOL 0x11CFF4 use 3+((info>>14)&3). Each uses info&0x3FFF as its run counter and signed first-halfword index times 0x20. Raw words for all six recorded function bodies were extracted from the original DOL and the lower14 rotate-mask instruction was checked in each body. Exact C features and original addresses are retained in CSV.

All real sample info high bits are zero. Consequently these observed candidate strides agree across their listed fallbacks. Applying the isolated reader directly to each raw command is an explicit validation context; pending groups, global header overrides and actual consumer selection remain unknown.

The native loops are do-while. This validator does not coerce zero run or zero corner counts into empty lists; the real sample contains neither. Negative signed run counts are preserved alongside magnitude; no topology or winding interpretation is assigned to their sign.

## Raw output

geometry-packets.csv retains complete command/data bytes, encoded bounds, candidate consumed bounds and every unconsumed tail byte. geometry-runs.csv retains signed/raw count words and exact spans. geometry-corners.csv retains each first index as raw u16 and signed16, the signed scaled-address candidate, and all extra raw halfwords. geometry-extra-halfwords.csv expands those extras with exact file offsets. geometry-oracle.ai.json nests the same packets/runs/corners for an independent implementation to compare. reader-source-features.csv, reader-original-words.csv and source-digests.csv preserve provenance.

The term corner identifies a record position within this candidate layout. It does not establish a triangle, strip, vertex identity, UV interpretation or native scratch bounds.

Unknowns: Actual runtime parser pending-group state, header overrides, consumer branch and cache/caller ordering.; Topology, winding, normalized attribute meanings and any relation between signed run count sign and rendering output.; Meaning of remaining tail bytes; they are preserved as unconsumed bytes under the basic candidate layout.; Scratch availability/initialization, complete vertex data, numeric transforms and FIFO transcript.; Opcode42 and nonzero info-high2 inner layouts have source observations but no real sample validation here.

No engine, repository, original carrier, frozen export, analysis database or processor language was modified. No native or engine execution occurred.
