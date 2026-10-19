# Bounded search for real grouped drawing data v1

One run of search_group_samples_v1.py finished the stated scan. Original ISO bytes, every selected PRS identity and protected source digests were checked. This is static asset evidence, not game execution.

Machine result: {"version":1,"result":"bounded_scan_complete","disc_id":"GSNE8P","disc_revision":0,"disc_bytes":1459978240,"disc_sha256":"c8f9db7c936fffed7a5ea12a099c39ad3197208731ebbe4bcdfc3cec9b350638","FST_iso_offset":"0x1fd100","FST_bytes":74203,"FST_sha256":"6118fa4570449fb2414ad4c52847e1c3a70a1de272539f76fc212ead251cb661","FST_file_entries":2819,"candidate_selection":"all FST basenames ending MDL.PRS, case-insensitive; cross-referenced with bounded prior original DOL literal set","limits":{"candidate_files":64,"decoded_bytes_per_file":8388608,"decoded_bytes_total":134217728,"table_entries_per_file":4096,"unique_nodes_per_file":20000,"local_commands_per_entry":10000,"unique_commands_per_file":100000,"first_stream_packets":10000,"collected_streams_host_bound":4},"model_name_literal_offsets":24,"candidate_assets":23,"candidates_with_literal_match":20,"candidate_statuses":{"candidate_scanned_not_runtime_proven":23},"decoded_bytes_total":2462312,"bank_candidate_table_entries":815,"bank_candidate_unique_nodes":2311,"bank_candidate_unique_payloads":1311,"local_stream_entries":923,"local_stream_statuses":{"outer_scan_completed_static_local_path":923},"unique_asset_command_rows":4839,"geometry_commands":1595,"geometry_info_high2":{"0":1595},"nonzero_pending_group_candidates":0,"group_candidate_statuses":{},"groups_collecting_at_least_two_streams":0,"positive_group_asset_paths":[],"scan_errors":0,"scan_error_stages":{},"protected_files_unchanged":69,"recorded_hashes_verified":61,"offset_space":"table/node/payload/command/group offsets are decoded asset file bytes; separate compressed asset ISO offsets identify storage only","native_execution":false,"runtime_cache_or_caller_order_inferred":false,"engine_files_changed":[],"script_runs":"search_group_samples_v1.py once"}

## Search boundary and source

The search selects every original FST basename ending MDL.PRS and cross-references the original DOL model-name literals previously recorded in sonicmdl-loader. SONICMDL.PRS and METALSONICMDL.PRS have original decompiled calls to 0x80050210 in the retained source-reference CSV; matching other names alone does not establish a loader or consumer. No other PRS basename is scanned.

Each selected file is decoded with the verified PRS grammar (0x800D2684), then checked against its prior full-disc PRS validation SHA256, length, consumed bytes and ISO location. A candidate table is read as BE8-byte records until FFFFFFFF. Each reachable self-contained node/payload pointer is separately bounded according to the known 0x80050210 / 0x8002F88C path; the aligned, low-positive, self-contained domain is a conservative scan policy, not a new native guarantee. Unique-node traversal is a structural inventory, not a reproduction of native repeated visit counts.

Drawing local scans use 0x8011CCF8: exact 00FF returns; command04 stores the following pointer and returns; command05 records an unresolved cache call then conditionally resumes at the next halfword. Every following definition pointer is scanned as a separate candidate entry. No cache is implicitly initialized and no same-slot definition is selected as its target.

A positive pending candidate uses the original sign-extended info expression, not merely unsigned high2. Values4000..7FFF produce one additional collected stream; bit15-set expressions exceed this bounded collection domain and are retained separately. Completed groups mean only that the required following geometry commands occur on a validated local stored path. Live global flags and emitter selection are not proved.

## Assets

| FST asset | Final scan status | Decoded bytes | Pending commands |
|---|---|---:|---:|
| amymdl.prs | candidate_scanned_not_runtime_proven | 98020 | 0 |
| bknuckmdl.prs | candidate_scanned_not_runtime_proven | 95892 | 0 |
| brougemdl.prs | candidate_scanned_not_runtime_proven | 91088 | 0 |
| chaos0mdl.prs | candidate_scanned_not_runtime_proven | 117624 | 0 |
| cwalkmdl.prs | candidate_scanned_not_runtime_proven | 83404 | 0 |
| dwalkmdl.prs | candidate_scanned_not_runtime_proven | 73536 | 0 |
| eggmdl.prs | candidate_scanned_not_runtime_proven | 84992 | 0 |
| ewalk1mdl.prs | candidate_scanned_not_runtime_proven | 99568 | 0 |
| ewalk2mdl.prs | candidate_scanned_not_runtime_proven | 97620 | 0 |
| ewalkmdl.prs | candidate_scanned_not_runtime_proven | 118496 | 0 |
| knuckmdl.prs | candidate_scanned_not_runtime_proven | 113600 | 0 |
| metalsonicmdl.prs | candidate_scanned_not_runtime_proven | 72280 | 0 |
| milesmdl.prs | candidate_scanned_not_runtime_proven | 89832 | 0 |
| rougemdl.prs | candidate_scanned_not_runtime_proven | 133824 | 0 |
| shadow1mdl.prs | candidate_scanned_not_runtime_proven | 97444 | 0 |
| sonic1mdl.prs | candidate_scanned_not_runtime_proven | 83276 | 0 |
| sonicmdl.prs | candidate_scanned_not_runtime_proven | 136360 | 0 |
| sshadowmdl.prs | candidate_scanned_not_runtime_proven | 176168 | 0 |
| ssonicmdl.prs | candidate_scanned_not_runtime_proven | 149380 | 0 |
| teriosmdl.prs | candidate_scanned_not_runtime_proven | 154260 | 0 |
| ticalmdl.prs | candidate_scanned_not_runtime_proven | 92044 | 0 |
| twalk1mdl.prs | candidate_scanned_not_runtime_proven | 97456 | 0 |
| twalkmdl.prs | candidate_scanned_not_runtime_proven | 106148 | 0 |

Raw output includes all candidate identities, table records, linked nodes, both payload pointer words, local stream boundaries, command bytes, group candidates, collected stream bytes, exact errors and source digests. samples/ preserves every selected compressed and decoded carrier. Asset ISO offsets refer to compressed storage; internal offsets remain decoded-file offsets.

Unknowns: Whether candidate assets are reached, which native caller/consumer is selected and the live parser/global state.; Actual runtime cache initialization, bindings, mutation and caller order; local continuation after a reference is conditional on its call returning.; Topology, attributes, complete inner multi-stream layout, pointer-array capacities/aliases, transforms and FIFO behavior.; PRS files outside the explicit MDL.PRS basename boundary, other regions/revisions and malformed native behavior.

No engine, repository, original carrier, frozen export, analysis database or processor language was modified. No native game or engine execution occurred.
