# Original model bootstrap and upload audit v1

One run each of prepare_bootstrap_v1.py and audit_bootstrap_v1.py passed. The existing project-free DumpSonicLoader parsed four added scopes; no Program or project was opened. Full C was checked first and exact original words establish store/call order where generated C loses repeated MMIO writes or paired-lane details.

Machine result: {"version":1,"result":"passed_bounded_original_audit","original_instruction_rows_verified":742,"distinct_original_VAs":742,"selected_scopes":19,"setup_direct_calls":11,"setup_state_word_stores":3,"copy_memory_instructions":32,"conditional_binary32_upload_components":{"0x801057c4":12,"0x801057f8":9,"0x8010582c":8},"synthetic_integer_wrapper_cases":54,"synthetic_wrapper_events":162,"matrix_permuted_components":12,"matrix_source_component_order":[0,4,8,1,5,9,2,6,10,3,7,11],"protected_files_unchanged":87,"recorded_hashes_verified":82,"native_game_execution":false,"project_or_ProgramDB_opens":0,"GQR0_or_FPSCR_runtime_value_proved":false,"matrix_source_ownership_or_initialization_proved":false,"engine_files_changed":[],"scripts":["prepare_bootstrap_v1.py once","audit_bootstrap_v1.py once"]}

## Verified setup order

8011D2F4: three D44 calls with raw arguments,2EF8(1), state writes0/FFFFFFFF/0,5850(source80357880,index0),588C(same,index0),then optional path if live SDA-71D8 bit00100000 clear; optional ED7CC/ED798/ED368 twice/5908(stack08,2A,0),fresh state reload OR00100000.

The three state writes are not three zero clears: the middle value is FFFFFFFF. The optional-path gate and final OR use separate original loads of live r13-71D8; no stale entry-state value is substituted. The stack frame base is post-prologue SP, with blocks at+68,+38,+08. The second ED368 call has output equal its second input. ED368 arithmetic is not reconstructed here.

## Upload instruction sequences

Each5850/588C/5908 writes byte10 then32-bit control toCC008000 BEFORE copy helper source loads.5850=((index<<2)mod32)|B0000→57C4.588C=(3*index+400 mod32)|80000→57F8.5908 address=index<40?index*4:(index-40)*4+500 mod32,OR ((mode==1?7:B)<<16);mode0→57C4,allnonzero→582C. No GPU names inferred.

57C4 loads six GQR0 pairs offsets00/08/10/18/20/28 then stores six pairs repeatedly at destination+0.57F8 loads pairs00/10/20 and scalars08/18/28 then alternating pair/scalar stores at destination+0.582C loads four pairs00/08/10/18 then four stores at destination+0. All loads precede first store.

For ordinary GQR0 load/store type0 binary32 layout, the source component orders are12 sequential words for57C4; offsets00,04,08,10,14,18,20,24,28 for57F8;8 sequential words for582C. A paired store has two lanes at adjacent format-dependent byte locations, and repeated stores use the same destination base. No PSQ packet length or float values are asserted for other live quantization formats. Mode values other than0/1 retain the original5908 mismatch between its B<<16 control field and8-component helper; the audit does not normalize that behavior.

At the setup call sites, index0 gives controls000B0000 and00080400. The conditional5908 index2A/mode0 call gives000B00A8. These are byte10 followed by the corresponding BE32 control, then the original helper payload operations. The integer model checked boundary/wrap indices and mode values without executing MMIO or floating instructions.

## Current pointer and lane conversion

Absolute803AE0C4 pointer read,advanced+30 and stored BEFORE source loads,then shared blockC140 loads six GQR0 pairs/reorders lanes/stores six pairs at old+30. Binary32-layout lane-source order0,4,8,1,5,9,2,6,10,3,7,11. This is lane provenance,not unqualified raw-bit/numeric/runtime equivalence.

The shared copy block8011C140..188 precedes the named entry8011C18C and is included in its frozen recorded body. The pointer update at8011C19C precedes the branch8011C1A0, so source initialization cannot be inferred from that update. All source pair loads precede the first destination pair store. Lane provenance is exact at the instruction level; binary32 byte offsets and matrix-shaped interpretations require an explicit GQR0 contract. Source storage ownership/init remains unknown.

Complete raw CSVs retain VA/DOL/ISO locations, all742 instruction rows, source constants, setup calls/stores, copy events, conditional upload component order, integer wrapper cases/events, pointer memory order and lane permutation. source-digests.csv preserves unchanged input hashes.

Unknowns: Actual GQR0 load/store format and scales, FPSCR/NI/NaN behavior and exact numeric results; other agents audit those scopes.; Initialization, ownership, capacity and lifetime of80357880 data and803AE0C4 pointed storage.; Live r2/r13 context; SDA labels/constants here use documented startup-base assumptions.; Caller closure, mode meanings, GPU interpretation, topology, transforms and successful retail execution.; C18C pointer/data aliasing can alter unread source when global pointer word aliases source; no nonalias assumption is elevated to native guarantee.

No engine/repository/original/frozen/database/language changes. No native game or engine execution. No leaked original source encountered.
