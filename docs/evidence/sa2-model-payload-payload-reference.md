# Original Sonic payload consumers and first-stream packet grammar

The original draw path consumes each node+4 target as a payload containing two pointers. Pointer+0 supplies record packets; pointer+4 supplies drawing/state/cache commands. The **first-stream integer grammar and all real Sonic packet spans are established**. Numerical skinning, material semantics and a complete renderer are not established. No retail runtime execution was observed.

## Original code coordinates

|Original VA|DOL offset|ISO offset|Observed role|
|---|---|---|---|
|0x80089f48|0x86f48|0xa5648|Copies node and24-byte payload; count-derived stream copy|
|0x8008a230|0x87230|0xa5930|Consumes and transforms copied stream records|
|0x8008a718|0x87718|0xa5e18|Submits copied node|
|0x8011e17c|0x11b17c|0x13987c|Wrapper into shared node path|
|0x8011d554|0x11a554|0x138c54|Selects payload callback|
|0x8011dfc0|0x11afc0|0x1396c0|Node walker passes node+4 to callback|
|0x8011d484|0x11a484|0x138b84|Payload gate/culling callback|
|0x8011d414|0x11a414|0x138b14|Dispatches payload+0 and+4 streams|
|0x8011d1d4|0x11a1d4|0x1388d4|First-stream integer packet grammar|
|0x8011daf0|0x11aaf0|0x1391f0|Opcode29 record consumer|
|0x8011dc98|0x11ac98|0x139398|Opcode2C indexed weighted consumer|
|0x8011da30|0x11aa30|0x139130|Opcode23 record consumer|
|0x8011ccf8|0x119cf8|0x1383f8|Second-stream draw/state/cache parser|
|0x80101948|0xfe948|0x11d048|Writes primitive command byte and vertex count|
|0x8011d690|0x11a690|0x138d90|Writes three scalar floats to FIFO|
|0x8011d8e4|0x11a8e4|0x138fe4|Writes two halfwords to FIFO|

All36 selected functions,105 source artifacts and432 outgoing edge rows remain in complete source/call CSV. Original inspection verified2,427 exported ASM rows covering1,428 unique original addresses against main.dol and the ISO DOL at1E700. C was read before instruction evidence; generated signatures, FP expansions and FIFO stores were not treated as equivalent original behavior.

## Proven bridge from the real bank

80089F48 reads the registry-backed node pointer, copies38 hexadecimal bytes into an allocated node, copies its node+4 target into a separately allocated18 hexadecimal-byte payload, then derives a source-stream copy size from the second32-bit word atpayload+0. The copied node is submitted by8008A718 through8011E17C. 8011D554 supplies8011D484 as the callback to8011DFC0; that walker invokes the callback with node+4. 8011D484 can gate through8012192C; on its accepted path8011D414 passes nonzero payload+0 to8011D1D4 and nonzero payload+4 to8011CCF8, using the same recorded scratch-buffer argument. Node transform recursion remains a separate audit; this is a static pointer-consumption path, not proof that every bank node is drawn.

Real registry ID20 has decoded node offset1C7F0 and payload offset1C7D8. Its first stream is1C70C, first header00310023 and information word000C0000:12 opcode23 records starting atscratch index0. Original copy arithmetic produces204 bytes/51 words, covering8 header bytes,192 record bytes and4 EOS bytes. Its second stream is1C6A0. Source copies and update loops also access payload float words+8,+C,+10,+14; their complete rendering/shape interpretation remains outside this grammar.

## First-stream layout and exact pointer movement

All fields below are big-endian32-bit words, as consumed by original `lwz` instructions.

|Location|Original handling|
|---|---|
|Packet+0|Preserve the full word. Opcode=word&FF. If opcode==FF, return before reading the information word.|
|Packet+4|High16 bits give the record count; low16 give the starting scratch index.|
|Packet+8|Beginning of record bytes passed to the selected handler.|
|Header high16|Encoded count of4-byte units used by the main scanner; it is not the record count.|
|Next packet|`dataStart +4*((header>>16)-1)`, equivalently`packetStart +4*((header>>16)+1)` under original32-bit arithmetic.|
|Scratch start|Scratch argument plus `(informationWord &FFFF)*20hex`. Scratch capacity/lifetime is not established here.|

The dispatcher recognizes opcodes29,2C,2A,23; other non-FF opcodes have no selected handler and still follow the encoded skip. Opcode2A's record layout and other unused opcodes remain unvalidated. The scanner has no demonstrated bounds/EOS-capacity guard. In particular, an encoded high16 value0 moves to packet+4 after reading the information word; it must not silently be reinterpreted as an ordinary8-byte packet. Host validation policy for such unvalidated inputs is separate from original behavior.

|Sample opcode|Original handler|Bytes/record proven on this sample|Stored fields|
|---|---|---|---|
|29|8011DAF0|24|Six32-bit scalar slots loaded through GQR0 paired-single operations.|
|2C|8011DC98|28|Six32-bit scalar slots; signed16-bit field at+24 decimal; unsigned16-bit destination index at+26 decimal. Destination index is shifted left5 and added to the starting scratch pointer.|
|23|8011DA30|16|Three32-bit scalar slots plus packed32-bit word at+12 decimal. The original handler rotates the packed word left8.|

The scalar slots contain finite big-endian float values in this sample. Their exact paired-single interpretation depends on runtimeGQR0; numerical output equivalence, FPSCR controls and exact fused operations were not validated. The28-byte opcode2C stride is established by original source-pointer increments: input loads at0,8,16, then weight at24, destination index at26, then next record at28. A32-byte stride would be incorrect for these real records.

Opcode2C receives a variant extracted as `(header &7FFF)>>8`; native instructions first clear bit15 and then rotate/extract that byte. Its original handler distinguishes zero from nonzero variants when writing versus combining scratch values. The sample has38 zero-variant packets,2 variant1 packets and43 variant2 packets. No CPU skinning implementation or further variant naming is inferred from generated C.

## Exact original mask evidence

|VA|DOL offset|ISO offset|Original word|Role|
|---|---|---|---|---|
|0x8011d200|0x11a200|0x138900|0x5465043e|Header low16 extraction|
|0x8011d204|0x11a204|0x138904|0x5460001e|Header high16 mask|
|0x8011d208|0x11a208|0x138908|0x541d843e|Header high16 right extraction|
|0x8011d214|0x11a214|0x138914|0x54a5045e|Clear header bit15 before variant extraction|
|0x8011d218|0x11a218|0x138918|0x5460001e|Information word high16 mask|
|0x8011d21c|0x11a21c|0x13891c|0x5400843e|Information word high16 count extraction|
|0x8011d228|0x11a228|0x138928|0x5460043e|Information word low16 start extraction|
|0x8011d22c|0x11a22c|0x13892c|0x54002834|Start index times32|
|0x8011d264|0x11a264|0x138964|0x54a5c63e|Opcode2C high-byte variant extraction after bit15 clear|
|0x8011d2b4|0x11a2b4|0x1389b4|0x381dffff|Encoded header length minus1|
|0x8011d2b8|0x11a2b8|0x1389b8|0x5400103a|Length units times4|
|0x8011d2c8|0x11a2c8|0x1389c8|0x5460063e|Low-byte opcode/EOS extraction|
|0x8011d2cc|0x11a2cc|0x1389cc|0x280000ff|Compare opcode withFF|

All72 original words of8011D1D4 are retained in `first-stream-original-mask-words.csv`. The project-free bounded integer field selector was checked against135 existing Gekko rotate/mask instructions and267 existing word loads; unsupported instruction encodings remain explicitly undecoded rather than invented. The parser's complete C and direct call edges remain source evidence alongside those raw words.

## Real Sonic validation

One run of`validate_first_stream_v1.py` passed. Actual ISO data at479024A4 matches the protected102331-byte PRS file. The decoded136360-byte SHA-256 is`b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963`, matching the prior original PRS validation. Decoded offsets have no one-to-one compressed ISO coordinates.

The115 payloads contain100 nonzero first-stream pointers, all distinct, and15 zero pointers. The100 streams contain154 nonterminal packets and100 EOS words. Every sample data span equals8+count*recordStride:

|Opcode|Packets|Records|Bytes/record|
|---|---:|---:|---:|
|29|69|2273|24|
|2C|83|830|28|
|23|2|64|16|

There are3167 records total. Their possible scratch destinations cover509 distinct indices0..508 across the whole sample; this union does not prove per-draw initialization or capacity. Opcode2C's stored signed weight words range0..255. Complete raw header words, packet/record offsets, sizes, raw bytes, EOS positions, destination fields and opaque flags remain in CSV. No normalized weights or transformed/drawn results were produced.

## Original GQR1 and installed language caveat

8011DC98 writes **GQR1=08070807** using original words **38000807 at8011DCA4**, **64000807 at8011DCA8** and **7C11E3A6 at8011DCAC**. Complete DOL/ISO offsets are in `GQR1-original-setup-words.csv`. The original weight load at8011DD1C uses GQR1 with W1. The pinned primary Dolphin CPU definitions identify load type7 as signed16 and the scale field as6 bits; this original register value supplies load scale8, nominally2^-8. Exact transformed-vector results are not claimed.

The installed GameCubeLoader source **C:\decomp\sonic-adventure-gc\ghidra_12.1.4_PUBLIC\Extensions\Ghidra\GameCubeLoader\data\languages\ppc_gekko_broadway.slaspec**, also copied unchanged into the isolated language module, has SHA-256 **32ce4852d6243f5eea19cda1eb8cf0b2af8fb93532dcd9a585ee927a32c8eb75**. At line **1171**, its `load_ps` macro assigns `ls[0,3] = I[24,6];`: a6-bit scale is assigned to a3-bit target. Scale8 cannot be retained; its low3 bits are0. The frozen compiled SLA SHA-256 is **aa25bde9ffb8f6366e1e490c6a488b1aced4665dc6c4f2fdca9cc598d5530975**. Therefore its generated C is unsuitable evidence for exact weight scaling or weighted FP behavior. This is a source/decoding limitation, not an original game quirk. Installed source, isolated module, SLA and frozen exports were left unchanged.

## Bounded second-stream findings and remaining work

8011CCF8 reads16-bit command headers. Its EOS check is the exact halfword00FF. It recognizes single-halfword controls, two-halfword operations for low-byte8..F, size-prefixed operations10..3F and geometry operations at40..42. Command4 stores the following stream pointer in a cache indexed by the header high byte and returns; command5 invokes a cached pointer. The sample's initial scans reached34 explicit EOS sites and30 cache/control stops, including15 definitions and15 references. Those stops are preserved, not misreported as completed render parsing.

The basic geometry readers issue native command98 and emit counts, three-float attributes and, for the textured forms, two signed halfwords. Original80101948 writes a command byte and then a halfword count toCC008000; several scalar emitters write three floats to that same address, and8011D8E4 writes two halfwords. Generated C retains only the last overlapping FIFO write, so it is not a complete draw transcript. Exact material meanings, primitive topology attribution, cache initialization/redefinition order, multi-stream batching, index/attribute interpretation and full second-stream consumption remain future evidence work. External reference lookups for topology/CPU implementation returned cache misses; no facts were inferred from those failed lookups.

This pass intentionally supplies a reviewable **CPU first-stream packet reader contract**: preserve headers, encoded spans, offsets, raw records, EOS and unknowns. It supplies no skinning, drawing, native calls or engine changes. It does not establish a complete named model format or gameplay. No leaked original source was encountered or used. No Ghidra project, native game runtime, installed/frozen source, repository or engine file was opened for mutation or changed.

Complete evidence: `consumer-source-verified.csv`, `consumer-original-words.csv`, `consumer-calls-verified.csv`, `sample-payload-headers.csv`, `sample-stream0-commands.csv`, `sample-stream4-commands.csv`, `first-stream-mask-reference.csv`, `first-stream-original-mask-words.csv`, `first-stream-sample-streams.csv`, `first-stream-sample-packets.csv`, `first-stream-sample-records.csv`, `GQR1-original-setup-words.csv`, `quantization-reference-source-lines.csv`, `slot20-real-payload.csv`, `FIFO-emitter-original-words.csv`, `input-artifacts.csv` and paired validation/inspection reports. Python versions were run once each; undefined source read probes were not converted into invented functions.
