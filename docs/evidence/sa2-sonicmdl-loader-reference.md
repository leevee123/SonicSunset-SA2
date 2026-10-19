# Original sonicmdl.prs loader and bounded container layout

The original game requests **SONICMDL.PRS**, decompresses it, then scans an **8-byte ID/pointer table ending with signed ID-1**. The actual file has64 entries and a sentinel atdecoded offset200. Original pointer adjustment reaches200 distinct linked nodes and115 opaque two-word payloads. This establishes a bounded container layout; it does not establish geometry, drawing, animation or complete character behavior.

## Original code and stored sample

|Original function VA|DOL file offset|ISO offset|Observed role|
|---|---|---|---|
|0x800874c0|0x844c0|0xa2bc0|Filename selection and returned blob storage|
|0x80050210|0x4d210|0x6b910|Sentinel table scan, registration and root traversal|
|0x8001a190|0x17190|0x35890|File-size/read/PRS/callback/copy pipeline|
|0x8002f88c|0x2c88c|0x4af8c|Linked-node and opaque payload pointer adjustment|
|0x8001acac|0x17cac|0x363ac|File read wrapper|
|0x800d2684|0xcf684|0xedd84|Verified PRS decoder|
|0x801197d0|0x1167d0|0x134ed0|Dynamic size callback preserving r3 input/output|
|0x800eecfc|0xebcfc|0x10a3fc|FST pathname lookup|
|0x8010ba44|0x108a44|0x127144|Byte comparison mapping|

All17 selected functions, both generated views and complete outgoing graphs are recorded in `loader-source-verified.csv` and `loader-calls-verified.csv`. The real ISO DOL bytes at1E700 exactly match the protected main.dol. The model asset is FST entry2428, FST-entry ISO2042D0, filename ISO20DC97, stored data ISO479024A4, size102331 bytes. PRS consumes all102331 bytes and yields136360 bytes, SHA-256`b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963`. The compressed SHA-256 is`d8f90e6c724e709b8d3431e725a5db1d1a096bdf5118d2ecca9ad356e7862d99`.

Offsets inside the decoded asset are **decoded file offsets**. PRS compression prevents assigning them one-to-one ISO offsets. Synthetic addresses in the relocation experiment are separately labeled and are not observed retail addresses.

## Filename and read path

800874C0 passes the literal **SONICMDL.PRS at8017494C /DOL17194C /ISO19004C** to80050210 at **800875f8 /DOL0x845f8 /ISO0xa2cf8** and stores the returned pointer atits allocated block+398. That branch is selected when byte801CC186 iszero, or the byte indexed by incoming argument at801CC1BB iszero. A different branch choosesSONIC1MDL.PRS when the indexed byte equals1; the alternate payload was not validated here. An earlier conditional can divert to800871C4 before this path. These are static conditions, not observed selection or gameplay meanings.

80050210's prologue preserves incomingr3 through its call to8001A190 at80050228/DOL4D228. Its generated void signature and omitted filename argument are inaccurate ABI summaries. 8001A190 saves the name, opens through80119D64, gets the byte length through80119EC4 and closes through80119E6C. It computes compressed scratch space as811FFE60 minus `((size+7FF) arithmetic-shift-right11)<<11`, calls8001ACAC with the saved name and scratch pointer, and on nonnegative wrapper status calls800D2684 todecode into80FFFE60. Decoded length is passed inr3 to801197D0; its dynamic callback receives that size and returnsr3 without the helper overwriting it. Callback implementation and actual allocation address remain unknown.

If the returned pointer is nonzero,80119730 copies `(decodedLength>>2)+[low2bits!=0]` words from80FFFE60 into it and8001A190 returns that pointer. Its observed failure paths return0 when opening/size discovery, the read-wrapper result or the size callback fails. The original read wrapper8001ACAC has a quirk: after a successful open it calls80119EF0 and closes, then returns0 without propagating the read helper's status. No runtime I/O success is implied by a static nonnegative wrapper result.

For the real sample, reserved scratch space is102400 bytes and the source address is811E6E60. The lower read helper80119EF0 rounds the last request to32 bytes, yielding102336 bytes, including5 bytes beyond the stored file length; PRS stops atits end marker after102331 bytes. The final copy uses136360 bytes, with no extra word padding for this sample. Allocation padding/capacity policy for other sizes was not established.

The cached-read substring tests in8001ACAC use original`cam.prs`,`.bin`,`.BIN`,`.BMP`,`.bmp`; none matchesSONICMDL.PRS. Its visible file path therefore uses the FST wrapper. 800EEFF0 resolves paths through800EECFC, which compares each filename byte after8010BA44's original byte-table mapping at801764B8. That actual mapping makesSONICMDL.PRS equal to the FST's lowercase sonicmdl.prs. This validates the case spelling relationship from original code/data rather than assuming it.

## Fields established by the loader

|Location|Stored type/size|Original handling|
|---|---|---|
|Entry+0|Big-endian signed32-bit ID|ExactlyFFFFFFFF ends the scan before+4 is read. Other values advance by8. IDs0..213 are eligible for registration.|
|Entry+4|Big-endian32-bit root pointer word|Zero remains zero. Nonzero with bit31 clear has the decoded-buffer base added in place. Bit31 set is kept. Every nonzero root is then traversed, even when its ID is outside the registration range.|
|Node+4|Big-endian32-bit pointer word|For a nonzero word with bit31 clear, add base and then adjust the target's first two nonzero words. Already-highbit words skip that inner step.|
|Target of node+4,+0 and+4|Two big-endian32-bit words|If nonzero, add base **without an inner bit31 test**, but only during the node+4 conversion step. Their detailed payload meaning remains unknown.|
|Node+2C|Big-endian32-bit link A|Convert a nonzero low-bit31 word by adding base, then recursively process this link first.|
|Node+30|Big-endian32-bit link B|Apply the same rule and process it second.|

The node helper8002F88C reads all three node pointer words before altering them. Its accesses require at least34 hexadecimal bytes (52 bytes) at each node; that is a demonstrated minimum span, not proof of the complete original structure size. Fields+0,+8..+28 and opaque payload data beyond its first8 bytes are retained in raw evidence and remain unnamed. No GNO, Ninja, geometry, transform, vertex or hierarchy semantics were assigned from familiarity.

80050210 calculates a registry slot as801E6688+ID*8 and uses only its **word+4**. It installs the converted entry pointer only when0<=ID<214 and that existing slot word iszero. The slot's other word and prior contents are not defined by this loader. Registration conditions do not suppress nonzero-root traversal. There is no demonstrated count/header, magic signature, bounds check, alignment rule, cycle guard or requirement that the sentinel's following word bezero. The sample happens to containzero after its sentinel; the loader does not read that word as part of termination.

## Real sample validation

One run of`validate_sample_v1.py` passed against real ISO/FST/file bytes and the original DOL. It verified42 immutable source artifacts,863 exported ASM rows and195 independently parsed original words. Both views' immediate branch targets matched the original encodings. Complete source/function/call and ISO offsets are retained in CSV.

The real decoded sample has64 distinct IDs, all eligible; all64 root words are relative and nonzero. Its first entries are ID1/root10F2C, ID2/rootCF68 and ID3/root9468. The sentinel isFFFFFFFF at200, so there is no count word atoffset0. Traversal reaches200 distinct nodes and115 opaque targets. An exact-order simulation using **synthetic base81000000 and initially empty registry** made688 recursive visits and529 pointer stores, with no cycles or bounds failures. Repeated nodes are revisited in the original order rather than globally pruned. The simulated resulting blob SHA-256 is`7d67b1ed6d86009780b34cd52bd767f57fca364126711e62331fa0165914a90c`. This is a host experiment over the real bytes, not execution of retail code.

## Decisions and unknowns

The conservative decision is to expose only the sentinel records, original pointer rules and minimum opaque/node spans. Other fields retain their raw bytes. Actual heap address/callback, prior registry state, resource ownership/freeing, complete payload structures, geometry/GPU/drawing, animation, caller closure, malformed-file behavior beyond unchecked original reads and successful runtime loading remain unknown. Other model filename literals and the separateMETALSONICMDL.PRS request observed at80086BA4 are preserved in the discovery CSV; their payloads were not validated.

No Ghidra project was opened, no frozen helper or installed configuration changed, and no engine/repository files were edited. No leaked original source was encountered or used. Python versions were run once each; the first source-selection version incorrectly parsed the catalog's display-formatted bare hexadecimal body ranges asJSON. It remains preserved; version2 used the authoritative range CSV.

Complete evidence: `sample-fst.csv`, `loader-source-verified.csv`, `loader-calls-verified.csv`, `export-original-words-verified.csv`, `loader-original-words-verified.csv`, `sample-table-entries.csv`, `sample-linked-nodes.csv`, `sample-opaque-payloads.csv`, `sample-relocation-stores.csv`, `original-cache-substrings.csv`, `input-artifacts.csv`, `sample-validation.md` and itsAI twin. They preserve raw words/bytes, source paths/hashes and all available original VA/DOL/ISO coordinates.
