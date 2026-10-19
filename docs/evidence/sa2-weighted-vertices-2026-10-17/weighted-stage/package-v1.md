# Weighted vertex check package v1

PASS. Double-click `outputs/SA2-Weighted-Vertex-Check/Check-SA2-Weighted-Vertices.cmd` to repeat the check. Its one package validation passed all 314 weighted packet cases, 309 complete stream cases and eight batches covering all 65,536 signed 16-bit weights. The 631 case rows cover 20,486,848 complete scratch bytes with exact SHA256 and exact metadata comparisons. Weighted boundary fixtures passed 12 preservation and 17 rejection cases; stream fixtures passed 6 preservation and 6 rejection cases.

The bundle contains six checker/script/reference/document files and three result files. Real cases resolve offsets in a temporary extraction from the existing ISO. The reference embeds only own initial scratch and synthetic inputs, with per-blob hashes. No original source, decoded bank, packet records, lookahead windows, real output buffers or media are bundled. All 337 protected inputs stayed unchanged; the complete ISO hash matched before and after. The verified child temporary folder was removed.

Checker SHA256: `8d959138757ad6041628c2ebc4b6c967fbc6b52ffbbcf69b42c03de607eb0db8`. Reference SHA256: `5f132a5f2bd05ce76c86e1881ad324e1b2f82bd99ba978efa2e26e64607d1ca9`. Original ISO SHA256: `c8f9db7c936fffed7a5ea12a099c39ad3197208731ebbe4bcdfc3cec9b350638`.

These are explicit test matrices and initial state under the documented Float32 contract. Live bindings/state, model display, animation, levels and gameplay remain unfinished. The checker did not execute the original game or Dolphin. This packaging task changed no repository or engine files.

The launcher uses the existing local Python and ISO paths. `Last-result.md` and its AI twin retain the latest runtime result; `Last-case-results.csv` retains every successful comparison. Earlier build and validation reports are preserved. The README received a spacing edit after the initial build; executable, runtime script and expected reference were unchanged for the successful run.

| File | Bytes | SHA256 |
|---|---:|---|
| Check-SA2-Weighted-Vertices.cmd | 256 | `ffd85164cc94aa6b2295aff98cbbd370d59fdddfa873df9d0ed6c303ca56a720` |
| check_weighted_vertices.py | 8973 | `e41d07f56811f386c4e6d7a944e03c664ad69337c53d8a1c6ad410b840d6eced` |
| Last-case-results.csv | 75292 | `691a0a2f6d78b09e72293398737f4d49af62a86308f3daf6c57fb1336872f945` |
| Last-result.ai.json | 965 | `6863840cdde13f791f2a0a4f1b7b913e8369bc4d053058c53833dd23f795f5a0` |
| Last-result.md | 312 | `8963659934ee1d2aba1aae81560a56bc5881a6344b6b77c6167c577b480fa565` |
| README.ai.json | 1777 | `b46070e0614c596a872a080ac3717a87cb9c70ebda90ff385d0dacf0398e2abb` |
| README.md | 1464 | `99894b15afd5da4141cf1a0c9fbb78b04e0444bfa2af338bd635917a48ee850e` |
| Reference.ai.json | 2819604 | `5f132a5f2bd05ce76c86e1881ad324e1b2f82bd99ba978efa2e26e64607d1ca9` |
| vertex_stream_data_check_iso.exe | 550400 | `8d959138757ad6041628c2ebc4b6c967fbc6b52ffbbcf69b42c03de607eb0db8` |

Raw source guards and final file manifest are in `work/sa2-weighted-package-v1/final-source-guards.csv` and `package-files.csv`. Each versioned Python inspection/build/finalization script and the package runtime ran once.
