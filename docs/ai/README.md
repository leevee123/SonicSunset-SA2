# docs/ai: compact twins for Claude, loaded on demand
Token-saving versions of the long human docs, in dense shorthand. The human doc is the source of truth; on conflict it wins and the twin gets fixed. Nothing here is auto-loaded: read this index, then only the files the task needs.

| Task touches | Read | Human doc |
|---|---|---|
| any code change | `ARCHITECTURE.md` (state, build, layout, runtime flow, conventions, gaps; 7 KB) | `docs/ARCHITECTURE.md` |
| Globals, pools, camera, meshes, Entity, levels, streaming, culling | + `ARCH_ENGINE.md` | same |
| collision, physics, gameplay tick, Lua `sf` API, scripts | + `ARCH_GAMEPLAY.md` | same |
| a disc format / importer | + `ARCH_IMPORTERS.md` | same |
| SA2 whole-disc decompilation / generated corpus / coverage / Gekko / apploader / startup FP | + `SA2_DECOMPILATION.md` | `docs/SA2_DECOMPILATION_PROGRESS.md` |
| SA2 startup / outer loop / trailer callers / mode dispatch / original processor and MMIO effects | + `SA2_BOOT.md`, `SA2_DECOMPILATION.md` | `docs/SA2_BOOT_REFERENCE.md` |
| SA2 original callback records / cleanup / default allocator / Chao pointer consumption / list dispatch / partial ABI | + `SA2_CALLBACK.md`, `SA2_REL.md` | `docs/SA2_CALLBACK_REFERENCE.md` |
| SA2 stored REL reader / copied main-self section views / layouts / original link-unlink / module identity / relocation evidence | + `SA2_REL.md`, `ARCH_IMPORTERS.md` | `docs/SA2_REL_REFERENCE.md` |
| SA2 Sonic pointer-bank loading / sentinel layout / exact pointer order / original file-read path | + `SA2_POINTER_BANK.md`, `ARCH_IMPORTERS.md` | `docs/SA2_POINTER_BANK_REFERENCE.md` |
| SA2 node fields / static-animated traversal / vertex packets / drawing streams and explicit cache control / inner geometry records / explicit grouped-helper data and collector limits / explicit Float32 unweighted/weighted vertex calculations and complete first-stream dispatch / drawing setup / quantization and FIFO caveats | + `SA2_MODEL_DATA.md`, `SA2_POINTER_BANK.md`, `ARCH_IMPORTERS.md` | `docs/SA2_MODEL_DATA_REFERENCE.md` |
| SA2 interactive Chao texture preview / its launch and hidden check | + `SA2_PREVIEW.md`, `ARCH_ENGINE.md`, `ENGINE_USAGE.md` | `docs/SA2_PREVIEW.md` |
| SA2 Battle Chao palette conversion / exact live blend / TLUT groups and lifecycle / compressed module evidence | + `SA2_PALETTE.md` | `docs/SA2_PALETTE_REFERENCE.md` |
| SA2 Battle GVR/GVP / GX pixels / original mip upload | + `SA2_TEXTURE.md` | `docs/SA2_TEXTURE_REFERENCE.md` |
| SA2 Battle GVM containers / native texture loading | + `SA2_GVM.md` | `docs/SA2_GVM_REFERENCE.md` |
| SA2 Battle PRS files / compressed asset loading | + `SA2_PRS.md` | `docs/SA2_PRS_REFERENCE.md` |
| the original Shadow player (any) | `STH2005_PLAYER.md` (core: reading the game, frame, offsets, flags, behaviors, open questions) | `docs/STH2005_PLAYER_REFERENCE.md` |
| ground speed, turning, skid, slopes, drift | + `STH2005_GROUND.md` | same |
| ground resolve, collision sweep, probe/snap, fence kick | + `STH2005_COLLISION.md` | same |
| jump, jumpdash, landing, drawn model, animation | + `STH2005_AIR_ANIM.md` | same |
| the original SADX Sonic (task/struct layout, input, time, `sadxLiveLog.py`) | `SADX_SONIC.md` | `docs/SADX_SONIC_REFERENCE.md` |
| using the engine: loading a level, level JSON, adding a level or a game, the Lua `sf` entry points | `ENGINE_USAGE.md` | `docs/ENGINE_USAGE.md` |
| replay recording / comparison | `REPLAY.md` | `docs/REPLAY_COMPARISON.md` |
| running a tool | skill `project-tools` | `docs/TOOLS.md` |
| deciding what is left / parked as polish | `POLISH.md` | `docs/POLISH_NOTES.md` |

Rules:
- A task that changes a human doc updates the matching twin file in the same task. Twins keep current truth only; a superseded claim stays as a one-line `~~...~~` pointer at most; history lives in the human doc. A new fact goes in the topic file it belongs to, not in the core file.
- Open a human doc only for one section (grep its heading, Read with offset/limit).
- Decompile: grep the twins for the FUN_ address first (decoded functions are recorded there); otherwise `tools/decompFunc.py` (summary, `--grep`, `--lines`) instead of reading a whole function.
- Tool and script output: compact `--ai` / digest forms only; scratchpad scripts print the answer (a few lines or a short table), never whole lists or dumps.
- One task per chat: at the end of a task its status sits in the twins (e.g. `REPLAY.md` Status), so a new chat starts from them instead of a long history.

2026-10-17 SA2 weighted/stream status and evidence: `SA2_MODEL_DATA.md`, `SA2_DECOMPILATION.md`, `ARCH_IMPORTERS.md`, `ENGINE_CHANGES.md`; human `docs/evidence/sa2-weighted-vertices-2026-10-17/README.md` with paired reports/rawCSV. Explicit CPU path only;2A/live binding/render/gameplay remain.

| GitHub repository / source upload and exclusions | `GITHUB.md` | `docs/GITHUB.md` |

| Continuing the source project / build inputs and remaining SA2 work | `HANDOFF.md`, `GITHUB.md` | `docs/HANDOFF.md` |
