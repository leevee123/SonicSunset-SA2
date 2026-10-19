# Continuing the project

The public repository contains ordinary engine source folders. Clone or download it to work on the code; the two older source-upload parts are an additional recovery snapshot. They are not required to browse the current source tree.

## Code map

- `src/Importers/SA2/`: PRS, GVM/GVP textures, Chao palettes, REL/pointer banks, model nodes/vertex packets, drawing/geometry records and explicit unweighted/weighted vertex calculations.
- `src/Importers/GameCube/`, `Ninja/`, `Renderware/`, `STH2005/`: existing shared disc/asset readers and Sonic Adventure/Shadow paths.
- `src/Gameplay/`, `Objects/`, `Physics/`, `Scripting/`, `Graphics/`, `Loading/`: engine behavior, objects/prefabs, collisions/physics, Lua API, rendering and resource loading.
- `Scripts/`: existing Lua player/object/game logic. SA2 levels, player physics and gameplay prefabs are not implemented yet.
- `docs/ENGINE_CHANGES.md`: the file-by-file engine change ledger. Start documentation from `docs/ai/README.md`, and follow the human/compact topic pairs.

## Build and local inputs

Use CMake3.28+, C++23 and the vendored dependencies. Existing CMake links the included GLFW static libraries in `third-party/GLFW/lib/`; these are required third-party build dependencies, not game binaries. The tested configuration is Windows x64 MSVC/Ninja Debug, editor on. The prior local MSVC debug-information workaround was invocation-only: `-DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=Embedded`. See ARCHITECTURE for the platform details and runtime paths.

Supply your own original game files locally. Disc images, extracted native game files, saves, credentials and private assistant state are excluded. No new project license has been invented; existing third-party notices are preserved.

## SA2 state and next work

The latest completed CPU fragment implements original8011DC98 weighted vertices and8011D1D4 first-stream dispatch with explicit matrix, initial scratch, state and Float32 assumptions. The independent checks passed314 weighted cases,309 full streams and all65536 signed weights; the full engine compiled and linked. These results do not establish a live animation/cache/material binding or a rendered character.

Read SA2_MODEL_DATA_REFERENCE and its compact twin for addresses, VA/DOL/ISO mappings, decoded file offsets, exact formulas, host guards, native quirks, failures and unknowns. Continue with matrix-stack initialization, animation/provider/skeleton traversal, actual cache ownership/lifetime and material/topology/GX binding. Opcode2A numerical behavior remains unknown and is rejected. Levels/collision/object behavior/player physics/camera need original evidence and Lua prefabs afterward.

Complete research CSVs and paired reports are under `docs/evidence/`. Some retained scripts and evidence paths refer to the original author's local scratch workspace and require path adaptation. The full generated Ghidra projects/corpus, analysis runtime installations and original disc are not part of this source repository. Another researcher must recreate that analysis setup from their own originals; the saved function addresses/hashes and reviewed findings are the starting evidence.

## Publication validation

The source tree is being published directly through GitHub's file upload UI, with a complete remote/local byte comparison and a clean-checkout build to follow. No write-enabled Actions workflow or personal token is needed. Final publication evidence is recorded separately when those checks complete. No engine behavior is changed by this publication.
