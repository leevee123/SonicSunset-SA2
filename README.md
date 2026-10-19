# SonicSunset / SA2

C++ engine work for Sonic Adventure, Shadow the Hedgehog (2005), and Sonic Adventure 2 Battle, with Lua gameplay and documented reverse engineering.

This is a work in progress. Sonic Adventure 2 is not fully decompiled, animated or playable in this engine. Original disc images, extracted game files, save states and local builds are not included.

## Current SA2 progress

The engine has validated PRS and texture/palette loaders, REL and pointer-bank readers, model/drawing/geometry data readers, and explicit CPU vertex transforms. The latest weighted vertex and complete first-stream path passes314 weighted cases,309 stream cases and all65,536 signed weight values against independent original-instruction references. The full Windows x64 MSVC/Ninja Debug editor build passes.

Matrices, scratch buffers and state are explicit test inputs. Live animation, matrix/cache/material bindings, complete model rendering, levels, player physics and camera still need original evidence and implementation. Unknown opcode2A is rejected rather than guessed.

## Working with the project

- Read [AGENTS.md](AGENTS.md) for repository instructions.
- Start documentation at [docs/ai/README.md](docs/ai/README.md); human references are linked there.
- Build/layout/runtime details: [architecture](docs/ARCHITECTURE.md).
- SA2 status: [decompilation progress](docs/SA2_DECOMPILATION_PROGRESS.md).
- Vertex reconstruction, function addresses and validation: [model reference](docs/SA2_MODEL_DATA_REFERENCE.md).
- Exact engine edits: [engine changes](docs/ENGINE_CHANGES.md).
- GitHub source policy and import method: [repository notes](docs/GITHUB.md).

CMake3.28+, C++23 and the vendored dependencies are used. Configure with `cmake -S . -B build` and build with `cmake --build build`. Consult the architecture document for platform/editor settings and the tested Windows configuration. Supply your own game files locally; do not commit them.

Existing third-party license notices remain in their original directories. This import does not assign a new license to the project.

The importers and engine logic are published as normal `src/` and `Scripts/` files. See [the handoff guide](docs/HANDOFF.md) for where to continue, required game files, validation limits and the next unknowns. The original two-part snapshot remains as an older recovery backup.
