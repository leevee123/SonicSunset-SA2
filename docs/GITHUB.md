# GitHub repository

Public repository: https://github.com/leevee123/SonicSunset-SA2

## Current source publication, October19,2026

The owner's request to include the importers and logic is fulfilled with normal browsable `src/`, `Scripts/`, `third-party/`, `docs/`, `tools/`, shader and authored configuration folders, plus CMake build files. The older two-part archive is an additional recovery snapshot. Clone or download the repository directly to continue; see [HANDOFF.md](HANDOFF.md).

Publication used GitHub's signed-in file-upload UI. No write-enabled Actions workflow, personal token or new local credential was created. The original local project remains a ZIP checkout; a separate public clone was used for validation. Two existing GLFW static libraries required by unchanged CMake are included under an exact allowlist in `.gitignore`. These are third-party build dependencies; their license notices remain with the vendor files.

Disc images, extracted original game assets/modules, save states, generated native-code corpora outside this checkout, builds, credentials, environment files and private assistant directories remain excluded. No project license was invented. Root `.gitattributes` preserves evidence bytes; vendor attributes retain their existing checkout line-ending rules. No C++/Lua/CMake behavior changed during publication.

## Publication validation

The public source audit checked all2123 selected committed files against the local SHA256 identities, with zero missing files or content mismatches. All252 C++/Lua engine files are included. The audited source commit is `244fd9d744cf57dd38e25fdd81030d24df2b1b08`. The five older backup/recovery files remain as additional history.

A fresh public clone passed the Windows x64 MSVC/Ninja Debug editor build at `29ed1c4c949c529c78f9c160513bd14bb7665000`. All997 source/dependency inputs matched their exact committed bytes. The executable SHA256 was `db5c9f9b6b99c0de19cd3586040b04293d3d63a4a0e4ddfb123a7ce2b7d346f4`; the complete build-log SHA256 was `8d6e39ed93554c29911a5aa4eee5a660097dd23d775459c0f69f338a1fca989b`. The invocation-only debug-information option was `-DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=Embedded`. Existing ImGui Git attributes change only line endings in165 checked-out files; the committed originals still match exactly.

The earlier build attempt failed at the sandbox network resolver before compilation. The next comparison identified only vendor checkout line-ending transformations; the final check compares exact committed blobs and separately accounts for those newline-only differences. GitHub rejected one combined tools upload as too large, so the identical complete files were split into smaller batches. Interrupted evidence uploads were checked and retried; final hashes verify the result.

## SA2 limits

GitHub hosting does not mean the complete game is decompiled or playable. The previous weighted package passes314 weighted cases,309 complete streams and all65,536 signed weights under explicit matrix/cache/state and Float32 assumptions. Live bindings, opcode2A numerical behavior, complete model rendering, animation, levels, player physics and camera remain unfinished. The function addresses, original behavior, validation scope and unknowns remain in the topic references. The last engine edits were ModelVertexTransform.h/.cpp, recorded in ENGINE_CHANGES; this publication changes no engine files.

## Earlier hosting history

On October18 the repository was created private and a verified2118-file snapshot was uploaded in two parts. The32,274,101-byte combined archive has SHA25617be8afe19f7950caad7c7b6b9762b158f62d5d9776faf3a4873fd62ae87f6d8. Restore-Source.cmd/restore_source.py validate paths, sizes and hashes and restore into a new Source folder without overwriting existing files. Verification passed for all2118 members. An initial hardlink fixture failed; workspace copies passed, and the failure reports were preserved.

An earlier proposed Actions importer was rejected by automatic approval review because it would grant contents:write and push access beyond that request's interpreted scope. It was never enabled; proposed-import-workflow.yml.txt remains inert. Direct uploads now provide the normal source tree without that permission change.

On October19 the owner requested public visibility and completed GitHub sudo verification directly in the browser. No verification code was requested in chat or stored. An optional README update during that visibility-only task was rejected by automatic approval review and cancelled. The later explicit request to publish importers/logic authorized the direct source publication and current README/handoff updates. The repository badge and settings were verified Public.
