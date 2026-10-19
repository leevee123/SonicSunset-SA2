# SA2 Chao texture preview

The engine now has an interactive view of real Sonic Adventure 2 Battle Chao body textures. Select one of six families and change four mixes to see the original palette math recolor three texture images. Reset restores the starting family and values. Close the window or press Escape to exit.

This is a flat texture preview. A Chao model, animations, garden and playable SA2 character are not implemented. The original type and blend-field gameplay names are still unknown, so the controls deliberately use neutral Family 1–6 and Mix A–D labels.

## Open the local preview

The tested local package is in this chat's `outputs/SA2-Preview/`. Double-click `Start-SA2-Preview.cmd`. It uses the existing uncompressed image in this chat's `work/sa2.iso`; keep that image in place. The package contains the compiled engine, content manifest and readable instructions. It does not copy the disc or require the SADX/Shadow images. It is a local Windows x64 build using this machine's MSVC runtime and OpenGL 4.5 support; portability to another machine has not been checked.

From an engine build with EDITOR enabled:

```text
SonicSunset.exe --sa2-palette-preview "path\to\sa2.iso" "Assets\External\SA2\PalettePreview.json"
```

The two supplied paths are explicit. Normal startup without these flags still follows the existing SADX/Shadow path. The preview owns its GLFW window, ImGui context, textures and cleanup; it does not call the game renderer, level loader, Lua startup, resource pools or camera callbacks. The cursor is free. Minimized windows remain under GLFW/ImGui handling. The inspection window starts at 1100 × 760 and has a 900 × 650 minimum, with scrolling available when content is taller.

## Original evidence and content

The preview uses the previously verified parallel SA2 readers, palette builder, decoder and supplied-mip upload unchanged. Original formats and layout validation remain in SA2_PRS_REFERENCE.md, SA2_GVM_REFERENCE.md, SA2_TEXTURE_REFERENCE.md and SA2_PALETTE_REFERENCE.md with their AI twins. No new original format or gameplay rule is inferred by this interface.

| Proven source | What the preview uses |
|---|---|
| ChaoMain decoded `+0x1FAF8`, filename table `+0xA7328` | Load 39 GVP banks in the original order; retain each 192-byte BGRA bank. |
| ChaoMain `+0x1F2E4` | Generate 96 bytes of BE RGB565 for types 2/6/9/12/15/18 using the four offset-named floats. Original float/FMA order and quirks stay in the CPU helper. |
| ChaoMain `+0x1F1B8`, texture table `+0xA72E0` | Select the matching three AL_BODY entries for each supported type. |
| ChaoMain `+0x1FA88`; DOL `0x801039A0` / `0x801039E8` | Interpret the output as three contiguous groups of 16 RGB565 colors. The preview supplies explicit RGBA groups rather than recreating GX slots. |
| ChaoMain `+0x2884C` → `+0x28D38`; list `+0xFB07C` | Established AL_BODY list, 143 entries. |
| DOL `0x80072820` → `0x80072458` → `0x800D2684` → `0x80118FC0` | Original AL_BODY PRS/GVM loading relationship. |

Module locations above are decoded ChaoMain file offsets, not asserted runtime addresses. The prior Ghidra analysis used synthetic runtime mappings; actual module base remains unknown. REA 6.3 cannot open this DOL/PPC target, so the established Ghidra headless fallback supplies the original evidence. No new decompilation is needed for an interface over the verified resources.

`External/SA2/PalettePreview.json` is new diagnostic content, not an original game format. Version 1 has `bodyArchive`, 39 ordered `banks`, and six `families` with a display `label`, original byte `type` and three `textureEntries`. Python generates/checks these from the retained original table evidence, without picking filenames or indices by eye. The existing CopyExternal build target copies it next to the engine. C++ validates counts, supported type bytes, bounds and C4 format before opening graphics. A disc-header guard admits only the inspected GSNE8P disc number 0, revision 0 image; other revisions are unsupported until examined.

## Conservative interface decisions

- Family labels have no assumed character or evolution meanings. Mix A/B/C/D map to original data fields `+0xA8/+0xAC/+0xB0/+0xC0`. Mix C is disabled outside type 2 because those other proven branches do not use it.
- The slider interval −1..1 and starting floats 0, 0, 0.5, 0.5 are inspection choices. They are not claims about native save defaults or the legal gameplay range. The palette builder applies its existing original branch/clamp behavior. Some distinct inputs produce the same colors.
- Nearest filtering, clamp addressing and RGBA8 display with framebuffer sRGB disabled follow the engine's ImGui inspection path. They show the decoded texels clearly; original model sampling, material color and retail frame gamma remain unknown.
- Keep all engine changes opt-in, with no shared importer, palette math, GPU upload or existing game-body alteration. This is an editor diagnostic, not a reconstructed character/mechanic, so it introduces no Lua prefab.
- Keep the disc in the existing scratch location instead of duplicating a large image. The launcher reports a missing image and leaves its message visible.

## Validation

The native hidden check uses the same loader, texture rebuild and draw functions as the visible preview:

```text
SonicSunset.exe --sa2-palette-preview-check "path\to\sa2.iso" "PalettePreview.json" "check-output"
```

It uploads all six families, injects mouse events through the actual ImGui widgets, checks the family button, all four sliders and two Reset actions, reads every uploaded mip, and captures its own rendered back buffer. It is bounded to 25 frames and returns nonzero if any check fails or it exits early. On success it writes `check.md` and compact `check.ai.json`, plus `default.png`, `changed.png`, `reset.png`. These captures are produced by this app, not by desktop screen automation. The flag does not start either existing game.

Observed on this machine: full Windows x64 MSVC/Ninja Debug EDITOR ON engine build, link and asset copies passed. Invocation-only Embedded debug information avoids the local default PDB C1902 issue; repository build settings are unchanged. Strict isolated `/W4 /WX /O2` compilation passed after using the build directory for the compiler's relative module-map path. The first strict invocation used the wrong cwd and failed to find that map; source did not need a correction.

Quoted native result: `SA2 preview check passed: six families, four sliders, family/reset buttons and GPU pixels.` Renderer: AMD Radeon RX 9060 XT. Loaded 39 real banks and 143 body textures. Compared **172,032 GPU bytes** with the verified CPU decoder. All selected body entries are single-mip textures; all 18 entries are exercised.

Quoted one-run Python result: `{"passed": true, "manifestBanks": 39, "manifestFamilies": 6, "palettePayloadBytes": 3744, "renderedTexturePixels": 307200, "renderedResetPixelsMatch": 307200, "renderedChangedPixels": 307200}`. The script checks real disc identity/FST/GVPL headers and recorded offsets, original manifest table mapping, all native control checkpoints, 1100 × 760 captures and the rendered image crops. Reset restores all **307,200 displayed texture pixels** exactly; changing family/mix changes all of those pixels in the chosen capture. Three startup error cases (wrong argument count, missing image, invalid manifest version) return 1 with readable messages. PNGs were visually inspected for layout and visible color changes.

Reports/captures are retained in this chat's `work/preview-check-final/`, `work/preview-validation.*` and `outputs/SA2-Preview/Validation/`; the repository carries the validation digest in `docs/evidence/sa2-preview-validation.ai.json`. The corresponding readable evidence is this document.

## What remains unknown or unported

Gameplay names/ranges/defaults for the four floats and six types; retail FPSCR state; original palette slot allocation/reuse and GX region policy; original model/material UV binding, sampler and full-frame color; three GVP header meanings; other game revisions. The native byte/color math retains the earlier tested nearest-even, NI=0, VE=0 FP contract. The preview does not resolve those unknowns.

Models, skeletons, animations, levels, object logic, player movement and camera/gameplay reconstruction remain future work. The user requested something testable, so this task closes with an actual interactive resource preview rather than guessed gameplay. No leaked original source was encountered or used.
