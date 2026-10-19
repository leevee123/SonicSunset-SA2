# SonicSunset-SA2

Private project backup for the SonicSunset engine and Sonic Adventure 2 reconstruction.

The complete reviewed snapshot contains **2,118 source, dependency and documentation files**. Disc images, extracted native game files, save states, local builds, credentials and private assistant directories are excluded.

## Get the source

Download this repository through **Code → Download ZIP**, extract it, then double-click **Restore-Source.cmd** on this computer. It verifies the archive and every source-file hash before restoring the normal project into a new **Source** folder. It does not overwrite an existing Source folder, access the network or modify the uploaded parts. Python3.10+ can also run `python restore_source.py`.

`source-upload.part01` and `source-upload.part02` together hold the complete source archive. They are transport files, not game data. The verified archive SHA256 is `17be8afe19f7950caad7c7b6b9762b158f62d5d9776faf3a4873fd62ae87f6d8`.

## Current engine status

Weighted vertices and complete first-stream calculations pass314 weighted cases,309 stream cases and all65,536 signed weights. The full Windows engine builds and links. SA2 is not yet fully decompiled or playable: live animation/cache/material bindings, rendering, levels and gameplay remain unfinished. Unknown2A behavior is not guessed.

## GitHub file-tree import

Expanding the snapshot into GitHub's browsable source tree is pending. Automatic approval review rejected a proposed import workflow because it would give GitHub Actions repository write/push permission. No such workflow or permission was enabled. The exact proposed workflow is saved as `proposed-import-workflow.yml.txt`; this text file cannot run as a GitHub workflow. The uploaded backup and local restoration work without granting that permission.

Existing vendor license notices are preserved. No new project license was assigned.
