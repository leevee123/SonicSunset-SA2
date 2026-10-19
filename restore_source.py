from pathlib import Path, PurePosixPath
import hashlib
import io
import json
import stat
import sys
import zipfile

root = Path(__file__).resolve().parent
parts = [root / 'source-upload.part01', root / 'source-upload.part02']
data = b''.join(part.read_bytes() for part in parts)
assert hashlib.sha256(data).hexdigest() == '17be8afe19f7950caad7c7b6b9762b158f62d5d9776faf3a4873fd62ae87f6d8', 'Source snapshot hash does not match.'
contents = {}
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    manifest = json.loads(archive.read('SOURCE_MANIFEST.ai.json'))
    entries = {row['path']: row for row in manifest['files']}
    assert len(entries) == len(manifest['files'])
    assert set(archive.namelist()) == set(entries) | {'SOURCE_MANIFEST.ai.json'}
    for entry in archive.infolist():
        path = PurePosixPath(entry.filename)
        assert not path.is_absolute() and '..' not in path.parts and '\\' not in entry.filename
        assert path.parts and not any(part in ('.git', '.github') for part in path.parts)
        assert not stat.S_ISLNK(entry.external_attr >> 16)
        value = archive.read(entry)
        if entry.filename in entries:
            row = entries[entry.filename]
            assert len(value) == row['bytes'] and hashlib.sha256(value).hexdigest() == row['sha256'], entry.filename
        contents[entry.filename] = value
if '--verify-only' in sys.argv:
    print(f'PASS: {len(entries)} source files verified; no files extracted.')
else:
    target = (root / 'Source').resolve()
    assert target.parent == root.resolve() and not target.exists(), 'Source folder already exists; no files overwritten.'
    target.mkdir()
    for name, value in contents.items():
        output = (target / Path(*PurePosixPath(name).parts)).resolve()
        assert output.is_relative_to(target)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(value)
    print(f'Restored {len(entries)} verified source files to {target}')
