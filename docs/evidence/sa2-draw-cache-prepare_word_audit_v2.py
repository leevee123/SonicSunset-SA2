from pathlib import Path
import runpy

folder = Path(__file__).resolve().parent
source = (folder / 'audit_cache_words_v1.py').read_text(encoding='utf-8')

"""/* Correct the convenience decoder's argument order in an independent v2.
Original bytes, mappings and ASM comparisons never depended on this column. */"""
assert source.count('decode(address, value)') == 1
source = source.replace('decode(address, value)', 'decode(value, address)')
source = source.replace("OUT = Path(__file__).resolve().parent\nROOT = OUT.parents[1]", "SOURCE_OUT = Path(__file__).resolve().parent\nROOT = SOURCE_OUT.parents[1]\nOUT = SOURCE_OUT / 'word-audit-v2'\nOUT.mkdir(exist_ok=False)")
source = source.replace("'version': 1, 'DOL_sha256'", "'version': 2, 'DOL_sha256'")
source = source.replace('# Cache original-word audit v1', '# Cache original-word audit v2')
target = folder / 'audit_cache_words_v2.py'
assert not target.exists()
target.write_text(source, encoding='utf-8')
runpy.run_path(str(target), run_name='__main__')
