from pathlib import Path
source = Path(__file__).with_name('compile_weighted_data_v1.py').read_text().replace('compile-v1','compile-v2')
exec(compile(source,str(Path(__file__)),'exec'))
