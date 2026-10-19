from pathlib import Path
script = Path(__file__).with_name('fetch_model_fp_reference_v1.py')
source = script.read_text().replace("'sa2-model-setup-v1/dolphin-reference'", "'sa2-model-setup-v1/dolphin-reference-v2'")
exec(compile(source, str(Path(__file__)), 'exec'))
