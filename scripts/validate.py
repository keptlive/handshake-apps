"""Validate every bundled manifest's schema; not signature or host verification."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

root = Path(__file__).resolve().parents[1]
schema = json.loads((root / 'manifest.schema.json').read_text())
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema, format_checker=FormatChecker())
examples = sorted((root / 'examples').rglob('*.app.json'))
if not examples:
    raise SystemExit('No example manifests found')
failed = False
for example in examples:
    errors = list(validator.iter_errors(json.loads(example.read_text())))
    for error in errors:
        print(f'{example.relative_to(root)}: {list(error.path)}: {error.message}')
    failed |= bool(errors)
    if not errors:
        print(f'PASS {example.relative_to(root)}')
raise SystemExit(1 if failed else 0)
