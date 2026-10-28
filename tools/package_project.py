"""Build a local source/data/offline-dependencies archive; exclude venv/caches."""
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'dist';OUT.mkdir(exist_ok=True)
verification=json.loads((ROOT/'outputs/normalized_only_validation/validation.json').read_text(encoding='utf-8'))
assert verification['passed']
wheel_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'wheelhouse').glob('*.whl')}
(ROOT/'docs/wheelhouse_sha256.json').write_text(json.dumps(wheel_hashes,indent=2)+'\n',encoding='utf-8')
selected=[]
for path in ROOT.rglob('*'):
    if not path.is_file():continue
    rel=path.relative_to(ROOT)
    if any(part in ('.venv','cache','dist','.git','__pycache__','.pytest_cache') for part in rel.parts):continue
    if rel.parts[0] in ('baseline','outputs'):continue
    if rel.parts[0]=='vendor':continue  # runtime library sources are included in the pinned wheels
    if path.suffix in ('.pyc','.pyo'):continue
    selected.append(path)
archive=OUT/'network-config-normalizer-ttp.zip'
with ZipFile(archive,'w',ZIP_DEFLATED) as out:
    for path in selected:out.write(path,'network-config-normalizer-ttp/'+path.relative_to(ROOT).as_posix())
    out.writestr('network-config-normalizer-ttp/LIRE_MOI_ARCHIVE.txt',
        'Ouvrir README.md pour lancer le projet.\n'
        'L’archive contient les sources, configurations de test, rapports et dépendances Python figées en wheels.\n'
        'Créer .venv avec setup.ps1 ; l’environnement installé et les clones Git de référence restent dans le dossier local initial.\n'
        'Les révisions Git de référence sont dans docs/dependencies.json.\n')
with ZipFile(archive) as check:assert check.testzip() is None
print(f'{archive.name}: {len(selected)} files, {archive.stat().st_size} bytes; {len(wheel_hashes)} offline wheels')
