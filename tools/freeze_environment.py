import hashlib
from importlib.metadata import distributions
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
freeze=subprocess.check_output([sys.executable,'-m','pip','freeze'],text=True)
(ROOT/'requirements.lock').write_text(freeze,encoding='utf-8')
dependencies=sorted([{'name':d.metadata['Name'],'version':d.version} for d in distributions()],key=lambda x:x['name'].lower())
sources=[]
for name in ('ttp','ttp_templates','ios-show-run-ttp'):
    repo=ROOT/'vendor'/name
    commit=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    licenses=[str(p.relative_to(ROOT)) for p in repo.glob('LICENSE*')]
    sources.append({'repository':name,'commit':commit,'licenses':licenses,
                    'usage':'reference_only_no_code_imported' if name=='ios-show-run-ttp' else 'official_reference'})
(ROOT/'docs/dependencies.json').write_text(json.dumps({'dependencies':dependencies,'repositories':sources},indent=2)+'\n',encoding='utf-8')
from ttp_templates import get_template
from parser.run_ttp import OFFICIAL
out=ROOT/'templates/upstream';out.mkdir(parents=True,exist_ok=True)
catalog=[]
for name,filename in OFFICIAL.items():
    template=get_template(path='platform/'+filename)
    (out/filename).write_text(template,encoding='utf-8',newline='\n')
    catalog.append({'id':name,'source':'dmulyalin/ttp_templates','installed_version':'0.6.18',
                    'path':'templates/upstream/'+filename,'sha256':hashlib.sha256(template.encode()).hexdigest(),
                    'role':{'interfaces':'Interface records with default enabled=True; defaults not adopted by mapper.',
                            'vrfs':'VRF records; rd reused only with source evidence.',
                            'bgp_asns':'ASN collection only; not a complete BGP parser.',
                            'nat_static':'Official forms include extendable, VRF and ports; the unqualified static IP-to-IP form needs our extension. Qualifiers/ports stay native when v0.1 is inadequate.'}[name]})
(ROOT/'templates/catalogue_upstream.json').write_text(json.dumps(catalog,indent=2)+'\n',encoding='utf-8')
print('Pinned dependencies, Git revisions and four actively executed upstream templates.')
