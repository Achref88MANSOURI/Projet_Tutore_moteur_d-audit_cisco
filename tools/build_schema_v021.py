"""Generate the new schema without replacing the frozen 0.2.0 contract."""
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from schemas.normalizedconfig_v02 import NormalizedConfig


def schema():
    result=NormalizedConfig.model_json_schema()
    result['properties']['schema_version']={'const':'0.2.1','default':'0.2.1','title':'Schema Version','type':'string'}
    return result


if __name__=='__main__':
    (ROOT/'schemas/normalizedconfig_v0_2_1.schema.json').write_text(json.dumps(schema(),indent=2)+'\n',encoding='utf-8')
