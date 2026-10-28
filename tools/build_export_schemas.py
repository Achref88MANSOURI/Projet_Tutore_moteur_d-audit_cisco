"""Generate the single public business schema."""
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from schemas.normalized_config import business_schema

if __name__=='__main__':
    path=ROOT/'schemas/normalized_export_v1.schema.json'
    path.write_text(json.dumps(business_schema(),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(path.name)
