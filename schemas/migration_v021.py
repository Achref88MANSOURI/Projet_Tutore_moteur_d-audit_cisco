"""Explicit upgrade and loss-refusing legacy export, using frozen 0.2.0 schema."""
from copy import deepcopy
import json
from pathlib import Path
from jsonschema import Draft202012Validator

LEGACY=json.loads(Path(__file__).with_name('normalizedconfig_v0_2.schema.json').read_text(encoding='utf-8'))


def upgrade_v020(document):
    Draft202012Validator(LEGACY).validate(document)
    from .normalizedconfig_v02 import NormalizedConfig
    data=deepcopy(document);data['schema_version']='0.2.1'
    return NormalizedConfig.model_validate(data)


def project_v020(document):
    def populated(v):
        if isinstance(v,dict):return any(populated(x) for x in v.values())
        if isinstance(v,list):return bool(v)
        return v is not None
    def trim(value,schema):
        if '$ref' in schema:schema=LEGACY['$defs'][schema['$ref'].split('/')[-1]]
        if 'anyOf' in schema:
            candidates=[x for x in schema['anyOf'] if '$ref' in x or x.get('type')==('array' if isinstance(value,list) else 'object' if isinstance(value,dict) else None)]
            if candidates:return trim(value,candidates[0])
        if isinstance(value,dict) and 'properties' in schema:
            result={}
            for k,v in value.items():
                if k in schema['properties']:result[k]=trim(v,schema['properties'][k])
                elif populated(v):raise ValueError('Cannot export populated 0.2.1 audit properties as 0.2.0')
            return result
        if isinstance(value,list) and 'items' in schema:return [trim(x,schema['items']) for x in value]
        return value
    data=trim(deepcopy(document),LEGACY);data['schema_version']='0.2.0'
    Draft202012Validator(LEGACY).validate(data)
    return data
