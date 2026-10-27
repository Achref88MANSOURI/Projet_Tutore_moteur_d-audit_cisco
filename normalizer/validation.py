import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from schemas.normalizedconfig import NormalizedConfig

SCHEMA=Path(__file__).resolve().parents[1]/'schemas/normalizedconfig_v0_1.schema.json'


def validate(document):
    model=NormalizedConfig.model_validate(document)
    Draft202012Validator(json.loads(SCHEMA.read_text(encoding='utf-8')),format_checker=FormatChecker()).validate(model.model_dump(mode='json'))
    return model
