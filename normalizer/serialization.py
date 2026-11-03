"""Serialize the sole canonical contract after Pydantic graph validation."""
import json
from schemas.router_contract_v1 import RouterContractV1


def to_dict(model):
    if not isinstance(model, RouterContractV1):
        raise TypeError('Export requires RouterContractV1')
    # Revalidate nested mutations as well as the root model before exporting.
    validated = RouterContractV1.model_validate(model.model_dump(mode='python'))
    return validated.model_dump(mode='json')


def to_json(model):
    return json.dumps(to_dict(model), ensure_ascii=False, separators=(',', ':')) + '\n'
