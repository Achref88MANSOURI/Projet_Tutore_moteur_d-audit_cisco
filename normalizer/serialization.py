"""JSON representation only: semantic decisions are complete before this step."""
import json


def to_dict(model):
    return model.model_dump(mode='json', exclude_unset=True, exclude_none=True)


def to_json(model):
    return json.dumps(to_dict(model), ensure_ascii=False, separators=(',', ':')) + '\n'
