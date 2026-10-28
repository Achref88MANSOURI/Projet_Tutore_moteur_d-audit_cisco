"""Validation of the single business contract for Python consumers."""
from jsonschema import Draft202012Validator, FormatChecker
from schemas.normalized_config import NormalizedConfig, business_schema


def boolean(value):
    """Accept a captured boolean, never infer one from a nonempty string."""
    if type(value) is not bool:
        raise ValueError('Configured flag must be a boolean')
    return value


def validate(document):
    model = NormalizedConfig.model_validate(document)
    Draft202012Validator(business_schema(), format_checker=FormatChecker()).validate(
        model.model_dump(mode='json', exclude_unset=True, exclude_none=True))
    return model
