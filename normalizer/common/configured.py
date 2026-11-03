"""Select exactly owned values; no protocol mappings or CLI interpretation."""
from dataclasses import dataclass
from .contexts import at, child


@dataclass(frozen=True, slots=True)
class Binding:
    path: str
    record: int


def leaves(value, path=''):
    if hasattr(value, 'model_dump'):
        # Mutating an existing list/model does not update its parent's
        # model_fields_set. Walk nested objects without treating scalar defaults
        # or untouched empty factories as configured values.
        for name in type(value).model_fields:
            item = getattr(value, name)
            if name in value.model_fields_set or hasattr(item, 'model_dump') or isinstance(item, (list, dict)) and item:
                yield from leaves(item, child(path, name))
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield from leaves(item, child(path, key))
    elif isinstance(value, list) and value:
        for index, item in enumerate(value):
            yield from leaves(item, child(path, index))
    elif value is not None:
        if hasattr(value, 'compressed'):
            value = str(value)
        yield path, value


def validate_targets(model, bindings):
    for binding in bindings:
        try:
            if at(model, binding.path) is None:
                raise ValueError('Configured value is unset')
        except (AttributeError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise ValueError('Invalid internal field binding') from exc


def select_configured(state, blocked):
    """Project eligible leaves, preserving explicit false, zero and empty lists."""
    eligible = {b.path.lstrip('/') for b in state.bindings if state.eligible(b.record)}

    def select(value, path):
        if any(path == p or path.startswith(p + '/') for p in blocked):
            return None
        if value is None:
            return None
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                projected = select(item, child(path, key))
                if projected is not None:
                    result[key] = projected
            return result or None
        if isinstance(value, list) and value:
            result = [select(item, child(path, i)) for i, item in enumerate(value)]
            result = [item for item in result if item is not None]
            return result or None
        if value == [] and not state.absences.permits(path):
            return None
        # For leaf values, check eligibility (strip leading slash for comparison)
        if path.lstrip('/') not in eligible:
            return None
        return value

    selected = select(state.c.model_dump(mode='json'), '') or {}
    # Fixed V1 roots; nested unknowns are restored by the same canonical models.
    return {**state._empty_document, **selected}
