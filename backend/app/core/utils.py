"""Small shared utilities."""
import uuid
from typing import Union


def to_uuid(value: Union[str, uuid.UUID, None]) -> Union[uuid.UUID, None]:
    """Convert a string or UUID to a uuid.UUID (used for column bindings)."""
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return None
