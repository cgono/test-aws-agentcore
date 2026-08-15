from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
type FrozenJsonValue = (
    None | bool | int | float | str | tuple[FrozenJsonValue, ...] | Mapping[str, FrozenJsonValue]
)


@dataclass(frozen=True, init=False)
class Observation:
    """One sanitized, append-only POC observation."""

    hypothesis: str
    operation: str
    outcome: str
    details: Mapping[str, FrozenJsonValue]

    def __init__(
        self,
        hypothesis: str,
        operation: str,
        outcome: str,
        details: Mapping[str, JsonValue],
    ) -> None:
        object.__setattr__(self, "hypothesis", hypothesis)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "details", _freeze_mapping(details))

    def as_dict(self) -> dict[str, object]:
        return {
            "hypothesis": self.hypothesis,
            "operation": self.operation,
            "outcome": self.outcome,
            "details": _thaw_mapping(self.details),
        }


def _freeze_mapping(details: Mapping[str, JsonValue]) -> Mapping[str, FrozenJsonValue]:
    return MappingProxyType({key: _freeze(value) for key, value in details.items()})


def _freeze(value: JsonValue) -> FrozenJsonValue:
    if isinstance(value, dict):
        return _freeze_mapping(value)
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw_mapping(details: Mapping[str, FrozenJsonValue]) -> dict[str, JsonValue]:
    return {key: _thaw(value) for key, value in details.items()}


def _thaw(value: FrozenJsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        return _thaw_mapping(value)
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value
