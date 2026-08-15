from dataclasses import dataclass

type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]


@dataclass(frozen=True)
class Observation:
    """One sanitized, append-only POC observation."""

    hypothesis: str
    operation: str
    outcome: str
    details: dict[str, JsonValue]

    def as_dict(self) -> dict[str, object]:
        return {
            "hypothesis": self.hypothesis,
            "operation": self.operation,
            "outcome": self.outcome,
            "details": self.details,
        }
