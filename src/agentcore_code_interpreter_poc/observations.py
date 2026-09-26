"""Structured, sanitized observations for the findings write-up."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Status = Literal["pass", "fail", "blocked"]


@dataclass(frozen=True)
class Observation:
    question: str
    check: str
    status: Status
    expected: str
    observed: str
    config: Mapping[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "question": self.question,
            "check": self.check,
            "status": self.status,
            "expected": self.expected,
            "observed": self.observed,
            "config": dict(self.config),
        }


def append_observations(path: Path, observations: Iterable[Observation]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for observation in observations:
            handle.write(json.dumps(observation.as_dict(), sort_keys=True))
            handle.write("\n")
