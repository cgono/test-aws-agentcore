import json
from pathlib import Path

from agentcore_identity_poc.models import Observation
from agentcore_identity_poc.redaction import assert_safe_evidence


class EvidenceWriter:
    """Append sanitized observations as compact JSONL rows."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    def append(self, observation: Observation) -> None:
        row = observation.as_dict()
        assert_safe_evidence(row)
        encoded_row = json.dumps(row, allow_nan=False, separators=(",", ":"))

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8", newline="\n") as evidence_file:
            evidence_file.write(encoded_row)
            evidence_file.write("\n")
