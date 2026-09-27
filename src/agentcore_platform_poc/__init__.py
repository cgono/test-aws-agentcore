"""Phase 3a platform plumbing POC."""

from pathlib import Path


def build_id() -> str:
    marker = Path(__file__).with_name("BUILD_ID")
    return marker.read_text().strip() if marker.exists() else "local"
