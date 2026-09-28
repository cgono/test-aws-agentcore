"""Deterministic benchmark workspaces with needles at known file/line positions."""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from typing import Any

NEEDLE = "POC3-NEEDLE-7f3a"
LINE_BYTES = 100
BLOCK_BYTES = 104_857_600  # 100 MiB, a multiple of 100
HEAD_PART_BYTES = (
    5_243_000  # the smallest multiple of 100 >= 5 MiB (5,242,880), the S3 non-final part minimum
)
_ALPHABET = "abcdefghijklmnopqrstuvwxyz     "


@dataclass(frozen=True)
class FileSpec:
    path: str
    size: int
    needle_lines: tuple[int, ...]


def _line(rng: random.Random) -> str:
    return "".join(rng.choice(_ALPHABET) for _ in range(LINE_BYTES - 1))


def text(seed: str, size: int, needle_lines: tuple[int, ...] = ()) -> bytes:
    if size % LINE_BYTES:
        raise ValueError("size must be a multiple of 100")
    rng = random.Random(seed)  # noqa: S311 - fixture content, not security
    wanted = set(needle_lines)
    lines = []
    for number in range(1, size // LINE_BYTES + 1):
        line = _line(rng)
        if number in wanted:
            line = (NEEDLE + line)[: LINE_BYTES - 1]
        lines.append(line)
    return ("\n".join(lines) + "\n").encode()


def small_workspace() -> list[FileSpec]:
    needles = {3: (5,), 11: (42,)}
    return [FileSpec(f"bench/small/f{i:02d}.txt", 10_000, needles.get(i, ())) for i in range(20)]


def large_workspace() -> list[FileSpec]:
    files = [
        FileSpec(f"bench/large/small/f{i:03d}.txt", 10_000, (50,) if i % 25 == 0 else ())
        for i in range(950)
    ]
    files += [
        FileSpec(f"bench/large/medium/m{i:02d}.txt", 1_000_000, (777,) if i in (0, 22) else ())
        for i in range(45)
    ]
    files += [
        FileSpec(f"bench/large/medium/n{i}.txt", 5_000_000, (49_999,) if i == 4 else ())
        for i in range(5)
    ]
    huge = [
        ("h050", 50_000_000, 3),
        ("h200", 200_000_000, 2),
        ("h1g", 1_000_000_000, 1),
        ("h5g", 5_000_000_000, 1),
    ]
    files += [
        FileSpec(f"bench/large/huge/{name}_{i}.txt", size, (10, 20_000))
        for name, size, count in huge
        for i in range(count)
    ]
    return files


def expected_matches(files: list[FileSpec]) -> list[tuple[str, int]]:
    return sorted((f.path, line) for f in files for line in f.needle_lines)


def manifest(files: list[FileSpec]) -> dict[str, Any]:
    matches = expected_matches(files)
    digest = hashlib.sha256(json.dumps(matches).encode()).hexdigest()
    return {
        "files": sorted(({"path": f.path, "size": f.size} for f in files), key=lambda f: f["path"]),
        "matches": matches,
        "digest": digest,
    }


def huge_parts(size: int) -> list[tuple[str, int]]:
    parts: list[tuple[str, int]] = [("head", HEAD_PART_BYTES)]
    remaining = size - HEAD_PART_BYTES
    while remaining > 0:
        n = min(BLOCK_BYTES, remaining)
        parts.append(("block", n))
        remaining -= n
    return parts
