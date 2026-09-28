"""File-access methods compared by the benchmark. Every method goes through the Resource Hub."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from agentcore_platform_poc.agent_platform.hub_client import ResourceHubClient
from agentcore_platform_poc.resource_hub.paths import glob_matches

METHODS = frozenset({"direct", "hub_search", "mirage_sdk", "mirage_fuse", "mirror"})
OPS = frozenset({"list", "read", "write", "search"})
_TARGET = re.compile(r"[A-Za-z0-9._\-*?/|]{1,300}")
RG = Path(__file__).resolve().parents[2] / "bin" / "rg"
# Aliases: inside the classes below, the method names list and bytes shadow the builtins.
Paths = list[str]
Matches = list[tuple[str, int]]
Data = bytes
MIRROR_ROOT = Path("/tmp/poc3-mirror")  # noqa: S108 - Runtime scratch, one user per session


@dataclass(frozen=True)
class Case:
    method: str
    op: str
    target: str
    text: str | None = None
    fresh: bool = False

    @classmethod
    def parse(cls, data: dict[str, Any]) -> Case:
        case = cls(
            str(data.get("method")),
            str(data.get("op")),
            str(data.get("target")),
            data.get("text"),
            bool(data.get("fresh", False)),
        )
        if case.method not in METHODS or case.op not in OPS:
            raise ValueError("unknown method or op")
        if not _TARGET.fullmatch(case.target) or ".." in case.target or case.target.startswith("/"):
            raise ValueError("bad target")
        if case.op == "search" and (not case.text or "|" not in case.target):
            raise ValueError("search needs text and 'folder|glob' target")
        return case


def digest(results: Any) -> str:
    return hashlib.sha256(json.dumps(sorted(results)).encode()).hexdigest()


class Method(Protocol):
    async def list(self, folder: str) -> Paths: ...
    async def read(self, path: str) -> int: ...
    async def write(self, path: str, data: Data) -> None: ...
    async def search(self, folder: str, glob: str, text: str) -> Matches: ...
    async def close(self) -> None: ...
    def requests(self) -> int: ...
    def bytes(self) -> int: ...


class SearchIncomplete(Exception):
    """A search stopped at a limit; its matches must not be scored as a full result."""


class DirectMethod:
    def __init__(
        self, hub: ResourceHubClient, concurrency: int = 16, max_carry_bytes: int = 1024 * 1024
    ) -> None:
        self.hub = hub
        self._sem = asyncio.Semaphore(concurrency)
        self._max_carry = max_carry_bytes
        self.peak_carry_bytes = 0

    def requests(self) -> int:
        return self.hub.requests_made

    def bytes(self) -> int:
        return self.hub.bytes_received

    async def list(self, folder: str) -> Paths:
        return [e["path"] for e in await self.hub.list(folder)]

    async def read(self, path: str) -> int:
        return sum([len(part) async for part in self.hub.iter_chunks(path)])

    async def write(self, path: str, data: Data) -> None:
        await self.hub.write(path, data)

    async def _scan(self, path: str, needle: Data) -> Matches:
        async with self._sem:
            found: Matches = []
            carry, line_no, hit = b"", 0, False  # hit: needle seen in a cut part of this line
            keep = max(len(needle) - 1, 0)
            async for part in self.hub.iter_chunks(path):
                lines = (carry + part).split(b"\n")
                carry = lines.pop()
                for index, line in enumerate(lines):
                    line_no += 1
                    if (index == 0 and hit) or needle in line:
                        found.append((path, line_no))
                if lines:
                    hit = False
                if len(carry) > self._max_carry:
                    # A very long line: remember a hit, keep only a tail that can finish a needle.
                    hit = hit or needle in carry
                    carry = carry[-keep:] if keep else b""
                self.peak_carry_bytes = max(self.peak_carry_bytes, len(carry))
            if hit or (carry and needle in carry):
                found.append((path, line_no + 1))
            return found

    async def search(self, folder: str, glob: str, text: str) -> Matches:
        paths = [p for p in await self.list(folder) if glob_matches(glob, p)]
        results = await asyncio.gather(*(self._scan(p, text.encode()) for p in paths))
        return sorted(m for r in results for m in r)

    async def close(self) -> None:
        return None


class HubSearchMethod(DirectMethod):
    async def search(self, folder: str, glob: str, text: str) -> Matches:
        result = await self.hub.search(text, glob)
        if result.get("truncated"):
            raise SearchIncomplete(f"truncated:{result['truncated']}")
        return sorted((m["path"], int(m["line_no"])) for m in result["matches"])


class MirrorMethod(DirectMethod):
    def __init__(self, hub: ResourceHubClient, root: Path = MIRROR_ROOT, rg: Path = RG) -> None:
        super().__init__(hub)
        self.root = root
        self.rg = rg
        # A copy-in snapshot: files stay as first fetched until close() (fresh: true).
        self._synced: set[str] = set()
        self._fetched: set[str] = set()

    async def _fetch(self, path: str) -> None:
        async with self._sem:
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as handle:
                async for part in self.hub.iter_chunks(path):
                    handle.write(part)
        self._fetched.add(path)

    async def _sync(self, folder: str) -> None:
        if folder in self._synced:
            return
        paths = await DirectMethod.list(self, folder)
        await asyncio.gather(*(self._fetch(p) for p in paths if p not in self._fetched))
        self._synced.add(folder)

    async def list(self, folder: str) -> Paths:
        await self._sync(folder)
        return sorted(
            str(p.relative_to(self.root)) for p in (self.root / folder).rglob("*") if p.is_file()
        )

    async def read(self, path: str) -> int:
        if path not in self._fetched:
            await self._fetch(path)
        return (self.root / path).stat().st_size

    async def write(self, path: str, data: Data) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        self._fetched.add(path)
        await self.hub.write(path, data)  # write-back through the Hub

    async def search(self, folder: str, glob: str, text: str) -> Matches:
        await self._sync(folder)
        return await rg_search(self.rg, self.root, folder, glob, text)

    async def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
        self._synced.clear()
        self._fetched.clear()


async def rg_search(rg: Path, cwd: Path, folder: str, glob: str, text: str) -> Matches:
    """Fixed-string search with ripgrep; the glob is applied with the Hub's segment rules."""
    process = await asyncio.create_subprocess_exec(
        str(rg),
        "--fixed-strings",
        "--line-number",
        "--only-matching",  # print the needle, not the line: output stays small
        "--null",  # path, NUL, then line:match — safe for any path
        "--with-filename",
        "--no-heading",
        "--no-ignore",
        "--hidden",
        "--text",
        "-e",
        text,  # -e: a needle such as "--files" is never read as an option
        "--",
        folder,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:  # PIPE always sets both
        raise RuntimeError("rg pipes missing")
    matches: set[tuple[str, int]] = set()
    async for raw in process.stdout:
        path, _, rest = raw.rstrip(b"\n").partition(b"\0")
        number = rest.split(b":", 1)[0]
        name = path.decode()
        if number.isdigit() and glob_matches(glob, name):
            matches.add((name, int(number)))
    stderr = await process.stderr.read()
    code = await process.wait()
    if code not in (0, 1):  # 1 means no match
        raise RuntimeError(f"rg exit {code}: {stderr[:200]!r}")
    return sorted(matches)
