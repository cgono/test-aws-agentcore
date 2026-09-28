"""File-access methods compared by the benchmark. Every method goes through the Resource Hub."""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from agentcore_platform_poc.agent_platform.hub_client import ResourceHubClient

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


class DirectMethod:
    def __init__(self, hub: ResourceHubClient, concurrency: int = 16) -> None:
        self.hub = hub
        self._sem = asyncio.Semaphore(concurrency)

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
            carry, line_no = b"", 0
            async for part in self.hub.iter_chunks(path):
                lines = (carry + part).split(b"\n")
                carry = lines.pop()
                for line in lines:
                    line_no += 1
                    if needle in line:
                        found.append((path, line_no))
            if carry and needle in carry:
                found.append((path, line_no + 1))
            return found

    async def search(self, folder: str, glob: str, text: str) -> Matches:
        paths = [p for p in await self.list(folder) if fnmatch.fnmatchcase(p, glob)]
        results = await asyncio.gather(*(self._scan(p, text.encode()) for p in paths))
        return sorted(m for r in results for m in r)

    async def close(self) -> None:
        return None


class HubSearchMethod(DirectMethod):
    async def search(self, folder: str, glob: str, text: str) -> Matches:
        result = await self.hub.search(text, glob)
        return sorted((m["path"], int(m["line_no"])) for m in result["matches"])


class MirrorMethod(DirectMethod):
    def __init__(self, hub: ResourceHubClient, root: Path = MIRROR_ROOT, rg: Path = RG) -> None:
        super().__init__(hub)
        self.root = root
        self.rg = rg
        self._synced: set[str] = set()

    async def _sync(self, folder: str) -> None:
        if folder in self._synced:
            return

        async def fetch(path: str) -> None:
            async with self._sem:
                target = self.root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("wb") as handle:
                    async for part in self.hub.iter_chunks(path):
                        handle.write(part)

        await asyncio.gather(*(fetch(p) for p in await DirectMethod.list(self, folder)))
        self._synced.add(folder)

    async def list(self, folder: str) -> Paths:
        await self._sync(folder)
        return sorted(
            str(p.relative_to(self.root)) for p in (self.root / folder).rglob("*") if p.is_file()
        )

    async def read(self, path: str) -> int:
        await self._sync(str(Path(path).parent))
        return (self.root / path).stat().st_size

    async def write(self, path: str, data: Data) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        await self.hub.write(path, data)  # write-back through the Hub

    async def search(self, folder: str, glob: str, text: str) -> Matches:
        await self._sync(folder)
        process = await asyncio.create_subprocess_exec(
            str(self.rg),
            "-F",
            "-n",
            "--no-heading",
            "--with-filename",
            "-g",
            glob.removeprefix(folder + "/"),
            text,
            folder,
            cwd=self.root,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await process.communicate()
        matches = []
        for line in out.decode().splitlines():
            path, number, _rest = line.split(":", 2)
            matches.append((path, int(number)))
        return sorted(matches)

    async def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
        self._synced.clear()
