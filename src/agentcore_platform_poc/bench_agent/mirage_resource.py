"""Mirage over the Resource Hub: a GenericResource whose IO calls the Hub, never S3."""

from __future__ import annotations

import asyncio
import fnmatch
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from mirage import GenericResource, Workspace
from mirage.accessor.base import Accessor
from mirage.commands.builtin.generic_bind.adapter import CommandIO
from mirage.types import FileStat, FileType, MountMode
from mirage.utils.key_prefix import mount_prefix_of

from agentcore_platform_poc.agent_platform.hub_client import HubError, ResourceHubClient
from agentcore_platform_poc.bench_agent.methods import RG, Data, DirectMethod, Matches, Paths

MAX_READ_BYTES_OP = 1024**3


class ResourceTooLarge(Exception):
    """Mirage asked for a whole file larger than MAX_READ_BYTES_OP (recorded as a finding)."""


class HubAccessor(Accessor):  # type: ignore[misc]  # mirage is untyped
    def __init__(self, hub: ResourceHubClient) -> None:
        super().__init__()
        self.hub = hub


def _rel(path: Any) -> str:
    return str(path.resource_path).strip("/")


async def _readdir(accessor: HubAccessor, path: Any, /, index: Any = None) -> list[str]:
    folder = _rel(path)
    prefix = f"{folder}/" if folder else ""
    children = sorted(
        {e["path"][len(prefix) :].split("/", 1)[0] for e in await accessor.hub.list(folder)}
    )
    mount = mount_prefix_of(path.virtual, path.resource_path).rstrip("/")
    return [f"{mount}/{prefix}{child}" for child in children]


async def _stat(accessor: HubAccessor, path: Any, /, index: Any = None) -> FileStat:
    rel = _rel(path)
    name = os.path.basename(rel) or "/"
    if rel:
        try:
            return FileStat(name=name, size=await accessor.hub.stat(rel), type=FileType.FILE)
        except HubError as error:
            if error.status not in (400, 404):
                raise
    if not rel or await accessor.hub.list(rel):
        return FileStat(name=name, type=FileType.DIRECTORY)
    raise FileNotFoundError(rel)


async def _read_bytes(accessor: HubAccessor, path: Any, /, index: Any = None) -> bytes:
    rel = _rel(path)
    if await accessor.hub.stat(rel) > MAX_READ_BYTES_OP:
        raise ResourceTooLarge(rel)
    return b"".join([part async for part in accessor.hub.iter_chunks(rel)])


async def _read_stream(
    accessor: HubAccessor, path: Any, /, index: Any = None
) -> AsyncIterator[bytes]:
    async for part in accessor.hub.iter_chunks(_rel(path)):
        yield part


async def _read_range(
    accessor: HubAccessor, path: Any, /, index: Any = None, offset: int = 0, size: int | None = None
) -> bytes:
    rel = _rel(path)
    length = size if size is not None else await accessor.hub.stat(rel) - offset
    return await accessor.hub.read(rel, offset, length)


async def _write(accessor: HubAccessor, path: Any, data: bytes, /) -> None:
    await accessor.hub.write(_rel(path), bytes(data))


def _is_mounted(accessor: HubAccessor, /) -> bool:
    return True


def hub_resource(hub: ResourceHubClient) -> GenericResource:
    io = CommandIO(
        readdir=_readdir,
        read_bytes=_read_bytes,
        read_stream=_read_stream,
        stat=_stat,
        is_mounted=_is_mounted,
        read_range=_read_range,
        write=_write,
        local=False,
    )
    return GenericResource(name="hub", accessor=HubAccessor(hub), io=io, sizes_always_known=True)


class MirageMethod(DirectMethod):
    def __init__(self, hub: ResourceHubClient, *, fuse: bool, mountpoint: str = "/mnt/ws") -> None:
        super().__init__(hub)
        self.fuse = fuse
        self.mountpoint = mountpoint
        self._workspace: Workspace | None = None
        self._mounted: str | None = None

    async def _ws(self) -> Workspace:
        if self._workspace is None:
            self._workspace = Workspace({"/ws": hub_resource(self.hub)}, mode=MountMode.WRITE)
            if self.fuse:
                self._mounted = self._workspace.add_fuse_mount("/ws", self.mountpoint)
        return self._workspace

    async def _run(self, command: str, stdin: Data | None = None) -> str:
        result = await (await self._ws()).execute(command, stdin=stdin)
        if result.exit_code not in (0, 1):  # grep exits 1 when nothing matches
            raise RuntimeError(f"mirage exit {result.exit_code}: {(result.stderr or b'')[:200]!r}")
        out = result.stdout or b""
        return out.decode() if isinstance(out, bytes) else str(out)

    def _mount(self) -> Path:
        return Path(self._mounted or self.mountpoint)

    async def list(self, folder: str) -> Paths:
        await self._ws()
        if self.fuse:
            return sorted(
                str(p.relative_to(self._mount()))
                for p in (self._mount() / folder).rglob("*")
                if p.is_file()
            )
        out = await self._run(f"find /ws/{folder} -type f")
        return sorted(line.removeprefix("/ws/") for line in out.splitlines() if line)

    async def read(self, path: str) -> int:
        await self._ws()
        if self.fuse:
            total = 0
            with open(self._mount() / path, "rb") as handle:  # noqa: ASYNC230 - the benchmark measures the mount
                while chunk := handle.read(4 * 1024 * 1024):
                    total += len(chunk)
            return total
        await self._run(f"cat /ws/{path} > /dev/null")  # streams through read_stream
        return await self.hub.stat(path)

    async def write(self, path: str, data: Data) -> None:
        await self._ws()
        if self.fuse:
            (self._mount() / path).write_bytes(data)  # noqa: ASYNC240 - the benchmark measures the mount
        else:
            await self._run(f"tee /ws/{path} > /dev/null", stdin=data)

    async def search(self, folder: str, glob: str, text: str) -> Matches:
        await self._ws()
        if self.fuse:
            process = await asyncio.create_subprocess_exec(
                str(RG),
                "-F",
                "-n",
                "--no-heading",
                "--with-filename",
                text,
                folder,
                cwd=self._mount(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out = (await process.communicate())[0].decode()
        else:
            out = await self._run(f"grep -rnF {text} /ws/{folder}")
        pairs = []
        for line in out.splitlines():
            path, number, _rest = line.split(":", 2)
            pairs.append((path.removeprefix("/ws/"), int(number)))
        return sorted(p for p in pairs if fnmatch.fnmatchcase(p[0], glob))

    async def close(self) -> None:
        if self._workspace is not None:
            if self._mounted:
                self._workspace.remove_fuse_mount("/ws")
            await self._workspace.close()
            self._workspace = None
            self._mounted = None
