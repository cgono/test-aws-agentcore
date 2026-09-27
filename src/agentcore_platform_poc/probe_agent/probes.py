"""Checks that run inside AgentCore Runtime. Results must not contain secrets."""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import jwt

GRANT_HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Custom-Grant"
_SAFE = ("aud", "azp", "roles", "ver", "exp")
PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c6360000002000001e221bc330000000049454e44ae426082"
)


def header_summary(headers: Mapping[str, str]) -> dict[str, Any]:
    grant = next((v for k, v in headers.items() if k.lower() == GRANT_HEADER.lower()), "")
    return {"names": sorted(headers), "grant_length": len(grant)}


def safe_claims(token: str) -> dict[str, Any]:
    claims = jwt.decode(token, options={"verify_signature": False})
    return {key: claims[key] for key in _SAFE if key in claims}


async def identity_probe(scopes: list[str]) -> dict[str, Any]:
    # Task 13 supplies the token source; Task 7 is the first live invocation.
    from agentcore_platform_poc.agent_platform.tokens import (  # type: ignore[import-untyped]
        IdentityTokenSource,
    )

    out: dict[str, Any] = {}
    for scope in scopes:
        source = IdentityTokenSource(
            provider_name=os.environ["IDENTITY_PROVIDER"],
            scope=scope,
            region=os.environ["POC_REGION"],
        )
        out[scope] = safe_claims(await source.get())
    return out


async def claude_cli_probe(helper_ttl_ms: int = 5000) -> dict[str, Any]:
    from claude_agent_sdk import (
        AssistantMessage,
        ClaudeAgentOptions,
        ClaudeSDKClient,
        SystemMessage,
        ToolUseBlock,
        create_sdk_mcp_server,
        tool,
    )

    calls: list[str] = []
    with tempfile.TemporaryDirectory(prefix="probe-helper-") as directory:
        counter = Path(directory) / "helper-calls"
        counter.write_text("")
        helper = Path(directory) / "helper.sh"
        helper.write_text(
            "#!/bin/sh\n"
            f"echo x >> {shlex.quote(str(counter))}\n"
            f"cat {shlex.quote(os.environ['GATEWAY_TOKEN_FILE'])}\n"
        )
        helper.chmod(helper.stat().st_mode | stat.S_IEXEC)

        # The SDK decorator has no static type information.
        @tool("ping", "Returns pong.", {})  # type: ignore[misc]
        async def ping(_: dict[str, Any]) -> dict[str, Any]:
            calls.append("ping")
            return {"content": [{"type": "text", "text": "pong"}]}

        options = ClaudeAgentOptions(
            tools=[],
            mcp_servers={"probe": create_sdk_mcp_server("probe", tools=[ping])},
            strict_mcp_config=True,
            allowed_tools=["mcp__probe__ping"],
            setting_sources=[],
            settings=json.dumps({"apiKeyHelper": str(helper)}),
            env={
                "ANTHROPIC_BASE_URL": os.environ["GATEWAY_URL"],
                "CLAUDE_CODE_API_KEY_HELPER_TTL_MS": str(helper_ttl_ms),
            },
            model=os.environ["AGENT_MODEL"],
            max_turns=4,
            thinking={"type": "disabled"},
        )
        used: list[str] = []
        seen_tools: list[str] = []
        async with ClaudeSDKClient(options=options) as client:
            await client.query("Call the ping tool once, then say done.")
            async for message in client.receive_response():
                if isinstance(message, SystemMessage) and message.subtype == "init":
                    seen_tools = sorted(str(name) for name in message.data.get("tools", []))
                if isinstance(message, AssistantMessage):
                    used.extend(
                        block.name for block in message.content if isinstance(block, ToolUseBlock)
                    )
            helper_calls_before_ttl = len(counter.read_text().splitlines())
            await asyncio.sleep(helper_ttl_ms / 1000 + 1)
            await client.query("Say done again.")
            async for _ in client.receive_response():
                pass
        return {
            "cli_started": True,
            "tool_names_seen": seen_tools,
            "tool_calls": used,
            "builtin_called": [name for name in used if not name.startswith("mcp__")],
            "ping_ran": calls == ["ping"],
            "helper_calls_before_ttl": helper_calls_before_ttl,
            "helper_calls": len(counter.read_text().splitlines()),
        }


async def fuse_probe(mount_timeout_s: float = 30) -> dict[str, Any]:
    usage = shutil.disk_usage("/tmp")  # noqa: S108 - Runtime scratch space under test
    result: dict[str, Any] = {
        "dev_fuse": os.path.exists("/dev/fuse"),
        "tmp_total_bytes": usage.total,
        "tmp_free_bytes": usage.free,
    }
    workspace = None
    mountpoint = None
    setup_timed_out = False
    try:
        from mirage import MountMode, RAMResource, Workspace

        workspace = Workspace({"/data": RAMResource()}, mode=MountMode.WRITE)
        await workspace.fs.write("/data/probe.txt", b"probe")
        mountpoint = await asyncio.wait_for(
            asyncio.to_thread(workspace.add_fuse_mount, "/data"), timeout=mount_timeout_s
        )
        mounted, listing = await asyncio.wait_for(
            asyncio.to_thread(
                lambda: (os.path.ismount(mountpoint), sorted(os.listdir(mountpoint)))
            ),
            timeout=mount_timeout_s,
        )
        result["is_mount"] = mounted
        result["mounted_listing"] = listing
        visible = result["is_mount"] and "probe.txt" in result["mounted_listing"]
        result["mount"] = "ok" if visible else "not_visible"
    except asyncio.CancelledError:
        setup_timed_out = mountpoint is None
        raise
    except Exception as error:  # noqa: BLE001 - a failed mount is the measurement
        setup_timed_out = isinstance(error, TimeoutError) and mountpoint is None
        result["mount"] = f"{type(error).__name__}: {str(error)[:300]}"
    finally:
        if workspace is not None:
            if setup_timed_out:
                # The mount worker may still be inside setup. Leave the last probe's
                # microVM to reclaim it rather than blocking the Runtime loop.
                result["cleanup"] = "skipped_unfinished_mount"
            else:
                removal_failed = False
                if mountpoint is not None:
                    try:
                        await asyncio.wait_for(
                            asyncio.to_thread(workspace.remove_fuse_mount, "/data"),
                            timeout=mount_timeout_s,
                        )
                    except Exception as error:  # noqa: BLE001 - cleanup is a probe datum
                        result["cleanup"] = type(error).__name__
                        removal_failed = True
                if not removal_failed:
                    await workspace.close()
    return result


def s3_denied_probe() -> dict[str, Any]:
    import boto3  # type: ignore[import-untyped]
    from botocore.exceptions import ClientError  # type: ignore[import-untyped]

    client = boto3.client("s3", region_name=os.environ["POC_REGION"])
    bucket = os.environ["WORKSPACE_BUCKET"]
    out: dict[str, Any] = {}
    for op, call in (
        ("get", lambda: client.get_object(Bucket=bucket, Key="users/probe/x")),
        ("put", lambda: client.put_object(Bucket=bucket, Key="users/probe/x", Body=b"x")),
    ):
        try:
            call()  # type: ignore[no-untyped-call]
            out[op] = "allowed"
        except ClientError as error:
            out[op] = error.response["Error"]["Code"]
    return out


def sandbox_probe() -> dict[str, Any]:
    from bedrock_agentcore.tools.code_interpreter_client import CodeInterpreter

    from agentcore_code_interpreter_poc.results import parse_tool_result

    client = CodeInterpreter(os.environ["POC_REGION"])
    client.start(identifier=os.environ["CODE_INTERPRETER_ID"])
    try:
        client.upload_file("probe.png", PNG_1X1)
        back = client.download_file("probe.png")
        bucket = os.environ["WORKSPACE_BUCKET"]
        script = (
            "import boto3\n"
            "c = boto3.client('s3')\n"
            "results = []\n"
            "for op in ('get', 'put'):\n"
            "    try:\n"
            "        if op == 'get':\n"
            f"            c.get_object(Bucket={bucket!r}, Key='users/probe/x')\n"
            "        else:\n"
            f"            c.put_object(Bucket={bucket!r}, Key='users/probe/x', Body=b'x')\n"
            "        results.append(op + ':allowed')\n"
            "    except Exception as e:\n"
            "        code = type(e).__name__\n"
            "        if hasattr(e, 'response'):\n"
            "            code = e.response['Error']['Code']\n"
            "        results.append(op + ':' + code)\n"
            "print(results)\n"
        )
        s3 = parse_tool_result(client.execute_code(script))
        return {
            "png_round_trip": back == PNG_1X1,
            "s3_call_failed": (
                not s3.failed
                and "get:" in s3.output
                and "put:" in s3.output
                and ":allowed" not in s3.output
            ),
            "s3_output_head": s3.output[:300],
        }
    finally:
        client.stop()
