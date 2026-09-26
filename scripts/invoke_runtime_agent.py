"""Invoke the POC Runtime agent once and print the JSON result."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import boto3  # type: ignore[import-untyped]

from agentcore_runtime_poc.invoke import INVOKE_CLIENT_CONFIG, RuntimeInvoker, new_session_id
from scripts.terraform_outputs import load_terraform_outputs

ACTIONS = (
    "whoami",
    "set_marker",
    "get_marker",
    "probe_egress",
    "chat",
    "chat_unauthenticated",
    "sleep",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=ACTIONS, required=True)
    parser.add_argument("--provider", choices=("openai", "anthropic"))
    parser.add_argument("--prompt")
    parser.add_argument("--marker")
    parser.add_argument("--seconds", type=int)
    parser.add_argument("--session-id")
    parser.add_argument("--stop", action="store_true", help="stop the session afterwards")
    args = parser.parse_args(argv)

    outputs = load_terraform_outputs(Path("infra/terraform/poc"))
    client = boto3.client(
        "bedrock-agentcore", region_name=outputs["aws_region"], config=INVOKE_CLIENT_CONFIG
    )
    invoker = RuntimeInvoker(client, outputs["agent_runtime_arn"])
    session_id = args.session_id or new_session_id()
    payload = {
        key: value
        for key, value in {
            "action": args.action,
            "provider": args.provider,
            "prompt": args.prompt,
            "marker": args.marker,
            "seconds": args.seconds,
        }.items()
        if value is not None
    }
    result = invoker.invoke(payload, session_id)
    print(
        json.dumps(
            {
                "session_id": session_id,
                "status_code": result.status_code,
                "elapsed_ms": result.elapsed_ms,
                "body": result.body,
            },
            indent=2,
        )
    )
    if args.stop:
        invoker.stop(session_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
