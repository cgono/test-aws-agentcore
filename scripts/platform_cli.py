"""Caller CLI: acts as the UI for Users A and B."""

from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path
from urllib.parse import quote

import httpx
import msal  # type: ignore[import-untyped]

from agentcore_platform_poc.caller import TokenStore, brief_text
from scripts.terraform_outputs import load_terraform_outputs

STORE = TokenStore()


def _api_url() -> str:
    return os.environ.get("POC3_UNIFIED_API_URL", "http://127.0.0.1:8300")


def _hub_url() -> str:
    return load_terraform_outputs(Path("infra/terraform/platform"))["resource_hub_url"]


def login(user: str) -> None:
    env = os.environ
    app = msal.PublicClientApplication(
        env["POC3_CLI_CLIENT_ID"],
        authority=f"https://login.microsoftonline.com/{env['POC3_TENANT_ID']}",
    )
    for kind, scope in (
        ("api", f"api://{env['POC3_UNIFIED_API_CLIENT_ID']}/Research.Run"),
        ("hub", f"api://{env['POC3_HUB_APP_ID']}/Workspace.ReadWrite"),
    ):
        accounts = app.get_accounts()
        result = app.acquire_token_silent([scope], account=accounts[0]) if accounts else None
        if not result:
            flow = app.initiate_device_flow(scopes=[scope])
            print(flow["message"])
            result = app.acquire_token_by_device_flow(flow)
        if "access_token" not in result:
            raise SystemExit(f"login failed: {result.get('error')}")
        STORE.save(user, kind, result["access_token"])
    print(f"signed in as user {user}")


def _hub(user: str, method: str, route: str, **kwargs: object) -> httpx.Response:
    response = httpx.request(
        method,
        f"{_hub_url()}{route}",
        headers={"authorization": f"Bearer {STORE.load(user, 'hub')}"},
        timeout=60,
        **kwargs,
    )  # type: ignore[arg-type]
    if response.status_code >= 400:
        raise SystemExit(f"hub {response.status_code}: {response.text[:200]}")
    return response


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("login", "brief", "research", "grant", "ls", "get"):
        p = sub.add_parser(name)
        p.add_argument("--user", choices=["a", "b"], required=True)
        if name == "brief":
            p.add_argument("--region", choices=["sea", "ca"], required=True)
        if name == "research":
            p.add_argument("--prompt", default="Follow the instructions in brief.md.")
            p.add_argument("--mode", choices=["grant", "raw"], default="grant")
            p.add_argument("--grant-file", type=Path)
            p.add_argument(
                "--hub-token-file", type=Path, help="raw mode: a saved (possibly expired) hub token"
            )
            p.add_argument("--session-id")
        if name == "grant":
            p.add_argument("--ttl", type=int, required=True)
            p.add_argument("--out", type=Path, required=True)
        if name in ("ls", "get"):
            p.add_argument("--path", default="")
        if name == "get":
            p.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "login":
        login(args.user)
    elif args.command == "brief":
        marker = f"marker-{args.user}-{uuid.uuid4().hex[:8]}"
        _hub(
            args.user, "PUT", "/v1/files/brief.md", content=brief_text(args.region, marker).encode()
        )
        print(json.dumps({"uploaded": "brief.md", "marker": marker}))
    elif args.command == "research":
        body: dict[str, object] = {"prompt": args.prompt, "mode": args.mode}
        if args.session_id:
            body["session_id"] = args.session_id
        if args.grant_file:
            body["grant"] = args.grant_file.read_text().strip()
        if args.mode == "raw":
            body["user_hub_token"] = (
                args.hub_token_file.read_text().strip()
                if args.hub_token_file
                else STORE.load(args.user, "hub")
            )
        response = httpx.post(
            f"{_api_url()}/research",
            json=body,
            headers={"authorization": f"Bearer {STORE.load(args.user, 'api')}"},
            timeout=960,
        )
        print(json.dumps(response.json(), indent=2))
    elif args.command == "grant":
        response = httpx.post(
            f"{_api_url()}/grants",
            json={"ttl_seconds": args.ttl},
            headers={"authorization": f"Bearer {STORE.load(args.user, 'api')}"},
            timeout=30,
        )
        args.out.write_text(response.json()["grant"])
        os.chmod(args.out, 0o600)
        print(json.dumps({"saved": str(args.out), "exp": response.json()["exp"]}))
    elif args.command == "ls":
        print(
            json.dumps(
                _hub(args.user, "GET", f"/v1/list/{quote(args.path, safe='/')}").json(), indent=2
            )
        )
    elif args.command == "get":
        args.out.write_bytes(
            _hub(args.user, "GET", f"/v1/files/{quote(args.path, safe='/')}").content
        )
        print(json.dumps({"saved": str(args.out)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
