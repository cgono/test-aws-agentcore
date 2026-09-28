"""Claude Code apiKeyHelper: print the current gateway token, or fail if it is stale."""

from __future__ import annotations

import sys
import time

import jwt

from agentcore_platform_poc.agent_platform.tokens import GATEWAY_TOKEN_FILE


def main() -> int:
    try:
        token = GATEWAY_TOKEN_FILE.read_text().strip()
        exp = jwt.decode(token, options={"verify_signature": False}).get("exp")
    except (OSError, jwt.PyJWTError):
        print("gateway token file missing or unreadable", file=sys.stderr)
        return 1
    if not isinstance(exp, int) or exp <= time.time():
        print("gateway token expired", file=sys.stderr)
        return 1
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
