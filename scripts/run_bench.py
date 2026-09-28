"""Run the benchmark one case per request through the unified API; resumable."""

from __future__ import annotations

import argparse
import json
import os
import random
import uuid
from pathlib import Path
from typing import Any

import httpx

from agentcore_platform_poc.bench_agent.methods import digest
from agentcore_platform_poc.bench_fixtures import NEEDLE
from agentcore_platform_poc.bench_report import render_markdown, summarize
from agentcore_platform_poc.caller import TokenStore

BENCH_DIR = Path("evidence/bench")
METHODS = ["direct", "hub_search", "mirage_sdk", "mirage_fuse", "mirror"]
SMALL_OPS = [
    ("list", "bench/large", None),
    ("read", "bench/large/small/f001.txt", None),
    # Writes go outside the fixtures, so list and search results stay equal to the manifest.
    ("write", "bench/scratch/w-{method}.txt", None),
    ("search", "bench/small|bench/small/*", NEEDLE),
    ("search", "bench/large/small|bench/large/small/*", NEEDLE),
]
LARGE_OPS = [
    ("read", "bench/large/huge/h050_0.txt", None),
    ("read", "bench/large/huge/h1g_0.txt", None),
    ("read", "bench/large/huge/h5g_0.txt", None),
    ("search", "bench/large/huge|bench/large/huge/*", NEEDLE),
]
SEARCH_FOLDERS = (
    ("small", "bench/small"),
    ("large", "bench/large/small"),
    ("large", "bench/large/huge"),
)
CASE_FIELDS = ("method", "op", "target", "text", "fresh")


def plan(seed: int) -> list[dict[str, object]]:
    """Rounds of all methods per (op, target, rep), method order shuffled in each round.

    The reps of one (op, target) run back to back: the bench Runtime ends an idle session
    after 900 s and any session after 3,600 s, so a warm rep must not wait a whole plan round.
    """
    cases: list[dict[str, object]] = []
    for ops, reps in ((SMALL_OPS, 30), (LARGE_OPS, 5)):
        for op, target, text in ops:
            methods = [m for m in METHODS if op == "search" or m != "hub_search"]
            for rep in range(reps + 1):  # rep 0 is the cold case
                order = list(methods)
                random.Random(f"{seed}|{op}|{target}|{rep}").shuffle(order)  # noqa: S311
                cases += [
                    {
                        "method": method,
                        "op": op,
                        "target": target.format(method=method),
                        "text": text,
                        "rep": rep,
                        "fresh": rep == 0,
                    }
                    for method in order
                ]
    return cases


def expected_results(bench_dir: Path) -> dict[str, str]:
    """The correctness guard: search matches, the large listing, and each file's size."""
    manifests = {
        w: json.loads((bench_dir / f"manifest-{w}.json").read_text()) for w in ("small", "large")
    }
    expected: dict[str, str] = {}
    for workspace, prefix in SEARCH_FOLDERS:
        matches = [
            tuple(m) for m in manifests[workspace]["matches"] if m[0].startswith(prefix + "/")
        ]
        expected[f"{prefix}|{prefix}/*"] = digest(matches)
    expected["bench/large"] = digest([f["path"] for f in manifests["large"]["files"]])
    for manifest in manifests.values():
        for spec in manifest["files"]:
            expected[spec["path"]] = str(spec["size"])  # a read returns the bytes it read
    return expected


def _row(case: dict[str, object], response: httpx.Response) -> dict[str, Any]:
    """The agent's row, kept in the case's group; any other answer is a failed row."""
    try:
        body = response.json()
    except ValueError:
        body = None
    if response.status_code != 200 or not isinstance(body, dict):
        code = body.get("error") if isinstance(body, dict) else None
        return {"ok": False, "error": f"api:{response.status_code}:{code or 'bad_response'}"}
    result = body.get("result")
    if body.get("status") != 200 or not isinstance(result, dict):
        return {"ok": False, "error": f"runtime:{body.get('status')}"}
    return result | {"ok": result.get("ok") is True}


def _latest(rows_file: Path) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    if rows_file.exists():
        for line in rows_file.read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                latest[str(row["key"])] = row  # a retried case replaces its earlier failure
    return latest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user", default="a")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)
    api = os.environ.get("POC3_UNIFIED_API_URL", "http://127.0.0.1:8300")
    rows_file = BENCH_DIR / "rows.jsonl"
    try:
        expected = expected_results(BENCH_DIR)
    except FileNotFoundError:
        print(f"no fixture manifests in {BENCH_DIR}: run -m scripts.seed_bench_fixtures first")
        return 2
    done = {key for key, row in _latest(rows_file).items() if row.get("ok")}
    # One Runtime session per (method, op, target) in this run: rep 0 is the cold case in a new
    # session, and warm reps reuse it (same microVM and method instance). A session from an
    # earlier run is gone, so a resumed group starts a new session (the agent reports it cold).
    sessions: dict[str, str] = {}
    for case in plan(args.seed):
        group = f"{case['method']}|{case['op']}|{case['target']}"
        key = f"{group}|{case['rep']}"
        if key in done:
            continue
        if case["fresh"] or group not in sessions:
            sessions[group] = f"poc3-{uuid.uuid4().hex}"
            case = case | {"fresh": True}
        token = TokenStore().load(args.user, "api")  # re-read: the user may have signed in again
        body = {"case": {k: case[k] for k in CASE_FIELDS}, "session_id": sessions[group]}
        try:
            response = httpx.post(
                f"{api}/bench",
                json=body,
                headers={"authorization": f"Bearer {token}"},
                timeout=960,
            )
        except httpx.HTTPError as error:
            outcome: dict[str, Any] = {"ok": False, "error": f"transport:{type(error).__name__}"}
        else:
            if response.status_code in (401, 403):
                print(
                    f"caller token rejected ({response.status_code}): run "
                    f"`.venv/bin/python -m scripts.platform_cli login --user {args.user}`, "
                    "then rerun this command"
                )
                return 2
            outcome = _row(case, response)
        row = outcome | {
            "method": case["method"],
            "op": case["op"],
            "target": case["target"],
            "cold": bool(outcome.get("cold", case["fresh"])),
            "key": key,
            "rep": case["rep"],
            "session_id": sessions[group],
        }
        rows_file.parent.mkdir(parents=True, exist_ok=True)
        with rows_file.open("a") as handle:
            handle.write(json.dumps(row) + "\n")
        warm_ran_cold = row["ok"] and row["cold"] and not case["fresh"]
        note = " (warm rep ran cold: the session ended)" if warm_ran_cold else ""
        print(key, row["ok"], row.get("ms"), row.get("error") or "", note)
    summary = summarize(list(_latest(rows_file).values()), expected)
    (BENCH_DIR / "summary.md").write_text(render_markdown(summary))
    print(f"wrote {BENCH_DIR / 'summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
