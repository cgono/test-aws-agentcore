"""Summarize benchmark rows and judge them against the user-confirmed thresholds."""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any

THRESHOLDS: dict[tuple[str, str], tuple[float, float]] = {
    ("list", "large"): (1000, 2000),
    ("read", "small-file"): (200, 500),
    ("write", "small-file"): (300, 750),
    ("search", "large-10kb"): (5000, 10000),
}
MIN_READ_MBPS_1GB = 50.0
MIN_P95_SAMPLES = 20


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    rank = max(1, math.ceil(q / 100 * len(ordered)))
    return ordered[rank - 1]


def _workload(op: str, target: str) -> str | None:
    if op == "list" and target == "bench/large":
        return "large"
    if op == "read" and target.startswith(("bench/small/", "bench/large/small/")):
        return "small-file"
    if op == "write":
        return "small-file"  # the bench agent always writes 10 KB
    if op == "search" and target.startswith("bench/large/small|"):
        return "large-10kb"
    return None


def _read_size(rows: list[dict[str, Any]]) -> int:
    # The file size, not the bytes moved: a warm mirror read moves nothing but reads the file.
    for row in rows:
        size = row.get("result_count") or row.get("bytes")
        if size:
            return int(size)
    return 0


def summarize(rows: list[dict[str, Any]], expected: dict[str, str]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[(row["method"], row["op"], row["target"])].append(row)
    out = []
    for (method, op, target), items in sorted(groups.items()):
        ok = [r for r in items if r.get("ok")]
        failed = [r for r in items if not r.get("ok")]
        warm_rows = [r for r in ok if not r.get("cold")]
        warm = [float(r["ms"]) for r in warm_rows]
        cold = sorted((r for r in ok if r.get("cold")), key=lambda r: int(r.get("rep") or 0))
        want = expected.get(target)
        correct = want is None or all(r.get("result_digest") == want for r in ok)
        summary: dict[str, Any] = {
            "method": method,
            "op": op,
            "target": target,
            "n": len(items),
            "n_warm": len(warm),
            "failed": len(failed),
            "cold_ms": float(cold[0]["ms"]) if cold else None,
            "p50": percentile(warm, 50) if warm else None,
            "p95": percentile(warm, 95) if len(warm) >= MIN_P95_SAMPLES else None,
            "median": percentile(warm, 50) if warm else None,
            "max": max(warm) if warm else None,
            "mb_per_s": None,
            "correct": correct,
            "error": failed[0].get("error") if failed else None,
        }
        size = _read_size(warm_rows)
        if op == "read" and warm and size:
            summary["mb_per_s"] = round(size / 1e6 / (percentile(warm, 50) / 1000), 1)
        if not summary["correct"]:
            summary["verdict"] = "invalid"  # timings count only for correct results (spec)
        elif failed:
            summary["verdict"] = "fail"  # a method that fails some of the time is not fast enough
        else:
            summary["verdict"] = _verdict(op, target, summary)
        out.append(summary)
    return out


def _verdict(op: str, target: str, s: dict[str, Any]) -> str:
    if s["p50"] is None:
        return "recorded"  # no warm sample to judge
    if op == "read" and target.endswith("h1g_0.txt"):
        return "pass" if (s["mb_per_s"] or 0) >= MIN_READ_MBPS_1GB else "fail"
    limits = THRESHOLDS.get((op, _workload(op, target) or ""))
    if limits is None:
        return "recorded"
    if s["p50"] > limits[0]:
        return "fail"
    if s["p95"] is None:
        return "recorded"  # under MIN_P95_SAMPLES warm rows: the p95 half cannot be judged
    return "pass" if s["p95"] <= limits[1] else "fail"


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return " ".join(text.split()).replace("|", "\\|")  # one line; a pipe would split the cell


COLUMNS = (
    "method", "op", "target", "n", "n_warm", "failed", "cold_ms", "p50", "p95", "max",
    "mb_per_s", "correct", "verdict", "error",
)  # fmt: skip


def render_markdown(summary: list[dict[str, Any]]) -> str:
    head = "| " + " | ".join(COLUMNS) + " |\n" + "|---" * len(COLUMNS) + "|\n"
    lines = []
    for s in summary:
        cells = [_cell(s[c]) for c in COLUMNS]
        cells[2] = f"`{cells[2]}`"
        lines.append("| " + " | ".join(cells) + " |")
    return head + "\n".join(lines) + "\n"
