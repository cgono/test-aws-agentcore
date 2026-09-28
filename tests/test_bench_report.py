from __future__ import annotations

from typing import Any

from agentcore_platform_poc.bench_report import percentile, render_markdown, summarize

SEARCH = "bench/large/small|bench/large/small/*"


def _row(
    ms: float,
    cold: bool = False,
    digest: str = "d",
    op: str = "search",
    target: str = SEARCH,
    bytes_: int = 0,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "method": "direct",
        "op": op,
        "target": target,
        "ms": ms,
        "cold": cold,
        "ok": True,
        "result_digest": digest,
        "bytes": bytes_,
        **extra,
    }


def test_percentile_nearest_rank() -> None:
    values = [float(v) for v in range(1, 101)]
    assert percentile(values, 50) == 50 and percentile(values, 95) == 95
    assert percentile([7.0], 95) == 7.0


def test_summary_pass_and_cold_split() -> None:
    rows = [_row(9000, cold=True)] + [_row(3000)] * 28 + [_row(4000)]
    [summary] = summarize(rows, {SEARCH: "d"})
    assert summary["cold_ms"] == 9000 and summary["n"] == 30 and summary["p50"] == 3000
    assert summary["n_warm"] == 29
    assert summary["correct"] and summary["verdict"] == "pass"


def test_wrong_digest_is_invalid() -> None:
    rows = [_row(100, digest="x")] * 30
    assert summarize(rows, {SEARCH: "d"})[0]["verdict"] == "invalid"


def test_small_samples_have_no_p95() -> None:
    rows = [_row(100, op="read", target="bench/large/huge/h1g_0.txt", bytes_=1_000_000_000)] * 5
    [summary] = summarize(rows, {})
    assert summary["p95"] is None and summary["mb_per_s"] == 10_000.0
    assert summary["verdict"] == "pass"


def test_failed_rows_make_fail_verdict() -> None:
    rows = [dict(_row(100), ok=False, error="FuseError")] * 3
    assert summarize(rows, {})[0]["verdict"] == "fail"


def test_markdown_has_header_and_rows() -> None:
    text = render_markdown(summarize([_row(100)] * 20, {}))
    assert text.startswith("| method | op | target |") and "direct" in text


def test_any_failed_row_fails_the_group() -> None:
    rows = [_row(100)] * 29 + [dict(_row(100), ok=False, error="hub:500:internal")]
    [summary] = summarize(rows, {SEARCH: "d"})
    assert summary["failed"] == 1 and summary["verdict"] == "fail"
    assert summary["error"] == "hub:500:internal"


def test_slow_p95_fails_even_when_p50_passes() -> None:
    rows = [_row(3000)] * 18 + [_row(20_000)] * 2
    assert summarize(rows, {SEARCH: "d"})[0]["verdict"] == "fail"


def test_read_throughput_uses_the_file_size_not_the_bytes_moved() -> None:
    # A warm mirror read moves no bytes (the copy is local), but it still reads the whole file.
    target = "bench/large/huge/h1g_0.txt"
    row = _row(40_000, op="read", target=target, digest="1000000000", result_count=10**9)
    rows = [row] * 5
    [summary] = summarize(rows, {target: "1000000000"})
    assert summary["mb_per_s"] == 25.0 and summary["verdict"] == "fail"


def test_read_of_the_wrong_size_is_invalid() -> None:
    target = "bench/large/small/f001.txt"
    rows = [_row(50, op="read", target=target, digest="9999")] * 30
    assert summarize(rows, {target: "10000"})[0]["verdict"] == "invalid"


def test_cold_value_is_the_rep_zero_row() -> None:
    rows = [_row(700, cold=True, rep=4), _row(900, cold=True, rep=0)] + [_row(100, rep=1)] * 20
    [summary] = summarize(rows, {})
    assert summary["cold_ms"] == 900 and summary["n_warm"] == 20


def test_thresholds_by_workload() -> None:
    def verdict(op: str, target: str, ms: float) -> str:
        return str(summarize([_row(ms, op=op, target=target)] * 20, {})[0]["verdict"])

    assert verdict("list", "bench/large", 1000) == "pass"
    assert verdict("list", "bench/large", 1001) == "fail"
    assert verdict("read", "bench/large/small/f001.txt", 201) == "fail"
    assert verdict("write", "bench/scratch/w-direct.txt", 300) == "pass"
    assert verdict("write", "bench/scratch/w-direct.txt", 301) == "fail"
    assert verdict("search", "bench/small|bench/small/*", 60_000) == "recorded"
    assert verdict("read", "bench/large/huge/h5g_0.txt", 60_000) == "recorded"


def test_only_cold_rows_are_recorded_not_judged() -> None:
    [summary] = summarize([_row(100, cold=True)], {SEARCH: "d"})
    assert summary["p50"] is None and summary["verdict"] == "recorded"


def test_markdown_escapes_pipes_and_newlines() -> None:
    rows = [dict(_row(100), ok=False, error="boom | x\ny")]
    text = render_markdown(summarize(rows, {}))
    header, _, line = text.splitlines()
    assert "bench/large/small\\|bench/large/small/*" in line and "boom \\| x y" in line
    assert line.count("|") - line.count("\\|") == header.count("|")  # same number of cells
