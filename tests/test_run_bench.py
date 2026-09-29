from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentcore_platform_poc.bench_agent.methods import digest
from agentcore_platform_poc.caller import TokenStore
from scripts import run_bench


def test_plan_shape() -> None:
    cases = run_bench.plan(7)
    groups = Counter((str(c["method"]), str(c["op"]), str(c["target"])) for c in cases)
    # 3 small non-search ops x 4 methods + 2 small searches x 5 methods, 31 reps each;
    # 3 large reads x 4 methods + 1 large search x 5 methods, 6 reps each.
    assert len(cases) == 22 * 31 + 17 * 6
    assert {n for g, n in groups.items() if g[2].startswith("bench/large/huge")} == {6}
    assert not any(c["method"] == "hub_search" and c["op"] != "search" for c in cases)
    for group in groups:
        reps = [c["rep"] for c in cases if (c["method"], c["op"], c["target"]) == group]
        assert sorted(reps) == list(range(len(reps)))  # each rep once
    assert all(c["fresh"] == (c["rep"] == 0) for c in cases)


def test_plan_keeps_each_groups_reps_close_and_randomizes_method_order() -> None:
    # The bench Runtime ends a session after 900 s idle: the reps of one (op, target) run
    # back to back as rounds of all methods, so a warm rep never waits a full plan round.
    cases = run_bench.plan(7)

    def round_of(c: dict[str, object]) -> tuple[object, ...]:
        # A write target names its method; the round is the same template.
        return (c["op"], str(c["target"]).replace(str(c["method"]), "{method}"), c["rep"])

    rounds: list[list[str]] = []
    for index, c in enumerate(cases):
        if index == 0 or round_of(c) != round_of(cases[index - 1]):
            rounds.append([])
        rounds[-1].append(str(c["method"]))
    assert len(rounds) == 5 * 31 + 4 * 6
    assert len({tuple(r) for r in rounds if len(r) == 5}) > 1  # order differs between rounds
    assert run_bench.plan(7) == cases  # reproducible


def test_writes_stay_out_of_the_listed_and_searched_folders() -> None:
    writes = {str(c["target"]) for c in run_bench.plan(7) if c["op"] == "write"}
    assert writes and all(t.startswith("bench/scratch/") for t in writes)


def _manifests(root: Path) -> None:
    bench = root / "evidence/bench"
    bench.mkdir(parents=True)
    small = {
        "files": [{"path": "bench/small/s1.txt", "size": 10}],
        "matches": [["bench/small/s1.txt", 3]],
    }
    large = {
        "files": [
            {"path": "bench/large/huge/h1g_0.txt", "size": 1000},
            {"path": "bench/large/small/f001.txt", "size": 10000},
        ],
        "matches": [["bench/large/huge/h1g_0.txt", 10], ["bench/large/small/f001.txt", 5]],
    }
    (bench / "manifest-small.json").write_text(json.dumps(small))
    (bench / "manifest-large.json").write_text(json.dumps(large))


def test_expected_results_from_the_manifests(tmp_path: Path) -> None:
    _manifests(tmp_path)
    expected = run_bench.expected_results(tmp_path / "evidence/bench")
    assert expected["bench/small|bench/small/*"] == digest([("bench/small/s1.txt", 3)])
    assert expected["bench/large/small|bench/large/small/*"] == digest(
        [("bench/large/small/f001.txt", 5)]
    )
    assert expected["bench/large/huge|bench/large/huge/h5g_0.txt"] == digest([])  # h1g excluded
    assert expected["bench/large"] == digest(
        ["bench/large/huge/h1g_0.txt", "bench/large/small/f001.txt"]
    )
    assert expected["bench/large/small/f001.txt"] == "10000"


CASES: list[dict[str, object]] = [
    {"method": "direct", "op": "read", "target": "bench/large/small/f001.txt", "text": None,
     "rep": rep, "fresh": rep == 0}
    for rep in range(3)
] + [
    {"method": "mirror", "op": "read", "target": "bench/large/small/f001.txt", "text": None,
     "rep": 0, "fresh": True},
]  # fmt: skip


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    _manifests(tmp_path)
    TokenStore().save("a", "api", "tok")
    monkeypatch.setattr(run_bench, "plan", lambda seed: CASES)
    return tmp_path


def _agent(calls: list[dict[str, Any]], answer: Any = None) -> Any:
    def post(url: str, json: dict[str, Any], headers: dict[str, str], timeout: float) -> Any:
        calls.append(json)
        if answer is not None:
            return answer(json)
        case = json["case"]
        result = {
            "method": case["method"], "op": case["op"], "target": case["target"],
            "cold": case["fresh"], "ok": True, "ms": 5.0, "bytes": 10000, "requests": 2,
            "result_count": 10000, "result_digest": "10000", "error": None,
        }  # fmt: skip
        return httpx.Response(200, json={"status": 200, "session_id": "x", "result": result})

    return post


def _rows(root: Path) -> list[dict[str, Any]]:
    lines = (root / "evidence/bench/rows.jsonl").read_text().splitlines()
    return [json.loads(line) for line in lines]


def test_runs_every_case_with_one_session_per_group(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(run_bench.httpx, "post", _agent(calls))
    assert run_bench.main([]) == 0
    direct = [c["session_id"] for c in calls if c["case"]["method"] == "direct"]
    mirror = [c["session_id"] for c in calls if c["case"]["method"] == "mirror"]
    assert len(set(direct)) == 1 and len(direct) == 3 and set(mirror).isdisjoint(direct)
    assert [c["case"]["fresh"] for c in calls] == [True, False, False, True]
    assert set(calls[0]["case"]) == {"method", "op", "target", "text", "fresh"}
    summary = (workdir / "evidence/bench/summary.md").read_text()
    assert "| direct | read |" in summary and "| recorded |" in summary  # 2 warm rows < 20


def test_rerun_skips_successful_rows_and_retries_failures_in_a_new_session(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []

    def flaky(body: dict[str, Any]) -> httpx.Response:
        if body["case"]["method"] == "mirror":
            return httpx.Response(502, json={"error": "runtime_unavailable"})
        return _agent([])(url="", json=body, headers={}, timeout=0)

    monkeypatch.setattr(run_bench.httpx, "post", _agent(calls, flaky))
    assert run_bench.main([]) == 0
    [failed] = [r for r in _rows(workdir) if not r["ok"]]
    assert failed["method"] == "mirror" and failed["error"] == "api:502:runtime_unavailable"
    calls.clear()
    monkeypatch.setattr(run_bench.httpx, "post", _agent(calls))
    assert run_bench.main([]) == 0
    assert [c["case"]["method"] for c in calls] == ["mirror"]
    assert calls[0]["session_id"] != failed["session_id"]
    summary = (workdir / "evidence/bench/summary.md").read_text()
    assert "| mirror | read |" in summary and "| fail |" not in summary  # the retry replaced it


def test_resumed_warm_rep_starts_a_new_session(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(run_bench.httpx, "post", _agent(calls))
    monkeypatch.setattr(run_bench, "plan", lambda seed: CASES[:1])
    assert run_bench.main([]) == 0
    monkeypatch.setattr(run_bench, "plan", lambda seed: CASES[:2])
    assert run_bench.main([]) == 0
    # An earlier run's session (and microVM) is gone: rep 1 starts a new session, fresh.
    assert calls[1]["case"]["fresh"] is True and calls[1]["session_id"] != calls[0]["session_id"]


@pytest.mark.parametrize("status", [401, 403])
def test_caller_auth_failure_stops_the_run(
    workdir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    status: int,
) -> None:  # fmt: skip
    calls: list[dict[str, Any]] = []
    answer = lambda body: httpx.Response(status, json={"error": "token_expired"})  # noqa: E731
    monkeypatch.setattr(run_bench.httpx, "post", _agent(calls, answer))
    assert run_bench.main(["--user", "a"]) == 2
    assert len(calls) == 1 and not (workdir / "evidence/bench/rows.jsonl").exists()
    assert "platform_cli login --user a" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (httpx.Response(200, text="not json"), "api:200:bad_response"),
        (httpx.Response(200, json={"status": 500, "result": {"error": "x"}}), "runtime:500"),
        (httpx.Response(200, json={"status": 200, "result": "text"}), "runtime:200"),
        (httpx.Response(504, json={"error": "runtime_timeout"}), "api:504:runtime_timeout"),
    ],
)
def test_bad_responses_are_failed_rows_in_the_right_group(
    workdir: Path, monkeypatch: pytest.MonkeyPatch, response: httpx.Response, error: str
) -> None:
    monkeypatch.setattr(run_bench, "plan", lambda seed: CASES[:1])
    monkeypatch.setattr(run_bench.httpx, "post", _agent([], lambda body: response))
    assert run_bench.main([]) == 0
    [row] = _rows(workdir)
    assert row["ok"] is False and row["error"] == error
    assert (row["method"], row["op"], row["target"]) == ("direct", "read", CASES[0]["target"])


def test_transport_error_is_a_failed_row(workdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(body: dict[str, Any]) -> httpx.Response:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(run_bench, "plan", lambda seed: CASES[:1])
    monkeypatch.setattr(run_bench.httpx, "post", _agent([], refuse))
    assert run_bench.main([]) == 0
    assert _rows(workdir)[0]["error"] == "transport:ConnectError"


def test_agent_cannot_move_its_row_to_another_group(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def lying(body: dict[str, Any]) -> httpx.Response:
        result = {"method": "mirror", "op": "list", "target": "x", "ok": "yes", "ms": 1}
        return httpx.Response(200, json={"status": 200, "result": result})

    monkeypatch.setattr(run_bench, "plan", lambda seed: CASES[:1])
    monkeypatch.setattr(run_bench.httpx, "post", _agent([], lying))
    assert run_bench.main([]) == 0
    [row] = _rows(workdir)
    assert (row["method"], row["op"], row["ok"]) == ("direct", "read", False)


def test_missing_manifest_stops_before_any_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(run_bench.httpx, "post", _agent(calls))
    assert run_bench.main([]) == 2 and calls == []
    assert "seed_bench_fixtures" in capsys.readouterr().out


def test_a_partial_last_line_does_not_block_resume(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(run_bench.httpx, "post", _agent(calls))
    monkeypatch.setattr(run_bench, "plan", lambda seed: CASES[:2])
    assert run_bench.main([]) == 0
    rows_file = workdir / "evidence/bench/rows.jsonl"
    rows_file.write_text(rows_file.read_text() + '{"key": "cut-off')  # a crash mid-append
    calls.clear()
    monkeypatch.setattr(run_bench, "plan", lambda seed: CASES[:3])
    assert run_bench.main([]) == 0
    assert len(calls) == 1  # the cut-off line is skipped, the two good rows still count
    lines = rows_file.read_text().splitlines()
    assert lines[2] == '{"key": "cut-off' and json.loads(lines[3])["rep"] == 2


def test_rows_belong_to_one_user(workdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    TokenStore().save("b", "api", "tok-b")
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(run_bench.httpx, "post", _agent(calls))
    assert run_bench.main(["--user", "a"]) == 0
    calls.clear()
    assert run_bench.main(["--user", "b"]) == 0
    assert len(calls) == len(CASES)  # A's rows are not B's results
    assert {r["user"] for r in _rows(workdir)} == {"a", "b"}


def test_large_search_targets_the_5_gb_file(tmp_path: Path) -> None:
    # The whole huge folder is 6.55 GB, above the Hub's 6 GiB search cap.
    targets = {str(c["target"]) for c in run_bench.plan(7) if c["op"] == "search"}
    assert "bench/large/huge|bench/large/huge/h5g_0.txt" in targets
    assert "bench/large/huge|bench/large/huge/*" not in targets
    _manifests(tmp_path)
    manifest = tmp_path / "evidence/bench/manifest-large.json"
    data = json.loads(manifest.read_text())
    data["matches"].append(["bench/large/huge/h5g_0.txt", 10])
    manifest.write_text(json.dumps(data))
    expected = run_bench.expected_results(tmp_path / "evidence/bench")
    key = "bench/large/huge|bench/large/huge/h5g_0.txt"
    assert expected[key] == digest([("bench/large/huge/h5g_0.txt", 10)])


def _failing_direct(error: str) -> Any:
    def answer(body: dict[str, Any]) -> httpx.Response:
        if body["case"]["method"] != "direct":
            return _agent([])(url="", json=body, headers={}, timeout=0)
        case = body["case"]
        result = {
            "method": case["method"], "op": case["op"], "target": case["target"],
            "cold": case["fresh"], "ok": False, "ms": 5.0, "error": error,
        }  # fmt: skip
        return httpx.Response(200, json={"status": 200, "session_id": "x", "result": result})

    return answer


@pytest.mark.parametrize(
    "error",
    [
        "OSError: [Errno 28] No space left on device",
        "ResourceTooLarge: bench/large/huge/h5g_0.txt: mirage cat buffers 5000000000 bytes",
        "PermissionError: [Errno 13] Permission denied: '/mnt/ws'",
    ],
)
def test_an_infeasible_error_ends_its_group_and_stays_final_on_resume(
    workdir: Path, monkeypatch: pytest.MonkeyPatch, error: str
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(run_bench.httpx, "post", _agent(calls, _failing_direct(error)))
    assert run_bench.main([]) == 0
    # Rep 0 of direct fails for good: reps 1-2 are skipped, the mirror group still runs.
    assert [(c["case"]["method"], c["case"]["fresh"]) for c in calls] == [
        ("direct", True),
        ("mirror", True),
    ]
    calls.clear()
    assert run_bench.main([]) == 0
    assert calls == []
    summary = (workdir / "evidence/bench/summary.md").read_text()
    assert "| fail |" in summary


def test_other_failed_rows_do_not_end_their_group(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(run_bench.httpx, "post", _agent(calls, _failing_direct("hub:429:unknown")))
    assert run_bench.main([]) == 0
    assert len(calls) == 4


def test_unified_api_500_stops_the_run(
    workdir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[dict[str, Any]] = []
    answer = lambda body: httpx.Response(500, text="Internal Server Error")  # noqa: E731
    monkeypatch.setattr(run_bench.httpx, "post", _agent(calls, answer))
    assert run_bench.main([]) == 2
    assert len(calls) == 1 and not (workdir / "evidence/bench/rows.jsonl").exists()
    assert "aws sso login" in capsys.readouterr().out
