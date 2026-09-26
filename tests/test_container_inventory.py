from __future__ import annotations

from pathlib import Path
from typing import Any

from agentcore_runtime_poc.inventory import (
    container_inventory,
    load_inventory,
    new_resources,
    save_inventory,
)


class FakePaginated:
    def __init__(self, operation: str, pages: list[dict[str, Any]]) -> None:
        self.operation = operation
        self.pages = pages

    def get_paginator(self, name: str) -> FakePaginated:
        assert name == self.operation
        return self

    def paginate(self) -> list[dict[str, Any]]:
        return self.pages


def test_inventory_reads_every_page() -> None:
    ecr = FakePaginated(
        "describe_repositories",
        [
            {"repositories": [{"repositoryName": "b"}]},
            {"repositories": [{"repositoryName": "a"}]},
        ],
    )
    codebuild = FakePaginated("list_projects", [{"projects": ["p1"]}, {"projects": ["p2"]}])

    assert container_inventory(ecr, codebuild) == {
        "ecr_repositories": ["a", "b"],
        "codebuild_projects": ["p1", "p2"],
    }


def test_new_resources_ignores_pre_existing_ones() -> None:
    before = {"ecr_repositories": ["team-repo"], "codebuild_projects": []}
    after = {"ecr_repositories": ["team-repo", "bedrock-agentcore-x"], "codebuild_projects": ["p"]}

    assert new_resources(before, after) == {
        "ecr_repositories": ["bedrock-agentcore-x"],
        "codebuild_projects": ["p"],
    }


def test_inventory_round_trips_through_a_file(tmp_path: Path) -> None:
    path = tmp_path / "raw" / "before.json"
    inventory = {"ecr_repositories": ["a"], "codebuild_projects": []}

    save_inventory(path, inventory)

    assert load_inventory(path) == inventory
