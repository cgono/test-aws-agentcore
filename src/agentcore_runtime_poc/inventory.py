"""Paginated inventory of container-build resources, compared before and after a deploy."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

KEYS = ("ecr_repositories", "codebuild_projects")


def container_inventory(ecr: Any, codebuild: Any) -> dict[str, list[str]]:
    repositories = [
        repo["repositoryName"]
        for page in ecr.get_paginator("describe_repositories").paginate()
        for repo in page.get("repositories", [])
    ]
    projects = [
        name
        for page in codebuild.get_paginator("list_projects").paginate()
        for name in page.get("projects", [])
    ]
    return {"ecr_repositories": sorted(repositories), "codebuild_projects": sorted(projects)}


def new_resources(
    before: Mapping[str, list[str]], after: Mapping[str, list[str]]
) -> dict[str, list[str]]:
    return {key: sorted(set(after.get(key, [])) - set(before.get(key, []))) for key in KEYS}


def save_inventory(path: Path, inventory: Mapping[str, list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(inventory), indent=2, sort_keys=True), encoding="utf-8")


def load_inventory(path: Path) -> dict[str, list[str]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {key: [str(name) for name in raw.get(key, [])] for key in KEYS}
