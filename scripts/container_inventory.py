"""Snapshot ECR repositories and CodeBuild projects before a deploy (for Q2.6)."""

from __future__ import annotations

import os
from pathlib import Path

import boto3  # type: ignore[import-untyped]

from agentcore_runtime_poc.inventory import container_inventory, save_inventory

BEFORE_PATH = Path("evidence/raw/container-inventory-before.json")


def main() -> int:
    region = os.environ["AWS_REGION"]
    inventory = container_inventory(
        boto3.client("ecr", region_name=region), boto3.client("codebuild", region_name=region)
    )
    save_inventory(BEFORE_PATH, inventory)
    print(f"{BEFORE_PATH}: {', '.join(f'{k}={len(v)}' for k, v in inventory.items())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
