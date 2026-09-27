"""App CD pipeline: build, upload, and update one component. Rollback: --version-id <old>."""

from __future__ import annotations

import argparse
from pathlib import Path

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError

from agentcore_platform_poc.deploy import DeployError, deploy_lambda, deploy_runtime
from scripts.build_component_zip import build
from scripts.terraform_outputs import load_terraform_outputs

ROOT = Path("infra/terraform/platform")
# probe deploys into the research runtime slot (Task 6); research replaces it later.
RUNTIME_OUTPUT = {
    "research": "research_runtime_id",
    "probe": "research_runtime_id",
    "bench": "bench_runtime_id",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=["research", "bench", "probe", "resource-hub"])
    parser.add_argument("--version-id", help="redeploy an existing S3 object version (rollback)")
    args = parser.parse_args(argv)
    outputs = load_terraform_outputs(ROOT)
    region = outputs["aws_region"]
    bucket = outputs["code_bucket"]
    key = f"releases/{args.component}.zip"
    zip_path = None if args.version_id else build(args.component)
    s3 = boto3.client("s3", region_name=region)
    try:
        if args.component == "resource-hub":
            result = deploy_lambda(
                boto3.client("lambda", region_name=region),
                s3,
                function_name=outputs["resource_hub_function_name"],
                bucket=bucket,
                key=key,
                zip_path=zip_path,
                version_id=args.version_id,
            )
        else:
            result = deploy_runtime(
                boto3.client("bedrock-agentcore-control", region_name=region),
                s3,
                runtime_id=outputs[RUNTIME_OUTPUT[args.component]],
                bucket=bucket,
                key=key,
                zip_path=zip_path,
                version_id=args.version_id,
            )
    except DeployError as error:
        print(f"deploy failed: {error}")
        return 1
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "AWS error")
        print(f"deploy failed: AWS {code}")
        return 1
    except BotoCoreError as error:
        print(f"deploy failed: AWS {type(error).__name__}")
        return 1
    print(
        f"deployed {args.component}: s3 version {result.version_id}, "
        f"runtime version {result.runtime_version}"
    )
    print(
        "rollback: .venv/bin/python -m scripts.deploy_agent "
        f"{args.component} --version-id <previous version>"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
