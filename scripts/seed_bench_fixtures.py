"""Seed benchmark fixtures straight to S3 (admin path; not what the benchmark measures)."""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import boto3  # type: ignore[import-untyped]

from agentcore_platform_poc.bench_fixtures import (
    BLOCK_BYTES,
    HEAD_PART_BYTES,
    huge_parts,
    large_workspace,
    manifest,
    small_workspace,
    text,
)
from scripts.terraform_outputs import load_terraform_outputs

BLOCK_KEY = "fixtures/block-100MiB.txt"


def _huge(
    s3: Any, bucket: str, key: str, spec_seed: str, size: int, needles: tuple[int, ...]
) -> None:
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    target = {"Bucket": bucket, "Key": key, "UploadId": upload_id}
    try:
        parts = []
        for number, (kind, length) in enumerate(huge_parts(size), start=1):
            if kind == "head":
                body = text(spec_seed, HEAD_PART_BYTES, needles)
                etag = s3.upload_part(**target, PartNumber=number, Body=body)["ETag"]
            else:
                etag = s3.upload_part_copy(
                    **target,
                    PartNumber=number,
                    CopySource={"Bucket": bucket, "Key": BLOCK_KEY},
                    CopySourceRange=f"bytes=0-{length - 1}",
                )["CopyPartResult"]["ETag"]
            parts.append({"PartNumber": number, "ETag": etag})
        s3.complete_multipart_upload(**target, MultipartUpload={"Parts": parts})
    except BaseException:
        # Uploaded parts are billed until the upload is completed or aborted.
        s3.abort_multipart_upload(**target)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user-oid", required=True)
    parser.add_argument("--workspace", choices=["small", "large"], required=True)
    args = parser.parse_args(argv)
    outputs = load_terraform_outputs(Path("infra/terraform/platform"))
    s3 = boto3.client("s3", region_name=outputs["aws_region"])
    bucket = outputs["workspace_bucket"]
    files = small_workspace() if args.workspace == "small" else large_workspace()
    if args.workspace == "large":
        s3.put_object(Bucket=bucket, Key=BLOCK_KEY, Body=text("block", BLOCK_BYTES))
    prefix = f"users/{args.user_oid}/"

    def put(spec: object) -> None:
        path, size, needles = spec.path, spec.size, spec.needle_lines  # type: ignore[attr-defined]
        if size > 5_000_000:
            _huge(s3, bucket, prefix + path, path, size, needles)
        else:
            s3.put_object(Bucket=bucket, Key=prefix + path, Body=text(path, size, needles))

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(put, files))
    out = Path(f"evidence/bench/manifest-{args.workspace}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest(files), indent=1))
    print(f"seeded {len(files)} files under {prefix}bench/; manifest {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
