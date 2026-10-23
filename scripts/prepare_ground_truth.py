#!/usr/bin/env python3
"""Çok dilli ground-truth kaynak manifesti hazırla veya tamamlanmış paketi doğrula; analiz motorunu çalıştırmaz."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

APP = Path(__file__).resolve().parents[1]
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import ground_truth_review as review  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--root", required=True)
    prepare.add_argument("--project", action="append", required=True)
    prepare.add_argument("--manifest", required=True)
    prepare.add_argument("--ground-truth", required=True)
    prepare.add_argument("--source-profile", action="append", choices=sorted(review.SOURCE_PROFILES),
                         help="Kaynak dili profili; birden çok verilebilir (varsayılan: c_cpp).")
    validate = sub.add_parser("validate")
    validate.add_argument("--root", required=True)
    validate.add_argument("--manifest", required=True)
    validate.add_argument("--ground-truth", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            manifest, _ = review.prepare_bundle(
                args.root, args.project, args.manifest, args.ground_truth,
                source_profiles=args.source_profile,
            )
            result = {"prepared": True, "projects": sorted(manifest["projects"]),
                      "manifest_sha256": review.file_sha256(args.manifest)}
        else:
            result = review.validate_bundle(args.root, args.manifest, args.ground_truth, require_attestation=True)
    except review.GroundTruthReviewError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
