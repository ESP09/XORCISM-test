#!/usr/bin/env python3
"""Helm post-renderer: rewrite every container image to its digest-pinned mirror in the internal
GitLab Container Registry (from deploy/images.lock.json). Unknown images fail the render, so nothing
can be pulled from a public registry.

    helm upgrade --install defectdojo defectdojo/defectdojo --version <pinned> \
      -f deploy/values.yaml --post-renderer deploy/post-renderer/mirror-images.py
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LOCK = os.environ.get("IMAGES_LOCK") or os.path.join(HERE, "..", "images.lock.json")
IMAGE_LINE = re.compile(r'^(\s*-?\s*image:\s*)(["\']?)([^\s"\']+)\2\s*$')


def canonical(ref: str) -> str:
    ref = ref.strip()
    first = ref.split("/", 1)[0]
    if "/" not in ref:
        ref = "docker.io/library/" + ref
    elif "." not in first and ":" not in first and first != "localhost":
        ref = "docker.io/" + ref
    last = ref.rsplit("/", 1)[-1]
    if ":" not in last and "@" not in last:
        ref += ":latest"
    return ref


def main() -> int:
    with open(LOCK, encoding="utf-8") as fh:
        lock = json.load(fh)
    registry = lock["registry"].rstrip("/")
    mapping = {canonical(k): v for k, v in lock["images"].items()}
    out, missing = [], []
    for line in sys.stdin.read().splitlines():
        m = IMAGE_LINE.match(line)
        if m:
            ref = m.group(3)
            if ref.startswith(registry + "/") and "@sha256:" in ref:
                out.append(line)
                continue
            target = mapping.get(canonical(ref))
            if not target:
                missing.append(ref)
                out.append(line)
                continue
            line = f"{m.group(1)}{m.group(2)}{target}{m.group(2)}"
        out.append(line)
    if missing:
        sys.stderr.write("post-renderer: images missing from images.lock.json (run scripts/mirror_images.py): "
                         + ", ".join(sorted(set(missing))) + "\n")
        return 1
    sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
