"""Mirror pinned upstream images into the internal GitLab Container Registry and write the lock file
consumed by the Helm post-renderer (``deploy/post-renderer/mirror-images.py``).

    mirror_images.py --images deploy/images.json --lock deploy/images.lock.json [--dry-run]

``images.json``: {"registry": "registry.gitlab.example/secops/mirror",
                  "images": [{"source": "docker.io/defectdojo/defectdojo-django:2.x.y", "name": "defectdojo-django"}]}
Uses ``skopeo`` (``skopeo copy --all --preserve-digests`` then ``skopeo inspect`` for the digest).
CA trust for skopeo comes from the combined bundle (``--src-cert-dir``/system store), never ``--tls-verify=false``.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from typing import Any, Dict

from common import utc_now, write_json


def run(cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def mirror(spec: Dict[str, Any], dry: bool) -> Dict[str, Any]:
    reg = spec["registry"].rstrip("/")
    out = {"generated": utc_now(), "registry": reg, "images": {}}
    if not dry and not shutil.which("skopeo"):
        raise SystemExit("skopeo is required to mirror images")
    for img in spec["images"]:
        src = img["source"]
        tag = src.rsplit(":", 1)[-1] if ":" in src.split("/")[-1] else "latest"
        dest = f"{reg}/{img['name']}:{tag}"
        if dry:
            digest = img.get("digest") or "sha256:" + "0" * 64
        else:
            run(["skopeo", "copy", "--all", "--preserve-digests", f"docker://{src}", f"docker://{dest}"])
            digest = json.loads(run(["skopeo", "inspect", f"docker://{dest}"]))["Digest"]
        out["images"][src] = f"{reg}/{img['name']}@{digest}"
    return out


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--images", required=True)
    ap.add_argument("--lock", required=True)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    lock = mirror(json.load(open(a.images, encoding="utf-8")), a.dry_run)
    write_json(a.lock, lock)
    print(json.dumps({"mirrored": len(lock["images"]), "lock": a.lock}))
