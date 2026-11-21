#!/usr/bin/env python3
"""Build app/hashes.json from TYPO3 source tarballs.

Downloads tarballs from get.typo3.org (latest patch per minor), extracts
them to a temp dir, hashes public core asset files, and writes a small
hashes.json. Raw sources are deleted afterwards; only hashes.json is kept.

Usage: python3 scripts/build_hashes.py [tarball_dir]
Default tarball dir: /tmp/typo3-src
"""
import hashlib
import json
import os
import shutil
import sys
import tarfile
import tempfile
from datetime import datetime, timezone

VERSIONS = {
    # minor: (earliest patch, latest patch). Files are kept only when their
    # hash is identical in both, so they match any patch in the branch.
    "4.5": ("4.5.0", "4.5.40"),
    "6.2": ("6.2.0", "6.2.31"),
    "9.5": ("9.5.0", "9.5.31"),
    "10.4": ("10.4.0", "10.4.37"),
    "11.5": ("11.5.0", "11.5.41"),
    "12.4": ("12.4.0", "12.4.45"),
    "13.1": ("13.1.0", "13.1.1"),
    "13.4": ("13.4.0", "13.4.40"),
    "14.3": ("14.3.0", "14.3.12"),
}

# Public asset extensions worth hashing.
EXTS = {".js", ".css", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map"}
MAX_FILE_SIZE = 200 * 1024
MAX_FILES_PER_VERSION = 200


def public_asset_files(root):
    """Yield (rel_path, full_path) for public core asset files in a source tree."""
    typo3_dir = os.path.join(root, "typo3")
    if not os.path.isdir(typo3_dir):
        return
    for dirpath, dirnames, filenames in os.walk(typo3_dir):
        dirnames[:] = [d for d in dirnames if d not in ("Tests", "Documentation")]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in EXTS:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            # Only files that are served publicly: Resources/Public, or the
            # legacy public skin dirs of old versions.
            if ("Resources/Public/" in rel or "/res/" in rel or
                    "t3skin/" in rel or "sysext/cms/tslib/" in rel or
                    "contrib/" in rel):
                try:
                    if os.path.getsize(full) <= MAX_FILE_SIZE:
                        yield rel, full
                except OSError:
                    continue


def pick_files(candidates):
    """Deterministic subset: prefer short paths, mix extensions, cap count."""
    cands = sorted(set(candidates), key=lambda c: (len(c[0]), c[0]))
    picked = []
    seen_ext = {}
    for rel, full in cands:
        ext = os.path.splitext(rel)[1].lower()
        # Keep at most 60 files per extension so one type does not dominate.
        if seen_ext.get(ext, 0) >= 60:
            continue
        seen_ext[ext] = seen_ext.get(ext, 0) + 1
        picked.append((rel, full))
        if len(picked) >= MAX_FILES_PER_VERSION:
            break
    return picked


def hash_tarball(tarball):
    """Return {rel_path: sha256} for public asset files in one tarball."""
    tmp = tempfile.mkdtemp(prefix="typo3-hash-")
    try:
        with tarfile.open(tarball, "r:gz") as tf:
            tf.extractall(tmp)
        dirs = [d for d in os.listdir(tmp)
                if os.path.isdir(os.path.join(tmp, d))]
        top = os.path.join(tmp, dirs[0]) if dirs else tmp
        cands = list(public_asset_files(top))
        picked = pick_files(cands)
        files = {}
        for rel, full in picked:
            with open(full, "rb") as f:
                files[rel] = hashlib.sha256(f.read()).hexdigest()
        return files, len(cands)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    tarball_dir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/typo3-src"
    out_path = os.path.join(os.path.dirname(__file__), "..", "app", "hashes.json")
    out_path = os.path.normpath(out_path)

    versions_out = {}
    skipped = []
    for minor, (early, late) in VERSIONS.items():
        early_tb = os.path.join(tarball_dir, f"typo3_src-{early}.tar.gz")
        late_tb = os.path.join(tarball_dir, f"typo3_src-{late}.tar.gz")
        if not os.path.exists(early_tb) or not os.path.exists(late_tb):
            print(f"{minor}: missing tarball(s), skipped")
            skipped.append(minor)
            continue
        early_files, early_n = hash_tarball(early_tb)
        late_files, late_n = hash_tarball(late_tb)
        # Keep only files identical in both patches: stable across the branch.
        stable = {p: s for p, s in late_files.items()
                  if early_files.get(p) == s}
        if len(stable) < 20:
            # Too few stable files; fall back to latest-patch files.
            print(f"{minor}: only {len(stable)} stable files, "
                  f"falling back to latest-patch set")
            stable = late_files
        versions_out[minor] = {
            "minor": minor,
            "patch_early": early,
            "patch_late": late,
            "source": f"https://get.typo3.org/{late}",
            "files": stable,
        }
        print(f"{minor} ({early} vs {late}): {len(stable)} stable files "
              f"(from {early_n}/{late_n} candidates)")

    # Probes: files whose (path, hash) is unique to one version, up to 4 each.
    # Each probe records whether its path exists in only that version:
    # only a unique path earns "exists" points, a shared path only counts
    # when the hash matches exactly.
    path_hash_owners = {}
    for minor, v in versions_out.items():
        for path, sha in v["files"].items():
            path_hash_owners.setdefault((path, sha), []).append(minor)
    path_owners = {}
    for m2, v2 in versions_out.items():
        for path in v2["files"]:
            path_owners.setdefault(path, []).append(m2)
    for minor, v in versions_out.items():
        probes = []
        unique_paths = [p for p in v["files"] if len(path_owners.get(p, [])) == 1]
        unique_hashes = [p for p in v["files"]
                         if len(path_hash_owners.get((p, v["files"][p]), [])) == 1]
        for path in sorted(set(unique_paths + unique_hashes))[:4]:
            probes.append({"path": path, "sha256": v["files"][path],
                           "unique_path": path in unique_paths})
        # Fall back to any 4 files if nothing is unique (identical assets).
        if not probes:
            for path in sorted(v["files"])[:4]:
                probes.append({"path": path, "sha256": v["files"][path],
                               "unique_path": False})
        v["probes"] = probes

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "versions": versions_out,
        "skipped": skipped,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    print(f"wrote {out_path}: {len(versions_out)} versions, skipped={skipped}")
    print(f"size: {os.path.getsize(out_path) / 1024:.0f} KB")


if __name__ == "__main__":
    main()
