"""TYPO3 version detector.

Two layers, never guesses a version:
  1. Live fingerprints: generator meta tag, /typo3temp/, /typo3conf/,
     /typo3/sysext/ asset URLs, the /typo3/ backend login page, and
     version-specific public file paths.
  2. Hash database: public core asset files from TYPO3 source tarballs,
     hashed per version (see scripts/build_hashes.py). Homepage and login
     page asset URLs are fetched, hashed, and matched against the DB.

Scoring per version:
  exact hash match on a public core asset      +10
  version-unique file exists (path+hash)      +10 (same as a hash match)
  version-specific file path exists            +4
  backend login page loads with TYPO3 markers  +3
  generator meta tag says TYPO3                +2
  /typo3temp/ asset paths in the HTML          +2
  /typo3/sysext/ or /typo3conf/ paths          +2

Confidence: high >= 10, medium 5-9, low 2-4.
No TYPO3 signal at all -> is_typo3 False, version "Not verified".
TYPO3 confirmed but no version signal -> is_typo3 True, version "Not verified".
"""
import hashlib
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
HASHES_PATH = os.path.join(HERE, "hashes.json")

UA = {"User-Agent": "t3version/1.0 (+https://t3version.woodwolfdigital.com)"}
TIMEOUT = 5

# Signals that only confirm TYPO3, not a version.
TYPO3_MARKERS = [
    (re.compile(r'typo3temp/', re.I), "/typo3temp/ asset paths in page"),
    (re.compile(r'typo3conf/', re.I), "/typo3conf/ paths in page"),
    (re.compile(r'typo3/sysext/', re.I), "/typo3/sysext/ paths in page"),
    (re.compile(r'content=["\']TYPO3', re.I), "generator meta tag says TYPO3"),
]

HASH_SCORE = 10
PATH_SCORE = 4
LOGIN_SCORE = 3


def _load_hashes():
    try:
        with open(HASHES_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"generated_at": None, "versions": {}}


HASH_DB = _load_hashes()

# version -> {path: sha256}
_VERSION_FILES = {
    v["minor"]: v["files"] for v in HASH_DB.get("versions", {}).values()
}
# version -> list of probe files {path, sha256} (unique to that version)
_VERSION_PROBES = {
    v["minor"]: v.get("probes", []) for v in HASH_DB.get("versions", {}).values()
}
# sha256 -> set of minors that contain that exact file hash
_HASH_INDEX = {}
for minor, files in _VERSION_FILES.items():
    for path, sha in files.items():
        _HASH_INDEX.setdefault(sha, set()).add(minor)


def _fetch(session, url):
    try:
        r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        return r
    except requests.RequestException:
        return None


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _normalize_url(url):
    url = url.strip()
    if not url:
        return None
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    return url


def _asset_paths(html, base_url):
    """Asset URL paths referenced by a page (same-host typo3 paths only)."""
    paths = set()
    for m in re.finditer(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', html, re.I):
        raw = m.group(1)
        if not raw or raw.startswith(("data:", "mailto:", "tel:", "#", "javascript:")):
            continue
        full = urljoin(base_url, raw)
        p = urlparse(full)
        if p.netloc and p.netloc.lower() != urlparse(base_url).netloc.lower():
            continue
        if "/typo3/" in p.path or p.path.startswith("/typo3temp/"):
            paths.add(p.path)
    return sorted(paths)[:40]


def detect(url):
    started = time.time()
    url = _normalize_url(url)
    if not url:
        return {"url": url or "", "is_typo3": False, "version": "Not verified",
                "confidence": "none", "evidence": ["empty or invalid URL"]}
    parsed = urlparse(url)
    if not parsed.netloc:
        return {"url": url, "is_typo3": False, "version": "Not verified",
                "confidence": "none", "evidence": ["invalid URL, no host"]}

    session = requests.Session()
    session.headers.update(UA)
    evidence = []
    scores = {}
    typo3_signals = 0

    def add_score(minor, points, note):
        scores[minor] = scores.get(minor, 0) + points
        evidence.append(note)

    # --- Layer 1: homepage fingerprints -----------------------------------
    home = _fetch(session, url)
    if home is None:
        return {"url": url, "is_typo3": False, "version": "Not verified",
                "confidence": "none",
                "evidence": ["site did not respond (connection error or timeout)"]}
    if home.status_code >= 400:
        return {"url": url, "is_typo3": False, "version": "Not verified",
                "confidence": "none",
                "evidence": [f"site returned HTTP {home.status_code}"]}
    html = home.text
    evidence.append(f"homepage returned HTTP {home.status_code}")
    for pattern, note in TYPO3_MARKERS:
        if pattern.search(html):
            typo3_signals += 1
            evidence.append(note)

    # --- Layer 2a: hash-match assets referenced by the homepage -----------
    asset_urls = _asset_paths(html, url)
    hash_hits = []

    def _hash_asset(path):
        full = urljoin(url, path)
        r = _fetch(session, full)
        if r is None or r.status_code != 200 or not r.content:
            return None
        sha = _sha256(r.content)
        minors = _HASH_INDEX.get(sha)
        if minors:
            return (path, sha, sorted(minors))
        return None

    if asset_urls:
        with ThreadPoolExecutor(max_workers=10) as pool:
            for hit in pool.map(_hash_asset, asset_urls):
                if hit:
                    hash_hits.append(hit)
        for path, sha, minors in hash_hits:
            for minor in minors:
                add_score(minor, HASH_SCORE,
                          f"asset {path} hash matches TYPO3 {minor}")
            typo3_signals += 1

    # --- Layer 1b: backend login page --------------------------------------
    login_url = urljoin(url, "/typo3/")
    login = _fetch(session, login_url)
    login_html = ""
    login_assets = []
    if login is not None and login.status_code == 200:
        login_html = login.text
        if re.search(r"TYPO3", login_html, re.I) or "/typo3/sysext/" in login_html:
            typo3_signals += 1
            add_score("__typo3__", LOGIN_SCORE,
                      "backend login page /typo3/ loads with TYPO3 markers")
            login_assets = [p for p in _asset_paths(login_html, url)
                            if p not in asset_urls]

    # Hash-match the login page assets too (same worker as above).
    if login_assets:
        with ThreadPoolExecutor(max_workers=10) as pool:
            for hit in pool.map(_hash_asset, login_assets):
                if hit:
                    path, sha, minors = hit
                    for minor in minors:
                        add_score(minor, HASH_SCORE,
                                  f"asset {path} hash matches TYPO3 {minor}")
                    typo3_signals += 1

    # --- Layer 2b: probe version-unique files ------------------------------
    probes = []  # (minor, path, sha256, unique_path)
    for minor, plist in _VERSION_PROBES.items():
        for p in plist[:3]:
            probes.append((minor, p["path"], p["sha256"],
                           p.get("unique_path", False)))

    def _probe(item):
        minor, path, want_sha, unique_path = item
        full = urljoin(url, "/" + path.lstrip("/"))
        r = _fetch(session, full)
        if r is None or r.status_code != 200 or not r.content:
            return None
        if _sha256(r.content) == want_sha:
            return (minor, path, "hash")
        if unique_path:
            return (minor, path, "exists")
        return None

    if probes:
        with ThreadPoolExecutor(max_workers=10) as pool:
            for hit in pool.map(_probe, probes):
                if not hit:
                    continue
                minor, path, kind = hit
                if kind == "hash":
                    add_score(minor, HASH_SCORE,
                              f"file {path} exists and hash matches TYPO3 {minor}")
                    typo3_signals += 1
                else:
                    add_score(minor, PATH_SCORE,
                              f"file {path} exists (TYPO3 {minor} only path)")
                    typo3_signals += 1

    # --- Decide -------------------------------------------------------------
    scores.pop("__typo3__", None)
    best_minor = None
    best_score = 0
    for minor, score in sorted(scores.items()):
        if score > best_score:
            best_score = score
            best_minor = minor

    is_typo3 = typo3_signals > 0 or bool(scores)
    if not is_typo3:
        evidence.append("no TYPO3 markers found on homepage, login page, or probed files")
        return {"url": url, "is_typo3": False, "version": "Not verified",
                "confidence": "none", "evidence": evidence}

    if best_minor is None or best_score < 2:
        evidence.append("TYPO3 confirmed but no version signal matched")
        return {"url": url, "is_typo3": True, "version": "Not verified",
                "confidence": "low", "evidence": evidence}

    if best_score >= 10:
        confidence = "high"
    elif best_score >= 5:
        confidence = "medium"
    else:
        confidence = "low"
    evidence.append(f"checked in {time.time() - started:.1f}s, "
                    f"hash DB covers {len(_VERSION_FILES)} versions")
    return {"url": url, "is_typo3": True, "version": "v" + best_minor,
            "confidence": confidence, "evidence": evidence}


def hash_db_versions():
    """Minor versions covered by the hash DB, sorted oldest to newest."""
    def key(m):
        return tuple(int(x) for x in m.split("."))
    return sorted(_VERSION_FILES.keys(), key=key)
