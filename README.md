# t3version

Identify a TYPO3 version from a public URL. No guessing: if no signal
matches, the answer is "Not verified".

Live at https://t3version.woodwolfdigital.com

## How it detects

Two layers:

1. **Live fingerprints**: the homepage generator meta tag, `/typo3temp/`,
   `/typo3conf/` and `/typo3/sysext/` asset URLs, the `/typo3/` backend
   login page, and version-specific public file paths.
2. **Hash database** (`app/hashes.json`): public core asset files from
   TYPO3 source tarballs, hashed per version. Assets referenced by the
   target site are fetched, hashed, and matched against the database.

Scoring: an exact hash match is +10, a version-unique file path is +4,
the backend login page is +3, generic TYPO3 markers are +2 each.
Confidence is high at 10+, medium at 5-9, low below that. A site with
no TYPO3 markers at all is reported as not TYPO3.

## Web UI

Sign in with the admin user, then use the dashboard check form.

## API

```
POST /api/v1/check
X-API-Key: <token>
{"url": "https://example.com"}
```

Returns:

```json
{"url": "...", "is_typo3": true, "version": "v12.4", "confidence": "high", "evidence": ["..."]}
```

`GET /health` returns `{"status": "ok"}` with no auth.

## Configuration (environment only, never committed)

- `ADMIN_USER`
- `ADMIN_PASSWORD`
- `SECRET_KEY`
- `API_TOKEN`

## Rebuilding the hash database

```bash
# downloads tarballs from get.typo3.org into /tmp/typo3-src
python3 scripts/build_hashes.py /tmp/typo3-src
```

The script hashes public core assets and writes `app/hashes.json`.
Raw sources are deleted after hashing; only the hashes JSON is kept.
