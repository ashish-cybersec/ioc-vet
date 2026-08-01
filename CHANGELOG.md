# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release dates are on the [releases page](https://github.com/ashish-cybersec/ioc-vet/releases).

## [0.4.1] — 2026-08-01

### Documentation

- Added this changelog, covering every release from 0.1.0.
- README now leads with defanged-IOC and IDN support, the two features most
  likely to matter day to day, and shows real output from a live lookup instead
  of a hand-written example.
- Roadmap corrected: SQLite caching and CSV export were both shipped but still
  listed as pending. Speculative items are now separated from planned ones so
  the list reflects actual intent.

## [0.4.0] — 2026-08-01

### Added

- **On-disk result cache** (`~/.cache/iocvet/cache.db`, override with
  `IOCVET_CACHE_DIR`). A nightly cron job or CI pipeline re-checking the same
  indicators no longer re-spends its free-tier allowance on answers it already
  has. Entries are cached per provider and expire after 24 hours by default.
- `--no-cache`, `--refresh`, and `--cache-ttl SECONDS` on `lookup` and `batch`.
- `iocvet cache stats` and `iocvet cache clear`.

### Notes on cache behaviour

- **Errors, rate limits, and skipped providers are never cached.** An error is
  transient — caching a 500 would let one upstream blip silently degrade every
  lookup until it expired. A skip is configuration state, not data: caching
  "no API key configured" would mean adding a key appears to do nothing.
- The database runs in **WAL mode** so several `iocvet` processes can share it.
  Under the previous default journal, 8 of 12 concurrent processes lost their
  cache entirely to `database is locked` — a realistic scenario when a cron job
  and an analyst run at the same time.
- Entries stamped in the future (clock jumps, restored backups) are treated as
  unusable rather than never expiring.
- Capped at 50,000 entries, oldest evicted first, so a large feed can't grow the
  file without bound.
- A cache that can't be opened, is corrupt, or fails mid-run degrades to no
  caching rather than failing the lookup.

### Security

- Cache file created `0600` in a `0700` directory, including the WAL sidecars —
  it records which indicators were investigated.
- Symlinked cache paths are refused.

## [0.3.0]

### Added

- **Internationalised domain (IDN) support.** `münchen.de`, `россия.рф`, and
  `例え.jp` are accepted in their human-readable form and canonicalised to
  punycode. Homograph and lookalike domains are a live phishing vector, so
  rejecting them was a real gap.
- **CSV export for batch runs**: `iocvet batch iocs.txt --csv -o results.csv`,
  one row per (IOC, provider).
- `--output/-o` for writing results to a file.

### Security

- **CSV formula injection protection (CWE-1236).** Provider-returned text
  (threat names, ISP and organisation strings) is attacker-influenceable. A cell
  beginning with `=`, `+`, `-`, or `@` would execute as a formula when the file
  was opened in Excel or LibreOffice. Such cells are now escaped.

### Fixed

- Unicode, uppercase, punycode, and trailing-dot forms of the same domain now
  collapse to a single cache key instead of being queried separately.

## [0.2.0]

### Added

- **Defanged IOC support.** `evil[.]com`, `hxxp://evil[.]com`, and
  `1[.]2[.]3[.]4` can be pasted straight from a ticket or report.
- Domain enrichment via **RDAP** (registration data, no API key) and URLhaus
  host lookups.
- URLhaus IPv4 host lookups.
- `--fail-on-error` (exit 3) for security gates that must fail closed when no
  provider could reach a conclusion.
- Documented exit-code taxonomy (0/1/2/3).

### Fixed

- **URLhaus hash lookups never worked.** Payloads were queried with a generic
  `hash` parameter instead of `md5_hash`/`sha256_hash`, so every hash — real
  malware included — came back "not found".
- **AbuseIPDB flagged clean addresses as suspicious.** Any address with a single
  stale report was marked suspicious regardless of its confidence score,
  including well-known public resolvers. The score now drives the verdict and
  the whitelist is honoured.
- `import tomllib` broke the install on Python 3.10, which the package claims to
  support.
- Batch mode had no rate limiting and would trip ip-api's 45 requests/minute
  cap, risking a temporary ban.
- A typo'd IOC exited 0, so a malformed indicator could silently pass a CI gate.
- `lookup` printed errors to stdout, corrupting `--json` output in a pipe.
- Malformed `config.toml` produced a raw traceback.
- Batch files with a UTF-8 BOM silently dropped the first indicator; non-UTF-8
  files crashed.

### Security

- **Private and reserved IPs are never sent to external providers** — RFC1918,
  loopback, link-local (including cloud metadata `169.254.169.254`), and
  reserved ranges. Sending them disclosed internal network structure to a third
  party.
- Config file permissions tightened to `0600` in a `0700` directory.
- Symlinked config paths are refused.
- Oversized input is rejected before parsing.

## [0.1.0]

### Added

- Initial release: `lookup`, `batch`, `providers`, and `configure` commands.
- Providers: ip-api, AbuseIPDB, URLhaus.
- Automatic IOC type detection for IPs, domains, URLs, and MD5/SHA1/SHA256
  hashes.
- Parallel provider queries with a unified verdict.
- `--json` output and `--fail-on-malicious` for CI use.

[0.4.1]: https://github.com/ashish-cybersec/ioc-vet/releases/tag/v0.4.1
[0.4.0]: https://github.com/ashish-cybersec/ioc-vet/releases/tag/v0.4.0
[0.3.0]: https://github.com/ashish-cybersec/ioc-vet/releases/tag/v0.3.0
[0.2.0]: https://github.com/ashish-cybersec/ioc-vet/releases/tag/v0.2.0
[0.1.0]: https://github.com/ashish-cybersec/ioc-vet/releases/tag/v0.1.0
