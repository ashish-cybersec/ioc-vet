# ioc-vet

[![PyPI](https://img.shields.io/pypi/v/ioc-vet)](https://pypi.org/project/ioc-vet/)
[![Python](https://img.shields.io/pypi/pyversions/ioc-vet)](https://pypi.org/project/ioc-vet/)
[![CI](https://github.com/ashish-cybersec/ioc-vet/actions/workflows/ci.yml/badge.svg)](https://github.com/ashish-cybersec/ioc-vet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Changelog](https://img.shields.io/badge/changelog-md-blue)](CHANGELOG.md)

Multi-source IOC enrichment from your terminal. Drop in an IP, domain, URL, or file hash — get back a unified verdict pulled from multiple threat intel sources in parallel, instead of opening five browser tabs.

**Paste indicators exactly as they arrive.** Defanged IOCs from a ticket, an
email, or a threat report work as-is — no manual cleanup:

```
$ iocvet lookup 'hxxp://evil[.]com/payload.exe'
Refanged input → http://evil.com/payload.exe
```

Here's a real lookup against a live compromised host, pulled from URLhaus's
own feed. The hostname is redacted — it's a small business that was breached,
not an attacker, and it has presumably been cleaned up since:

```
$ iocvet lookup redacted-clinic.example

╭──────────────────────────────────────────────╮
│ redacted-clinic.example  [domain]  MALICIOUS │
╰──────────────────────────────────────────────╯
Provider   Verdict      Summary                                         Latency
ip-api     skipped      does not support IOC type 'domain'                    —
abuseipdb  skipped      does not support IOC type 'domain'                    —
rdap       UNKNOWN      registration date not published · Example         641ms
                        Domains Inc.
urlhaus    MALICIOUS    2 malware URL(s) currently online, 2 recorded     499ms
                        — blacklisted: spamhaus_dbl, surbl

rdap → https://client.rdap.org/?type=domain&object=redacted-clinic.example
urlhaus → https://urlhaus.abuse.ch/host/redacted-clinic.example/
```

A legitimate medical practice's website, compromised and serving malware. Two
providers answered, one found it, and the overall verdict follows the worst
finding — which is why "clean" from a single source isn't good enough.

## Why this exists

Most tools in this space are built to be clicked, not scripted. Browser extensions and note-taking plugins solve the same problem, but they only run while a human is looking at a screen — and the ones that go further usually paywall the providers that actually matter (AbuseIPDB, URLhaus) behind a paid tier.

ioc-vet is built for the other half of the job: the part that runs in a CI pipeline, a cron job checking yesterday's suspicious IPs, or a one-line `grep | iocvet batch` over last night's logs. It works out of the box with zero API keys, gets better as you add free ones, and every provider it supports is free — there's no Pro tier holding anything back.

## What it does

- **Accepts defanged indicators** — `evil[.]com`, `hxxp://…`, `1[.]2[.]3[.]4`,
  `evil[dot]com`. Paste from a ticket without editing.
- **Handles internationalised domains** — `münchen.de`, `россия.рф`, `例え.jp`.
  Homograph domains are a phishing staple, so they can't be a blind spot.
- **Auto-detects the type** — IPv4/IPv6, domain, URL, MD5/SHA1/SHA256.
- **Queries providers in parallel** and merges them into one verdict.
- **Caches on disk** so a nightly job doesn't re-spend its API quota.
- **Built for pipelines** — `--json`, `--csv`, and distinct exit codes so a CI
  gate can fail closed.
- **Never sends your internal IPs to a third party** — RFC1918 and cloud
  metadata addresses are recognised and skipped.
- **Zero API keys required** to start; every provider it supports has a free
  tier, and there's no Pro version withholding features.

## Install

```bash
pip install ioc-vet
```

Or from source:

```bash
git clone https://github.com/ashish-cybersec/ioc-vet
cd ioc-vet
pip install -e .
```

## Usage

```bash
# Single lookup, pretty terminal output
iocvet lookup 8.8.8.8

# Works on domains, URLs, and hashes too — type is auto-detected
iocvet lookup example.com
iocvet lookup https://example.com/payload.exe
iocvet lookup 44d88612fea8a8f36de82e1278abb02f

# Defanged IOCs — paste them straight from a ticket or report
iocvet lookup 'evil[.]com'
iocvet lookup 'hxxp://evil[.]com/malware.exe'
iocvet lookup '1[.]2[.]3[.]4'

# Machine-readable output for scripts/pipelines
iocvet lookup 8.8.8.8 --json

# Batch mode: one IOC per line
iocvet batch suspicious_ips.txt

# Batch to CSV for a spreadsheet (one row per IOC/provider)
iocvet batch suspicious_ips.txt --csv -o results.csv

# Results are cached on disk, so a nightly cron job doesn't re-spend quota
iocvet batch suspicious_ips.txt          # second run answers from cache
iocvet batch suspicious_ips.txt --refresh   # force fresh data
iocvet batch suspicious_ips.txt --no-cache  # bypass the cache entirely
iocvet cache stats                          # what's cached, and where
iocvet cache clear                          # wipe it

# Internationalised domains work — pasted in their human-readable form
iocvet lookup münchen.de

# Exit code 1 if malicious — useful in CI or alerting pipelines
iocvet lookup 1.2.3.4 --fail-on-malicious

# See what's configured
iocvet providers
```

## Providers

| Provider  | IOC types                  | API key needed? |
|-----------|----------------------------|-----------------|
| ip-api    | IP                         | No — works immediately (non-commercial use only) |
| AbuseIPDB | IP                         | Yes, free (1,000 checks/day) — [sign up](https://www.abuseipdb.com/register) |
| RDAP      | Domain                     | No — works immediately |
| URLhaus   | IP, domain, URL, file hash | Yes, free — [sign up](https://auth.abuse.ch/) |

> **Note on ip-api:** the free endpoint is [non-commercial use only](https://ip-api.com/docs/legal) and rate-limited to 45 requests/minute. If you're running iocvet at work or in a company CI pipeline, you need their paid tier — or drop ip-api and rely on the other providers.

## Exit codes

`iocvet` uses distinct exit codes so pipelines can branch on them:

| Code | Meaning |
|------|---------|
| 0 | Ran successfully (verdict may be clean, suspicious, or unknown) |
| 1 | `--fail-on-malicious` set and the overall verdict was malicious |
| 2 | Bad usage — unrecognisable IOC, missing/undecodable file, or config error |
| 3 | `--fail-on-error` set and at least one IOC had no provider answer |

For a **security gate that must fail closed**, combine both flags:

```bash
iocvet lookup "$IOC" --fail-on-malicious --fail-on-error
```

This exits non-zero on a malicious verdict *and* when no provider could reach a
conclusion — so an outage in the threat-intel sources can't let an unchecked
indicator pass as clean.

## Caching

Provider answers are cached on disk (`~/.cache/iocvet/cache.db`, override with
`IOCVET_CACHE_DIR`) for 24 hours by default. This matters most for the workflow
this tool is built for: a nightly cron job or CI pipeline re-checking the same
indicators would otherwise burn its entire free-tier allowance — AbuseIPDB's is
1,000 checks/day — re-asking questions it already has answers to.

Two things are deliberately **never** cached:

- **Errors and rate-limit responses**, which are transient. Caching a 500 would
  let one upstream blip silently degrade every lookup until it expired.
- **Skipped providers**, because a skip is configuration state rather than data.
  If "no API key configured" were cached, adding the key would appear to do
  nothing until the entry aged out.

Cache entries are per provider, so adding a key or retrying one failed source
doesn't discard everything else. Tune the lifetime with `--cache-ttl SECONDS`,
and remember the tradeoff runs both ways: a longer TTL saves more quota, but a
host that was clean yesterday can be compromised today.

The database runs in WAL mode so several `iocvet` processes can share it — a
nightly cron job and an ad-hoc batch at the same time won't lock each other
out. Entries are capped at 50,000 with the oldest evicted first, so a very
large feed can't grow the file without bound, and a cache that can't be opened
or read simply degrades to no caching rather than failing the lookup.

## Security & privacy

iocvet is built to be run against untrusted indicators, so it takes some care:

- **Private and reserved IPs are never sent to external providers.** RFC1918, loopback, link-local (including cloud metadata `169.254.169.254`), and reserved addresses are recognised and skipped — they'd disclose internal network structure to a third party and no reputation source can rate them anyway.
- **ip-api uses plaintext HTTP** (SSL is paid-tier on their side), so a public IP you look up is visible to an on-path observer. All other providers use HTTPS with certificate verification.
- **The cache records which indicators you looked up**, which is sensitive in
  itself. It is created `0600` in a `0700` directory, the tool refuses to use a
  symlinked cache path, and `iocvet cache clear` wipes it.
- Malformed inputs (path traversal, CRLF, multi-value smuggling, oversized strings) are rejected before any request is built. API keys are never written to output, errors, or `--json`.

Set keys as environment variables, or run `iocvet configure` to generate a config file at `~/.config/iocvet/config.toml`:

```bash
export ABUSEIPDB_API_KEY="your-key"
export URLHAUS_AUTH_KEY="your-key"
```

iocvet works with zero keys configured — it just runs fewer providers.

## Adding a provider

This is the part we'd love help with. Every provider is a self-contained class:

```python
from iocvet.providers.base import Provider
from iocvet.core.models import IOCType, ProviderResult, Verdict

class YourServiceProvider(Provider):
    name = "yourservice"
    requires_key = True
    api_key_env = "YOURSERVICE_API_KEY"

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in (IOCType.IPV4, IOCType.IPV6)

    async def _query(self, client, ioc, ioc_type) -> ProviderResult:
        resp = await client.get(f"https://api.yourservice.com/{ioc}")
        data = resp.json()
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.MALICIOUS,  # map their response onto ours
            summary="short human-readable summary",
        )
```

Register it in `src/iocvet/providers/__init__.py` and open a PR. Good candidates we don't cover yet: VirusTotal, AlienVault OTX, GreyNoise, Shodan, MalwareBazaar. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

Shipped:

- [x] Domain support (RDAP registration data + URLhaus host lookups) — v0.2.0
- [x] Defanged IOC input (`evil[.]com`, `hxxp://…`) — v0.2.0
- [x] Internationalised domain (IDN) support — v0.3.0
- [x] CSV export for tickets and spreadsheets — v0.3.0
- [x] SQLite response caching with TTL — v0.4.0

Planned:

- [ ] MalwareBazaar provider (reuses the URLhaus key you already have)
- [ ] AlienVault OTX provider (covers domains, URLs, and hashes)

Ideas, not commitments — [open an issue](https://github.com/ashish-cybersec/ioc-vet/issues)
if one of these would help you and it'll get prioritised:

- Markdown report export
- `--watch` mode to tail a log file and enrich IOCs as they appear
- GreyNoise / Shodan providers

See [CHANGELOG.md](CHANGELOG.md) for what changed in each release.

## License

MIT — see [LICENSE](LICENSE).
