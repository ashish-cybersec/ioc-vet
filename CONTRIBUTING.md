# Contributing to ioc-vet

Thanks for considering it. The fastest way to make a meaningful contribution here is adding a new provider — the project is deliberately architected so that's a small, self-contained change.

## Adding a provider (the easy on-ramp)

1. Pick a free threat intel source not yet covered. Good candidates: VirusTotal, AlienVault OTX, GreyNoise, Shodan, MalwareBazaar.
2. Create `src/iocvet/providers/yourservice.py`. Subclass `Provider` from `providers/base.py`. Look at `providers/abuseipdb.py` for a complete, simple example.
3. Map the service's response onto our three-value `Verdict` enum (`MALICIOUS`, `SUSPICIOUS`, `CLEAN`, `UNKNOWN`). Be conservative: if a source can't distinguish "verified safe" from "never checked," that's `UNKNOWN`, not `CLEAN`.
4. Register your provider in `src/iocvet/providers/__init__.py`.
5. Add tests in `tests/test_providers.py` using `httpx.MockTransport` (see existing tests) — no live API key should ever be required to run the test suite.
6. Update the provider table in `README.md`.

## Other contributions we'd welcome

- Passive DNS: domains now resolve via RDAP (registration data) and URLhaus (host lookups), but nothing maps a domain to the IPs it has historically resolved to. A passive-DNS provider would close that gap.
- SQLite response caching with a configurable TTL.
- Markdown/CSV export for the `lookup` and `batch` commands.
- Anything on the [roadmap](README.md#roadmap).

## Development setup

```bash
git clone https://github.com/ashish-cybersec/ioc-vet
cd ioc-vet
pip install -e ".[dev]"
pytest
ruff check .
```

## Pull request expectations

Keep PRs focused on one provider or one feature. Include tests — mocked, not live — for any new network-calling code. We're not strict about style beyond what `ruff` already enforces.

## Releasing

Maintainers: see [RELEASING.md](RELEASING.md).
