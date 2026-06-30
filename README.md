# ioc-vet

Multi-source IOC enrichment from your terminal. Drop in an IP, domain, URL, or file hash — get back a unified verdict pulled from multiple threat intel sources in parallel, instead of opening five browser tabs.

```
$ iocvet lookup 185.220.101.45

╭──────────────────────────────────────────────────╮
│ 185.220.101.45  [ipv4]   SUSPICIOUS               │
╰──────────────────────────────────────────────────╯
Provider    Verdict       Summary                                Latency
ip-api       SUSPICIOUS    Germany · M247 Europe SRL · known...   180ms
abuseipdb    SUSPICIOUS    abuse confidence 42/100 across 11...   310ms

abuseipdb → https://www.abuseipdb.com/check/185.220.101.45
```

## Why this exists

Most tools in this space are built to be clicked, not scripted. Browser extensions and note-taking plugins solve the same problem, but they only run while a human is looking at a screen — and the ones that go further usually paywall the providers that actually matter (AbuseIPDB, URLhaus) behind a paid tier.

ioc-vet is built for the other half of the job: the part that runs in a CI pipeline, a cron job checking yesterday's suspicious IPs, or a one-line `grep | iocvet batch` over last night's logs. It works out of the box with zero API keys, gets better as you add free ones, and every provider it supports is free — there's no Pro tier holding anything back.

## Install

```bash
pip install ioc-vet
```

Or from source:

```bash
git clone https://github.com/your-username/ioc-vet
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

# Machine-readable output for scripts/pipelines
iocvet lookup 8.8.8.8 --json

# Batch mode: one IOC per line
iocvet batch suspicious_ips.txt

# Exit code 1 if malicious — useful in CI or alerting pipelines
iocvet lookup 1.2.3.4 --fail-on-malicious

# See what's configured
iocvet providers
```

## Providers

| Provider  | IOC types         | API key needed?                          |
|-----------|--------------------|-------------------------------------------|
| ip-api    | IP                 | No — works immediately                    |
| AbuseIPDB | IP                 | Yes, free (1,000 checks/day) — [sign up](https://www.abuseipdb.com/register) |
| URLhaus   | URL, file hash     | Yes, free — [sign up](https://auth.abuse.ch/) |

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

- [ ] SQLite response caching (avoid re-querying the same IOC within a TTL)
- [ ] VirusTotal, OTX, GreyNoise, Shodan providers
- [ ] Markdown / CSV report export for tickets
- [ ] `--watch` mode to tail a log file and enrich IOCs as they appear

## License

MIT — see [LICENSE](LICENSE).
