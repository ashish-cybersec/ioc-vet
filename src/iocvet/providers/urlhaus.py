"""URLhaus (abuse.ch) — covers malware-distribution URLs and payload hashes.

As of 2025, abuse.ch requires a free Auth-Key for all API access (it used
to be keyless). Get one by signing in with GitHub/Google/etc at
https://auth.abuse.ch/ and generating a key in your profile.
"""

from __future__ import annotations

import httpx

from iocvet.core.models import IOCType, ProviderResult, Verdict
from iocvet.providers.base import Provider

_BASE_URL = "https://urlhaus-api.abuse.ch/v1"


class URLhausProvider(Provider):
    name = "urlhaus"
    requires_key = True
    api_key_env = "URLHAUS_AUTH_KEY"

    #: URLhaus indexes payloads by MD5 and SHA256 only. Deliberately NOT
    #: HASH_TYPES: that set includes SHA1, which the payload endpoint cannot
    #: look up. Claiming SHA1 support would turn every SHA1 query into a
    #: silent "not found" — i.e. a false negative on a malware hash.
    _HASH_FIELDS = {IOCType.MD5: "md5_hash", IOCType.SHA256: "sha256_hash"}

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type == IOCType.URL or ioc_type in self._HASH_FIELDS

    async def _query(self, client: httpx.AsyncClient, ioc: str, ioc_type: IOCType) -> ProviderResult:
        if ioc_type == IOCType.URL:
            return await self._query_url(client, ioc)
        return await self._query_hash(client, ioc, ioc_type)

    async def _query_url(self, client: httpx.AsyncClient, url: str) -> ProviderResult:
        resp = await client.post(
            f"{_BASE_URL}/url/",
            data={"url": url},
            headers={"Auth-Key": self.api_key or ""},
            timeout=self.timeout_seconds,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") != "ok":
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                summary="not found in URLhaus database",
            )

        tags = data.get("tags") or []
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.MALICIOUS,
            summary=f"known malware-distribution URL ({data.get('threat', 'unspecified')})"
            + (f" — tags: {', '.join(tags)}" if tags else ""),
            details={
                "url_status": data.get("url_status"),
                "threat": data.get("threat"),
                "tags": tags,
                "date_added": data.get("date_added"),
            },
            link=data.get("urlhaus_reference"),
        )

    async def _query_hash(
        self, client: httpx.AsyncClient, file_hash: str, ioc_type: IOCType
    ) -> ProviderResult:
        # The payload endpoint expects the hash under a length-specific key
        # ("md5_hash" / "sha256_hash"), not a generic "hash" param.
        resp = await client.post(
            f"{_BASE_URL}/payload/",
            data={self._HASH_FIELDS[ioc_type]: file_hash},
            headers={"Auth-Key": self.api_key or ""},
            timeout=self.timeout_seconds,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") != "ok":
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                summary="not found in URLhaus payload database",
            )

        vt_link = (data.get("virustotal") or {}).get("link")
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.MALICIOUS,
            summary=f"known malware payload ({data.get('file_type', 'unknown type')}, "
            f"{data.get('signature') or 'unidentified signature'})",
            details={
                "file_type": data.get("file_type"),
                "signature": data.get("signature"),
                "first_seen": data.get("firstseen"),
                "virustotal_result": (data.get("virustotal") or {}).get("result"),
            },
            link=vt_link,
        )
