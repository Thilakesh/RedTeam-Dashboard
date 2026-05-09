import logging
from dataclasses import asdict
from datetime import date

from app.core.config import get_settings
from app.pipeline.adapters._cache import cache_get, cache_set
from app.pipeline.stage import AssetRecord, StageContext

log = logging.getLogger(__name__)


class CensysStage:
    name = "censys"
    source_tool = "censys"
    inputs: list[str] = []
    outputs = ["subdomain", "ipv4"]
    depends_on: list[str] = []
    weight = 8
    optional = True
    authz_required = False

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        settings = get_settings()
        if not settings.censys_api_id or not settings.censys_api_secret:
            log.info("censys: no credentials configured, skipping")
            return []

        cache_key = f"censys:cache:{ctx.target_id}:{date.today().isoformat()}"
        cached = await cache_get(cache_key, settings.redis_url)
        if cached is not None:
            log.info("censys: cache hit for %s, skipping API call", ctx.domain)
            return [AssetRecord(**r) for r in cached]

        try:
            from censys.search import CensysHosts
            h = CensysHosts(api_id=settings.censys_api_id, api_secret=settings.censys_api_secret)
            results = h.search(f"parsed.names: {ctx.domain}", pages=2)
            records = self._parse(results, ctx.domain)
        except Exception as exc:
            log.warning("censys: API error for %s, skipping: %s", ctx.domain, exc)
            return []

        await cache_set(cache_key, settings.redis_url, [asdict(r) for r in records])
        return records

    def _parse(self, results, domain: str) -> list[AssetRecord]:
        seen: set[str] = set()
        records: list[AssetRecord] = []
        for host in results:
            ip = host.get("ip", "")
            if ip and ip not in seen:
                seen.add(ip)
                records.append(AssetRecord(type="ipv4", canonical_key=ip,
                                           payload={"source": "censys"}, confidence=90))
            for name in host.get("parsed", {}).get("names", []):
                fqdn = name.lower()
                if fqdn not in seen and (fqdn == domain or fqdn.endswith(f".{domain}")):
                    seen.add(fqdn)
                    records.append(AssetRecord(type="subdomain", canonical_key=fqdn,
                                               payload={"source": "censys"}, confidence=90))
        return records
