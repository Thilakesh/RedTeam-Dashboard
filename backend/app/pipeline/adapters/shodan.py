import logging
from dataclasses import asdict
from datetime import date

from app.core.config import get_settings
from app.pipeline.adapters._cache import cache_get, cache_set
from app.pipeline.stage import AssetRecord, StageContext

log = logging.getLogger(__name__)


class ShodanStage:
    name = "shodan"
    source_tool = "shodan"
    inputs: list[str] = []
    outputs = ["subdomain", "ipv4"]
    depends_on: list[str] = []
    weight = 5
    optional = True
    authz_required = False

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        settings = get_settings()
        if not settings.shodan_api_key:
            log.info("shodan: no API key configured, skipping")
            return []

        cache_key = f"shodan:cache:{ctx.target_id}:{date.today().isoformat()}"
        cached = await cache_get(cache_key, settings.redis_url)
        if cached is not None:
            log.info("shodan: cache hit for %s, skipping API call", ctx.domain)
            return [AssetRecord(**r) for r in cached]

        try:
            import shodan as shodan_lib
            api = shodan_lib.Shodan(settings.shodan_api_key)
            result = api.dns.domain_info(ctx.domain)
            records = self._parse(result, ctx.domain)
        except Exception as exc:
            log.warning("shodan: API error for %s, skipping: %s", ctx.domain, exc)
            return []

        await cache_set(cache_key, settings.redis_url, [asdict(r) for r in records])
        return records

    def _parse(self, result: dict, domain: str) -> list[AssetRecord]:
        seen: set[str] = set()
        records: list[AssetRecord] = []
        for label in result.get("subdomains", []):
            fqdn = f"{label}.{domain}".lower()
            if fqdn not in seen:
                seen.add(fqdn)
                records.append(AssetRecord(type="subdomain", canonical_key=fqdn,
                                           payload={"source": "shodan"}, confidence=85))
        for entry in result.get("data", []):
            if entry.get("type") == "A":
                ip = entry.get("value", "")
                if ip and ip not in seen:
                    seen.add(ip)
                    records.append(AssetRecord(type="ipv4", canonical_key=ip,
                                               payload={"source": "shodan"}, confidence=85))
        return records
