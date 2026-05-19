import asyncio
import json
import logging

from app.core.config import get_settings
from app.pipeline.stage import AssetRecord, StageContext

log = logging.getLogger(__name__)


class BBOTStage:
    name = "bbot"
    source_tool = "bbot"
    inputs: list[str] = []
    outputs = ["subdomain", "ipv4"]
    depends_on: list[str] = []
    weight = 120
    optional = True

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        settings = get_settings()
        proc = await asyncio.create_subprocess_exec(
            "bbot",
            "-t", ctx.domain,
            "-p", "subdomain-enum",
            "--json", "--yes",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=settings.bbot_timeout
            )
        except asyncio.TimeoutError:
            log.warning("bbot: timed out after %ds for %s", settings.bbot_timeout, ctx.domain)
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return []

        return self._parse(stdout, ctx.domain)

    def _parse(self, stdout: bytes, domain: str) -> list[AssetRecord]:
        seen: set[str] = set()
        records: list[AssetRecord] = []
        for raw_line in stdout.decode(errors="replace").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_type = event.get("type", "")
            data = event.get("data", "")
            if not isinstance(data, str):
                continue

            if event_type == "DNS_NAME":
                fqdn = data.lower()
                if fqdn not in seen and (fqdn == domain or fqdn.endswith(f".{domain}")):
                    seen.add(fqdn)
                    records.append(AssetRecord(type="subdomain", canonical_key=fqdn,
                                               payload={"source": "bbot"}, confidence=85))
            elif event_type == "IP_ADDRESS":
                ip = data.strip()
                if ip and ip not in seen:
                    seen.add(ip)
                    records.append(AssetRecord(type="ipv4", canonical_key=ip,
                                               payload={"source": "bbot"}, confidence=80))
        return records
