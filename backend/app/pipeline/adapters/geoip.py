import os
from pathlib import Path

import maxminddb

from app.pipeline.stage import AssetRecord, StageContext


# Default path inside the worker container; Dockerfile.worker downloads the
# dbip-city-lite mmdb to this location at build time. Override via env for local dev.
_DEFAULT_DB = "/opt/geoip/dbip-city-lite.mmdb"


class GeoipStage:
    """Local IP → Country, City lookup using the dbip-city-lite MMDB.

    No network calls, no rate limit, no per-call cost. The DB is bundled into the
    worker image; if it's missing, the stage logs and returns empty rather than
    failing the scan (geo data is enrichment, not load-bearing).
    """

    name = "geoip"
    source_tool = "geoip"
    inputs = ["ipv4"]
    outputs = ["ipv4"]
    depends_on = ["dnsx"]
    weight = 5
    optional = True

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        ips = ctx.inputs.get("ipv4", [])
        if not ips:
            return []

        db_path = Path(os.environ.get("GEOIP_DB_PATH", _DEFAULT_DB))
        if not db_path.exists():
            # Don't fail the scan — just skip enrichment.
            return []

        records: list[AssetRecord] = []
        with maxminddb.open_database(str(db_path)) as reader:
            for ip in ips:
                try:
                    row = reader.get(ip)
                except (ValueError, TypeError):
                    continue
                if not row:
                    continue
                country_iso, country_name = _country(row)
                city = _city(row)
                if not (country_iso or country_name or city):
                    continue
                records.append(
                    AssetRecord(
                        type="ipv4",
                        canonical_key=ip,
                        payload={
                            "country": country_iso,
                            "country_name": country_name,
                            "city": city,
                        },
                        confidence=80,
                    )
                )
        return records


def _country(row: dict) -> tuple[str, str]:
    country = row.get("country") or {}
    iso = country.get("iso_code") or ""
    names = country.get("names") or {}
    name = names.get("en") or ""
    return iso, name


def _city(row: dict) -> str:
    city = row.get("city") or {}
    names = city.get("names") or {}
    return names.get("en") or ""
