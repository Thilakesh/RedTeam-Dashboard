"""Daily EPSS and CISA KEV feed refresh.

Vuln stages MUST NOT call live feeds — they read from cve_intel. This module
is the sole writer to cve_intel. Run manually or via external cron:

    docker compose exec backend python -m app.workers.feeds_refresher

CI gate: `git diff backend/app/pipeline/vuln | grep -E 'first.org|cisa.gov' && exit 1`
enforces that no vuln stage imports these URLs.
"""
from __future__ import annotations

import asyncio
import csv
import gzip
import io
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.sql import func

from app.core.db import SessionLocal
from app.models.cve_intel import CveIntel

log = logging.getLogger(__name__)

_EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_BATCH = 2000


async def refresh_epss(db) -> int:
    """Download EPSS CSV, upsert into cve_intel. Returns rows upserted."""
    log.info("feeds_refresher: downloading EPSS from %s", _EPSS_URL)
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        resp = await client.get(_EPSS_URL)
        resp.raise_for_status()

    content = gzip.decompress(resp.content)
    text = content.decode("utf-8")

    reader = csv.reader(io.StringIO(text))
    rows: list[dict] = []
    for line in reader:
        # Skip blank, comment (#), and header (cve) lines
        if not line or not line[0] or line[0].startswith("#") or line[0] == "cve":
            continue
        cve_id = line[0].strip()
        if not cve_id.startswith("CVE-"):
            continue
        try:
            epss = float(line[1])
        except (IndexError, ValueError):
            continue
        rows.append({"cve_id": cve_id, "epss": epss})

    if not rows:
        log.warning("feeds_refresher: EPSS CSV parsed 0 rows")
        return 0

    for start in range(0, len(rows), _BATCH):
        chunk = rows[start : start + _BATCH]
        stmt = insert(CveIntel).values(chunk)
        stmt = stmt.on_conflict_do_update(
            index_elements=["cve_id"],
            set_={"epss": stmt.excluded.epss, "refreshed_at": func.now()},
        )
        await db.execute(stmt)
    await db.commit()

    log.info("feeds_refresher: EPSS upserted %d rows", len(rows))
    return len(rows)


async def refresh_kev(db) -> int:
    """Download CISA KEV catalog, upsert into cve_intel. Returns rows upserted."""
    log.info("feeds_refresher: downloading KEV from %s", _KEV_URL)
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
        resp = await client.get(_KEV_URL)
        resp.raise_for_status()

    data = resp.json()
    vulns = data.get("vulnerabilities") or []

    rows: list[dict] = []
    for v in vulns:
        cve_id = (v.get("cveID") or "").strip()
        if not cve_id.startswith("CVE-"):
            continue
        date_str = v.get("dateAdded") or ""
        kev_date: datetime | None = None
        if date_str:
            try:
                kev_date = datetime.strptime(date_str, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                pass
        ransomware = (v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
        rows.append({
            "cve_id": cve_id,
            "kev": True,
            "kev_added_date": kev_date,
            "ransomware_use": ransomware,
        })

    if not rows:
        log.warning("feeds_refresher: KEV JSON parsed 0 rows")
        return 0

    for start in range(0, len(rows), _BATCH):
        chunk = rows[start : start + _BATCH]
        stmt = insert(CveIntel).values(chunk)
        stmt = stmt.on_conflict_do_update(
            index_elements=["cve_id"],
            set_={
                "kev": stmt.excluded.kev,
                "kev_added_date": stmt.excluded.kev_added_date,
                "ransomware_use": stmt.excluded.ransomware_use,
                "refreshed_at": func.now(),
            },
        )
        await db.execute(stmt)
    await db.commit()

    log.info("feeds_refresher: KEV upserted %d rows", len(rows))
    return len(rows)


async def refresh_feeds() -> None:
    """Entry point: refresh EPSS then KEV. Manages its own DB session."""
    async with SessionLocal() as db:
        epss_count = await refresh_epss(db)
        kev_count = await refresh_kev(db)
    log.info(
        "feeds_refresher: done — EPSS %d rows, KEV %d rows", epss_count, kev_count
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(refresh_feeds())
