"""gowitness — screenshot capture for live HTTP/HTTPS services.

Takes subdomains as input, builds http/https URLs, runs gowitness in batch mode,
uploads screenshots to MinIO, returns screenshot assets.

Screenshot asset: type="screenshot", canonical_key=FQDN (e.g. "api.example.com"),
payload={"screenshot_url": "...", "url": "https://api.example.com"}.
"""
from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
from pathlib import Path

from app.pipeline.stage import AssetRecord, StageContext
from app.services import storage
from app.workers.sandbox import get_preexec_fn


class GoWitnessStage:
    name = "gowitness"
    source_tool = "gowitness"
    inputs = ["subdomain"]
    outputs = ["screenshot"]
    depends_on = ["httpx"]
    weight = 50
    optional = True

    _MAX_HOSTS = 50

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        hosts = ctx.inputs.get("subdomain", [])
        if not hosts:
            return []

        binary = shutil.which("gowitness")
        if binary is None:
            raise RuntimeError("gowitness binary not on PATH")

        hosts = sorted(hosts)[: self._MAX_HOSTS]

        # Build http and https URLs for each host
        urls: list[tuple[str, str]] = []  # (url, host)
        for host in hosts:
            urls.append((f"https://{host}", host))
            urls.append((f"http://{host}", host))

        with tempfile.TemporaryDirectory() as tmpdir:
            url_file = Path(tmpdir) / "urls.txt"
            ss_dir = Path(tmpdir) / "screenshots"
            ss_dir.mkdir()
            url_file.write_text("\n".join(u for u, _ in urls) + "\n")

            proc = await asyncio.create_subprocess_exec(
                binary,
                "file",
                "-f", str(url_file),
                "-P", str(ss_dir),
                "--disable-db",
                "--timeout", "20",
                "--chrome-path", "/usr/bin/chromium",
                "-t", "4",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=get_preexec_fn() if sys.platform != "win32" else None,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=300)
            except asyncio.TimeoutError:
                proc.kill()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    pass

            # Collect all screenshots, then deduplicate by canonical_key (FQDN).
            # Gowitness generates both https-host.png and http-host.png for the same
            # host; both resolve to the same canonical_key which causes a Postgres
            # CardinalityViolationError in the ON CONFLICT DO UPDATE upsert.
            # We keep only one record per host, preferring the https screenshot.
            best: dict[str, AssetRecord] = {}  # canonical_key → best record

            for png_path in ss_dir.glob("*.png"):
                filename = png_path.name
                stem = png_path.stem  # e.g. "https-sub.example.com" or "http-sub.example.com"
                host_guess = stem
                is_https = False
                # Strip scheme prefix added by gowitness
                for prefix in ("https-", "http-"):
                    if host_guess.startswith(prefix):
                        is_https = prefix == "https-"
                        host_guess = host_guess[len(prefix):]
                        break
                # Strip port suffix if present (e.g. "sub.example.com-443" → "sub.example.com")
                if "-" in host_guess:
                    parts = host_guess.rsplit("-", 1)
                    if parts[1].isdigit():
                        host_guess = parts[0]

                if not host_guess:
                    continue

                object_name = f"scans/{ctx.scan_id}/{filename}"
                uploaded = storage.upload_file(object_name, png_path)
                if not uploaded:
                    continue
                ss_url = storage.screenshot_url(object_name)
                if not ss_url:
                    continue

                record = AssetRecord(
                    type="screenshot",
                    canonical_key=host_guess,
                    payload={
                        "screenshot_url": ss_url,
                        "screenshot_object_name": object_name,
                        "url": f"https://{host_guess}",
                    },
                    confidence=90,
                )
                # Prefer https screenshot; only keep http if no https record seen yet
                if host_guess not in best or is_https:
                    best[host_guess] = record

            return list(best.values())
