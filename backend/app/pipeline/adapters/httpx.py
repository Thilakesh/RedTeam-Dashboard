import asyncio
import json
import shutil

from app.pipeline.stage import AssetRecord, StageContext


class HttpxStage:
    """ProjectDiscovery's httpx CLI (not the Python library) — probes HTTP(S) services
    on each input subdomain and emits one `http_service` per live URL.
    """

    name = "httpx"
    source_tool = "httpx"
    inputs = ["subdomain"]
    outputs = ["http_service"]
    depends_on = ["dnsx"]
    weight = 60
    optional = False

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        hosts = ctx.inputs.get("subdomain", [])
        if not hosts:
            return []

        # Installed as `pdhttpx` in Dockerfile.worker to avoid colliding with the
        # Python httpx library's CLI entry point.
        binary = shutil.which("pdhttpx")
        if binary is None:
            raise RuntimeError("pdhttpx (ProjectDiscovery httpx) binary not on PATH")

        # M1.5: every flag here maps to a column in the Subdomains table.
        #   -follow-redirects + -location → Redir column + final URL
        #   -cdn → CDN column (provider name)
        #   -ip → ip address probed (used for IP-tag derivation)
        #   -server / -web-server → Server column
        #   -cname → CNAME column (httpx ships this on its own host record)
        proc = await asyncio.create_subprocess_exec(
            binary,
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-server",
            "-web-server",
            "-cdn",
            "-ip",
            "-cname",
            "-follow-redirects",
            "-location",
            "-json",
            "-no-color",
            "-threads", "150",
            "-timeout", "5",  # per-host timeout — keeps dead hosts from blocking
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=("\n".join(hosts) + "\n").encode()),
                timeout=600,
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError("httpx timed out after 600s") from None

        if proc.returncode != 0:
            raise RuntimeError(
                f"httpx exited {proc.returncode}: {stderr.decode(errors='replace')[:500]}"
            )

        records: list[AssetRecord] = []
        seen: set[str] = set()
        for raw in stdout.decode(errors="replace").splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url")
            if not url or url in seen:
                continue
            seen.add(url)

            # httpx returns `host` (the input subdomain) and `input` (raw line). Prefer
            # `input` because it's the exact form that flowed into the table — keeps
            # the join back to the subdomain row deterministic.
            host = obj.get("input") or obj.get("host") or ""
            location = obj.get("location") or ""
            final_url = obj.get("final_url") or obj.get("final-url") or ""
            redirected = bool(location) or (final_url and final_url != url)

            cdn_name = obj.get("cdn_name") or obj.get("cdn-name") or ""
            cdn_type = obj.get("cdn_type") or obj.get("cdn-type") or ""
            is_cdn = bool(obj.get("cdn")) or bool(cdn_name)

            records.append(
                AssetRecord(
                    type="http_service",
                    canonical_key=url,
                    payload={
                        "host": host,
                        "status_code": obj.get("status_code"),
                        "title": obj.get("title"),
                        "tech": obj.get("tech") or obj.get("technologies") or [],
                        "input": obj.get("input"),
                        "server": obj.get("webserver") or obj.get("web-server") or obj.get("server") or "",
                        "ip": obj.get("host") if obj.get("a") is None else (obj.get("a") or [None])[0],
                        "cnames": obj.get("cnames") or obj.get("cname") or [],
                        "cdn": is_cdn,
                        "cdn_name": cdn_name,
                        "cdn_type": cdn_type,
                        "redirect": redirected,
                        "final_url": final_url,
                        "location": location,
                        "scheme": obj.get("scheme"),
                        "port": obj.get("port"),
                    },
                    confidence=95,
                )
            )
        return records
