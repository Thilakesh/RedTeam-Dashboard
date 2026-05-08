import asyncio
import json
import shutil

from app.pipeline.stage import AssetRecord, StageContext


class DnsxStage:
    name = "dnsx"
    source_tool = "dnsx"
    inputs = ["subdomain"]
    outputs = ["ipv4"]
    depends_on = ["subfinder", "assetfinder"]
    weight = 20
    optional = False

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        hosts = ctx.inputs.get("subdomain", [])
        if not hosts:
            return []

        binary = shutil.which("dnsx")
        if binary is None:
            raise RuntimeError("dnsx binary not on PATH")

        # JSON output is the only format that doesn't bake ANSI color codes and
        # type markers into stdout. Each line is one resolved host.
        # M1.5: -cname adds CNAME records to the JSON output so we can populate the
        # CNAME column in the Subdomains table without a second dnsx pass.
        proc = await asyncio.create_subprocess_exec(
            binary,
            "-silent",
            "-a",
            "-cname",
            "-resp",
            "-json",
            "-t", "100",
            "-r", "8.8.8.8,1.1.1.1,8.8.4.4,1.0.0.1",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=("\n".join(hosts) + "\n").encode()),
                timeout=480,
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError("dnsx timed out after 480s") from None

        if proc.returncode != 0:
            raise RuntimeError(
                f"dnsx exited {proc.returncode}: {stderr.decode(errors='replace')[:500]}"
            )

        # Two views built in one pass:
        #   by_ip   → ipv4 records (powers IP Summary tab)
        #   per_host → subdomain records carrying {ips, cnames} so the Subdomains
        #              table can light up Primary IP / All IPs / CNAME columns
        by_ip: dict[str, set[str]] = {}
        per_host: dict[str, dict[str, list[str]]] = {}
        for raw in stdout.decode(errors="replace").splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = (obj.get("host") or "").lower()
            if not host:
                continue
            ips = [ip for ip in (obj.get("a") or []) if ip]
            cnames = [c for c in (obj.get("cname") or []) if c]
            if ips or cnames:
                slot = per_host.setdefault(host, {"ips": [], "cnames": []})
                # Use sets via list dedup to preserve order roughly
                for ip in ips:
                    if ip not in slot["ips"]:
                        slot["ips"].append(ip)
                    by_ip.setdefault(ip, set()).add(host)
                for c in cnames:
                    if c not in slot["cnames"]:
                        slot["cnames"].append(c)

        records: list[AssetRecord] = [
            AssetRecord(
                type="ipv4",
                canonical_key=ip,
                payload={"resolves": sorted(resolved_hosts)},
                confidence=90,
            )
            for ip, resolved_hosts in by_ip.items()
        ]
        records.extend(
            AssetRecord(
                type="subdomain",
                canonical_key=host,
                payload={
                    "ips": data["ips"],
                    "cnames": data["cnames"],
                    "primary_ip": data["ips"][0] if data["ips"] else None,
                },
                confidence=90,
            )
            for host, data in per_host.items()
        )
        return records
