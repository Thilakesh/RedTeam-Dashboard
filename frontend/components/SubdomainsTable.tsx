"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type VisibilityState,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ArrowUpDown, Camera, Columns3, Download, Search } from "lucide-react";
import { api, type SubdomainRow, type SubdomainsPage } from "@/lib/api";
import { ScreenshotModal } from "@/components/ScreenshotModal";
import { cn } from "@/lib/cn";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { CountryFlag, IpTagChip, StatusBadge, WafConfBadge } from "@/components/StatusBadge";

const PAGE_SIZES = [15, 50, 100];

export function SubdomainsTable({ scanId }: { scanId: string }) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(15);
  const [sort, setSort] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string | null>(null);
  const [ipTagFilter, setIpTagFilter] = useState<string | null>(null);
  const [cdnFilter, setCdnFilter] = useState<string | null>(null);
  const [wafFilter, setWafFilter] = useState<string | null>(null);
  const [colVis, setColVis] = useState<VisibilityState>({});
  const [screenshotModal, setScreenshotModal] = useState<{ url: string; host: string } | null>(null);

  const qs = useMemo(() => {
    const p = new URLSearchParams({ page: String(page), limit: String(limit) });
    if (sort) p.set("sort", sort);
    if (search) p.set("search", search);
    if (statusFilter) p.set("status", statusFilter);
    if (ipTagFilter) p.set("ip_tag", ipTagFilter);
    if (cdnFilter) p.set("cdn", cdnFilter);
    if (wafFilter) p.set("waf", wafFilter);
    return p.toString();
  }, [page, limit, sort, search, statusFilter, ipTagFilter, cdnFilter, wafFilter]);

  const { data, isLoading } = useQuery({
    queryKey: ["scan-subdomains", scanId, qs],
    queryFn: () => api<SubdomainsPage>(`/scans/${scanId}/subdomains?${qs}`),
    placeholderData: (prev) => prev,
  });

  const rows = data?.rows ?? [];
  const total = data?.total ?? 0;

  const columns = useMemo<ColumnDef<SubdomainRow>[]>(
    () => [
      {
        id: "index",
        header: () => <span className="text-muted-foreground">#</span>,
        cell: ({ row }) => (
          <span className="text-muted-foreground tabular-nums">{(page - 1) * limit + row.index + 1}</span>
        ),
        size: 44,
        enableHiding: false,
      },
      {
        accessorKey: "subdomain",
        header: () => <SortHeader label="Subdomain" sortKey="subdomain" sort={sort} setSort={setSort} />,
        cell: ({ row }) => (
          <span className="font-mono text-[13px] text-foreground">{row.original.subdomain}</span>
        ),
      },
      {
        accessorKey: "http_status",
        header: () => <SortHeader label="HTTP Status" sortKey="http_status" sort={sort} setSort={setSort} />,
        cell: ({ row }) => <StatusBadge status={row.original.http_status} />,
        size: 110,
      },
      {
        id: "open_ports",
        header: "Open Ports",
        size: 120,
        cell: ({ row }) => {
          const ports = row.original.open_ports;
          if (!ports || ports.length === 0) return <span className="text-muted-foreground">—</span>;
          return <span className="font-mono text-xs">{ports.join(", ")}</span>;
        },
      },
      {
        accessorKey: "title",
        header: "Title",
        cell: ({ row }) => (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="truncate block max-w-[180px]">{row.original.title || "—"}</span>
            </TooltipTrigger>
            {row.original.title && <TooltipContent>{row.original.title}</TooltipContent>}
          </Tooltip>
        ),
      },
      {
        id: "redirect",
        header: "Redir",
        cell: ({ row }) =>
          row.original.redirect ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <Badge variant="warning">YES</Badge>
              </TooltipTrigger>
              {row.original.final_url || row.original.location ? (
                <TooltipContent>{row.original.final_url || row.original.location}</TooltipContent>
              ) : null}
            </Tooltip>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
        size: 70,
      },
      {
        id: "ip_tag",
        header: "IP Tag",
        cell: ({ row }) => <IpTagChip tag={row.original.ip_tag} />,
        size: 110,
      },
      {
        accessorKey: "primary_ip",
        header: "Primary IP",
        cell: ({ row }) => (
          <span className="font-mono text-xs">{row.original.primary_ip || "—"}</span>
        ),
        size: 130,
      },
      {
        id: "all_ips",
        header: "All IPs",
        cell: ({ row }) => {
          const ips = row.original.all_ips;
          if (!ips.length) return <span className="text-muted-foreground">—</span>;
          const display = ips.slice(0, 2).join(", ") + (ips.length > 2 ? ", …" : "");
          return (
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="font-mono text-xs">{display}</span>
              </TooltipTrigger>
              <TooltipContent>{ips.join(", ")}</TooltipContent>
            </Tooltip>
          );
        },
      },
      {
        accessorKey: "cdn_name",
        header: "CDN",
        cell: ({ row }) =>
          row.original.cdn_name ? (
            <Badge variant="info">{row.original.cdn_name}</Badge>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
        size: 140,
      },
      {
        accessorKey: "cname",
        header: "CNAME",
        cell: ({ row }) => (
          <span className="font-mono text-xs">{row.original.cname || "—"}</span>
        ),
      },
      {
        accessorKey: "waf",
        header: "WAF",
        cell: ({ row }) => row.original.waf || <span className="text-muted-foreground">—</span>,
      },
      {
        id: "waf_conf",
        header: "WAF Conf",
        cell: ({ row }) => <WafConfBadge conf={row.original.waf_conf} />,
        size: 90,
      },
      {
        accessorKey: "asn",
        header: "ASN",
        cell: ({ row }) => (
          <span className="font-mono text-xs">{row.original.asn || "—"}</span>
        ),
        size: 90,
      },
      {
        accessorKey: "org",
        header: "Org",
        cell: ({ row }) => row.original.org || <span className="text-muted-foreground">—</span>,
      },
      {
        id: "country",
        header: "Country",
        cell: ({ row }) => <CountryFlag iso={row.original.country} />,
        size: 90,
      },
      {
        accessorKey: "city",
        header: "City",
        cell: ({ row }) => row.original.city || <span className="text-muted-foreground">—</span>,
      },
      {
        accessorKey: "server",
        header: "Server",
        cell: ({ row }) => (
          <span className="font-mono text-xs">{row.original.server || "—"}</span>
        ),
      },
      {
        id: "screenshot",
        header: "Screenshot",
        size: 90,
        cell: ({ row }) => {
          const url = row.original.screenshot_url;
          if (!url) return <span className="text-muted-foreground">—</span>;
          return (
            <button
              onClick={() => setScreenshotModal({ url, host: row.original.subdomain })}
              className="flex items-center gap-1 text-primary hover:underline text-xs"
            >
              <Camera className="h-3.5 w-3.5" />
              View
            </button>
          );
        },
      },
    ],
    [sort, page, limit],
  );

  const table = useReactTable({
    data: rows,
    columns,
    getCoreRowModel: getCoreRowModel(),
    state: { columnVisibility: colVis },
    onColumnVisibilityChange: setColVis,
  });

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[14rem] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search subdomain…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            className="pl-9"
          />
        </div>
        <FilterSelect
          placeholder="All Status Codes"
          value={statusFilter}
          onChange={(v) => {
            setStatusFilter(v);
            setPage(1);
          }}
          options={[
            { value: "200", label: "200" },
            { value: "301", label: "301" },
            { value: "302", label: "302" },
            { value: "403", label: "403" },
            { value: "404", label: "404" },
            { value: "500", label: "500" },
          ]}
        />
        <FilterSelect
          placeholder="All IP Types"
          value={ipTagFilter}
          onChange={(v) => {
            setIpTagFilter(v);
            setPage(1);
          }}
          options={[
            { value: "Direct IP", label: "Direct IP" },
            { value: "CDN IP", label: "CDN IP" },
            { value: "Cloudflare IP", label: "Cloudflare IP" },
          ]}
        />
        <FilterSelect
          placeholder="All CDNs"
          value={cdnFilter}
          onChange={(v) => {
            setCdnFilter(v);
            setPage(1);
          }}
          options={uniqueValues(rows.map((r) => r.cdn_name)).map((v) => ({ value: v, label: v }))}
        />
        <FilterSelect
          placeholder="All WAF"
          value={wafFilter}
          onChange={(v) => {
            setWafFilter(v);
            setPage(1);
          }}
          options={uniqueValues(rows.map((r) => r.waf)).map((v) => ({ value: v, label: v }))}
        />
        <div className="ml-auto flex items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <Columns3 className="h-4 w-4" /> Columns
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Toggle columns</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {table.getAllLeafColumns().filter((c) => c.getCanHide()).map((c) => (
                <DropdownMenuCheckboxItem
                  key={c.id}
                  checked={c.getIsVisible()}
                  onCheckedChange={(v) => c.toggleVisibility(!!v)}
                  onSelect={(e) => e.preventDefault()}
                >
                  {String(c.columnDef.header) || c.id}
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          <Button variant="outline" size="icon" onClick={() => downloadCsv(rows)}>
            <Download className="h-4 w-4" />
          </Button>
        </div>
      </div>

      <div className="border border-border rounded-lg overflow-hidden bg-card">
        <div className="overflow-auto scrollbar-thin" style={{ maxHeight: "62vh" }}>
          <table className="w-full text-sm border-collapse">
            <colgroup>
              {table.getAllLeafColumns().filter((c) => c.getIsVisible()).map((c) => (
                <col key={c.id} style={{ width: c.columnDef.size ? `${c.columnDef.size}px` : undefined }} />
              ))}
            </colgroup>
            <thead className="bg-muted/50 sticky top-0 z-10">
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id}>
                  {hg.headers.map((h) => (
                    <th
                      key={h.id}
                      className="text-left px-3 py-2.5 text-xxs uppercase tracking-wider font-semibold text-muted-foreground border-b border-border whitespace-nowrap"
                    >
                      {flexRender(h.column.columnDef.header, h.getContext())}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {isLoading && (
                <tr>
                  <td colSpan={columns.length} className="text-center text-muted-foreground py-8">
                    Loading…
                  </td>
                </tr>
              )}
              {!isLoading && rows.length === 0 && (
                <tr>
                  <td colSpan={columns.length} className="text-center text-muted-foreground py-12">
                    No subdomains match the current filters.
                  </td>
                </tr>
              )}
              {!isLoading &&
                table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    className={cn("border-b border-border hover:bg-muted/30 transition-colors")}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td
                        key={cell.id}
                        className="px-3 py-2 align-middle whitespace-nowrap"
                      >
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="flex items-center justify-between text-sm">
        <div className="text-muted-foreground">
          Showing {rows.length === 0 ? 0 : (page - 1) * limit + 1} to{" "}
          {Math.min(page * limit, total)} of {total} results
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
          >
            ‹
          </Button>
          {pageWindow(page, totalPages).map((p, i) =>
            p === "…" ? (
              <span key={`gap-${i}`} className="px-2 text-muted-foreground">…</span>
            ) : (
              <Button
                key={p}
                variant={p === page ? "default" : "outline"}
                size="sm"
                onClick={() => setPage(p as number)}
                className="min-w-[2rem]"
              >
                {p}
              </Button>
            ),
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
          >
            ›
          </Button>
          <Select value={String(limit)} onValueChange={(v) => { setLimit(Number(v)); setPage(1); }}>
            <SelectTrigger className="w-[6.5rem]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PAGE_SIZES.map((n) => (
                <SelectItem key={n} value={String(n)}>{n} / page</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {screenshotModal && (
        <ScreenshotModal
          url={screenshotModal.url}
          host={screenshotModal.host}
          open={!!screenshotModal}
          onClose={() => setScreenshotModal(null)}
        />
      )}
    </div>
  );
}

function SortHeader({
  label,
  sortKey,
  sort,
  setSort,
}: {
  label: string;
  sortKey: string;
  sort: string | null;
  setSort: (s: string | null) => void;
}) {
  const active = sort === sortKey || sort === `-${sortKey}`;
  const desc = sort === `-${sortKey}`;
  const Icon = !active ? ArrowUpDown : desc ? ArrowDown : ArrowUp;
  return (
    <button
      onClick={() => setSort(active ? (desc ? null : `-${sortKey}`) : sortKey)}
      className="inline-flex items-center gap-1.5 hover:text-foreground"
    >
      {label}
      <Icon className="h-3 w-3" />
    </button>
  );
}

function FilterSelect({
  placeholder,
  value,
  onChange,
  options,
}: {
  placeholder: string;
  value: string | null;
  onChange: (v: string | null) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <Select value={value ?? "__all__"} onValueChange={(v) => onChange(v === "__all__" ? null : v)}>
      <SelectTrigger className="w-[10.5rem]">
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="__all__">{placeholder}</SelectItem>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function uniqueValues(arr: (string | null)[]): string[] {
  return Array.from(new Set(arr.filter((v): v is string => !!v))).sort();
}

function pageWindow(current: number, total: number): (number | "…")[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const out: (number | "…")[] = [1];
  if (current > 3) out.push("…");
  for (let p = Math.max(2, current - 1); p <= Math.min(total - 1, current + 1); p++) out.push(p);
  if (current < total - 2) out.push("…");
  out.push(total);
  return out;
}

function downloadCsv(rows: SubdomainRow[]) {
  const headers = [
    "subdomain", "http_status", "title", "redirect", "primary_ip", "all_ips", "cdn_name",
    "cname", "waf", "waf_conf", "asn", "org", "country", "city", "server",
  ];
  const escape = (v: unknown) => {
    if (v == null) return "";
    const s = Array.isArray(v) ? v.join("|") : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [
    headers.join(","),
    ...rows.map((r) => headers.map((h) => escape((r as Record<string, unknown>)[h])).join(",")),
  ];
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "subdomains.csv";
  a.click();
  URL.revokeObjectURL(url);
}
