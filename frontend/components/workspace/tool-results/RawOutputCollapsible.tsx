"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight, Copy, Check, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

export function RawOutputCollapsible({
  content,
  exitCode = null,
  stderr = null,
  stdoutUrl = null,
  stderrUrl = null,
}: {
  content: string | null;
  exitCode?: number | null;
  stderr?: string | null;
  stdoutUrl?: string | null;
  stderrUrl?: string | null;
}) {
  const [open, setOpen] = useState(false);
  const [stderrOpen, setStderrOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const exitBadge = exitCode !== null && (
    <Badge variant={exitCode === 0 ? "success" : "destructive"} className="font-mono">
      exit {exitCode}
    </Badge>
  );

  if (!content) {
    return (
      <div className="rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground flex items-center gap-2">
        No raw output captured for this task.
        {exitBadge}
      </div>
    );
  }

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* ignore — clipboard unavailable */
    }
  };

  const bytes = new Blob([content]).size;

  return (
    <div className="space-y-2">
      <div className="rounded-md border border-border bg-background">
        <div className="flex items-center justify-between border-b border-border bg-muted/30 px-3 py-2">
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="flex items-center gap-2 text-sm font-medium text-foreground"
          >
            {open ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
            Raw output
            <span className="text-xs text-muted-foreground">({bytes} bytes preview)</span>
            {exitBadge}
          </button>
          <div className="flex items-center gap-1">
            {stdoutUrl && (
              <Button type="button" variant="ghost" size="sm" className="h-7" asChild>
                <a href={stdoutUrl} target="_blank" rel="noreferrer">
                  <Download className="h-3.5 w-3.5 mr-1" />
                  Full output
                </a>
              </Button>
            )}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={handleCopy}
              className="h-7"
            >
              {copied ? (
                <Check className="h-3.5 w-3.5 mr-1" />
              ) : (
                <Copy className="h-3.5 w-3.5 mr-1" />
              )}
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
        </div>
        {open && (
          <pre className="max-h-[600px] overflow-auto bg-background p-3 text-xs leading-relaxed text-foreground whitespace-pre-wrap break-words">
            {content}
          </pre>
        )}
      </div>

      {stderr && (
        <div className="rounded-md border border-border bg-background">
          <div className="flex items-center justify-between border-b border-border bg-muted/30 px-3 py-2">
            <button
              type="button"
              onClick={() => setStderrOpen((v) => !v)}
              className="flex items-center gap-2 text-sm font-medium text-foreground"
            >
              {stderrOpen ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4" />
              )}
              stderr
            </button>
            {stderrUrl && (
              <Button type="button" variant="ghost" size="sm" className="h-7" asChild>
                <a href={stderrUrl} target="_blank" rel="noreferrer">
                  <Download className="h-3.5 w-3.5 mr-1" />
                  Full stderr
                </a>
              </Button>
            )}
          </div>
          {stderrOpen && (
            <pre className="max-h-[300px] overflow-auto bg-background p-3 text-xs leading-relaxed text-destructive whitespace-pre-wrap break-words">
              {stderr}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
