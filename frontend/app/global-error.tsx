"use client";

import { useEffect } from "react";
import { logger } from "@/lib/logger";

// Replaces the root layout entirely when an error escapes it, so it must
// render its own <html>/<body> and can't rely on globals.css having loaded.
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    logger.error("unhandled global frontend error", {
      message: error.message,
      digest: error.digest,
      stack: error.stack,
    });
  }, [error]);

  return (
    <html lang="en">
      <body>
        <div
          style={{
            display: "flex",
            minHeight: "100vh",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            gap: 16,
            textAlign: "center",
            padding: 16,
            fontFamily: "system-ui, sans-serif",
          }}
        >
          <h2>Something went wrong</h2>
          <p>{error.message || "An unexpected error occurred."}</p>
          {error.digest && (
            <p style={{ fontFamily: "monospace", fontSize: 12 }}>Reference: {error.digest}</p>
          )}
          <button onClick={() => reset()}>Try again</button>
        </div>
      </body>
    </html>
  );
}
