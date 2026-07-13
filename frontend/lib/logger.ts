// Minimal structured console logger. Every entry is one JSON line so it's
// grep/paste-friendly next to backend JSON logs. request_id (when passed)
// is the same id forwarded to the API via X-Request-ID, so a frontend error
// and the backend log line it triggered can be tied together by that field.

export function genRequestId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

type LogFields = Record<string, unknown>;

function emit(level: "info" | "warn" | "error", message: string, fields?: LogFields): void {
  const record = { level, message, timestamp: new Date().toISOString(), ...fields };
  const fn = level === "error" ? console.error : level === "warn" ? console.warn : console.log;
  fn(JSON.stringify(record));
}

export const logger = {
  info: (message: string, fields?: LogFields) => emit("info", message, fields),
  warn: (message: string, fields?: LogFields) => emit("warn", message, fields),
  error: (message: string, fields?: LogFields) => emit("error", message, fields),
};
