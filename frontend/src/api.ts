import type {
  Analytics,
  AskResult,
  BenchmarkQuestion,
  BenchmarkResult,
  ExtractionNed,
  ExtractResult,
  Ingestion,
  Mention,
  Overview,
} from "./types";

export class ApiError extends Error {}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch {
    throw new ApiError("Cannot reach the ThreatGraph API. Is it running? (make app)");
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(detail);
  }
  return res.json() as Promise<T>;
}

const post = <T>(path: string, body: unknown) => request<T>(path, { method: "POST", body: JSON.stringify(body) });

export const errorText = (e: unknown) => (e instanceof ApiError ? e.message : String(e));

export const api = {
  overview: () => request<Overview>("/api/overview"),
  questions: () => request<BenchmarkQuestion[]>("/api/benchmark/questions"),
  ingestion: () => request<Ingestion>("/api/ingestion"),
  analytics: () => request<Analytics>("/api/analytics"),
  runAnalytics: () => post<Analytics>("/api/analytics/run", {}),
  extractionNed: () => request<ExtractionNed>("/api/extraction-ned"),
  extract: (text: string) => post<ExtractResult>("/api/extract", { text }),
  ned: (text: string) => post<{ mentions: Mention[] }>("/api/ned", { text }),
  ask: (question: string) => post<AskResult>("/api/graphrag/ask", { question }),
  benchmark: () => request<BenchmarkResult>("/api/graphrag/benchmark"),
  runBenchmark: () => post<unknown>("/api/graphrag/benchmark/run", {}),
};
