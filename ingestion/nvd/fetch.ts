import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

export interface NvdCveRecord {
  cve: {
    id: string;
    descriptions?: Array<{ lang?: string; value?: string }>;
    metrics?: Record<string, unknown>;
    weaknesses?: unknown;
  };
}

export interface NvdPage {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: NvdCveRecord[];
}

const NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const DEFAULT_RESULTS_PER_PAGE = 2000;

export const NVD_KEYWORD_BUCKETS = [
  "sql injection",
  "sqli",
  "xss",
  "cross-site scripting",
  "path traversal",
  "directory traversal",
  "command injection",
  "shell injection",
  "deserialization",
  "unsafe deserialization",
  "ssrf",
  "server-side request forgery",
  "xxe",
  "xml external entity",
  "lfi",
  "local file inclusion",
  "rfi",
  "remote file inclusion",
  "buffer overflow",
  "heap overflow",
  "format string",
  "race condition",
  "type confusion",
] as const;

export async function fetchNvdRaw(opts: {
  outputDir: string;
  apiKey?: string;
  resultsPerPage?: number;
  sleepMs?: number;
  includeRejected?: boolean;
}): Promise<string[]> {
  const outputDir = opts.outputDir;
  const resultsPerPage = clampResultsPerPage(opts.resultsPerPage ?? DEFAULT_RESULTS_PER_PAGE);
  const sleepMs = opts.sleepMs ?? (opts.apiKey ? 750 : 6000);
  const includeRejected = opts.includeRejected ?? false;
  const fetchedAt = new Date().toISOString();

  await mkdir(outputDir, { recursive: true });

  const rawPaths: string[] = [];

  for (const keyword of NVD_KEYWORD_BUCKETS) {
    let startIndex = 0;

    while (true) {
      const url = buildNvdUrl(keyword, startIndex, resultsPerPage, includeRejected);
      const page = await fetchJson<NvdPage>(url, opts.apiKey);
      const slug = slugify(keyword);
      const rawPath = path.join(outputDir, `nvd-${slug}-${startIndex}.json`);
      const payload = {
        source: "nvd",
        keyword,
        fetched_at: fetchedAt,
        request: { startIndex, resultsPerPage },
        response: page,
      };

      await writeFile(rawPath, JSON.stringify(payload, null, 2), "utf8");
      rawPaths.push(rawPath);

      const nextIndex = page.startIndex + page.resultsPerPage;
      if (nextIndex >= page.totalResults || page.resultsPerPage === 0) {
        break;
      }

      startIndex = nextIndex;
      await sleep(sleepMs);
    }
  }

  return rawPaths;
}

function buildNvdUrl(keyword: string, startIndex: number, resultsPerPage: number, includeRejected: boolean): string {
  const params = new URLSearchParams({
    keywordSearch: keyword,
    resultsPerPage: String(resultsPerPage),
    startIndex: String(startIndex),
  });

  if (!includeRejected) {
    params.set("noRejected", "true");
  }

  return `${NVD_BASE_URL}?${params.toString()}`;
}

async function fetchJson<T>(url: string, apiKey?: string): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": "CTF-Intelligence-Assistant/1.0",
  };

  if (apiKey) {
    headers.apiKey = apiKey;
  }

  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`NVD request failed: ${response.status} ${response.statusText}`);
  }

  return (await response.json()) as T;
}

function clampResultsPerPage(value: number): number {
  return Math.max(1, Math.min(DEFAULT_RESULTS_PER_PAGE, value));
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
