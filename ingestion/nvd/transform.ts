import type { NvdChunk, NvdCategory, TransformResult } from "../shared/schema.js";
import type { NvdCveRecord, NvdPage } from "./fetch.js";
import { readFile, readdir, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/";

// Return type is NvdChunk, not ChunkDocument — keeps the discriminated union honest
export function transformNvdRecord(record: NvdCveRecord, ingestedAt: string): NvdChunk | null {
  const cveId = record.cve?.id?.trim();
  if (!cveId) return null;

  const text = extractEnglishDescription(record.cve.descriptions);
  if (!text) return null;

  return {
    id: cveId,
    source: "nvd",
    category: inferCategory(text),
    severity: extractSeverity(record.cve.metrics),
    cwe: extractCwe(record.cve.weaknesses),
    text,
    url: `${NVD_DETAIL_URL}${cveId}`,
    ingested_at: ingestedAt,
  };
}

// Mirrors the shape run.ts expects from both pipelines
export async function transformNvdRaw(opts: {
  rawDir: string;
  chunksDir: string;
}): Promise<TransformResult> {
  await mkdir(opts.chunksDir, { recursive: true });

  const files = (await readdir(opts.rawDir)).filter((f) => f.endsWith(".json"));
  const ingestedAt = new Date().toISOString();

  let transformed = 0;
  let skipped = 0;
  let failed = 0;
  const seen = new Set<string>(); // dedupe CVE-IDs across keyword buckets
  const allChunks: NvdChunk[] = [];

  for (const file of files) {
    try {
      const raw = JSON.parse(await readFile(path.join(opts.rawDir, file), "utf-8"));
      const vulns: NvdCveRecord[] = raw?.response?.vulnerabilities ?? [];

      for (const record of vulns) {
        const chunk = transformNvdRecord(record, ingestedAt);
        if (!chunk) { skipped++; continue; }
        if (seen.has(chunk.id)) { skipped++; continue; }
        seen.add(chunk.id);
        allChunks.push(chunk);
        transformed++;
      }
    } catch (err) {
      console.error(`[nvd/transform] Failed on ${file}:`, err);
      failed++;
    }
  }

  const outPath = path.join(opts.chunksDir, "nvd.json");
  await writeFile(outPath, JSON.stringify(allChunks, null, 2), "utf-8");
  console.log(
    `[nvd/transform] ${transformed} chunks → ${outPath} | skipped: ${skipped} | failed: ${failed}`
  );

  return { transformed, skipped, failed };
}

// --- Private helpers (unchanged logic, tightened return types) ---

function extractEnglishDescription(
  descriptions?: Array<{ lang?: string; value?: string }>
): string {
  if (!descriptions?.length) return "";
  const english = descriptions.find((d) => d.lang?.toLowerCase() === "en")?.value?.trim();
  return english ?? descriptions[0]?.value?.trim() ?? "";
}

function extractSeverity(metrics?: Record<string, unknown>): number | null {
  if (!metrics) return null;
  for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const entries = metrics[key];
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      const score = (entry as { cvssData?: { baseScore?: unknown } })?.cvssData?.baseScore;
      if (typeof score === "number") return score;
    }
  }
  return null;
}

function extractCwe(weaknesses?: unknown): string | null {
  if (!Array.isArray(weaknesses)) return null;
  for (const weakness of weaknesses) {
    const descriptions = (weakness as { description?: Array<{ value?: string }> }).description;
    if (!Array.isArray(descriptions)) continue;
    for (const item of descriptions) {
      const value = item?.value?.trim();
      if (value?.toUpperCase().startsWith("CWE-")) return value;
    }
  }
  return null;
}

// Return type is NvdCategory — prevents "pwn" or "crypto" sneaking in here
function inferCategory(text: string): NvdCategory {
  const lower = text.toLowerCase();

  if (
    lower.includes("sql injection") ||
    lower.includes("xss") ||
    lower.includes("cross-site scripting") ||
    lower.includes("path traversal") ||
    lower.includes("directory traversal") ||
    lower.includes("command injection") ||
    lower.includes("deserialization") ||
    lower.includes("ssrf") ||
    lower.includes