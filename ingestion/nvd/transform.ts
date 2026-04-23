import type { ChunkDocument } from "../shared/schema.js";
import type { NvdCveRecord } from "./fetch.js";

const NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/";

export function transformNvdRecord(record: NvdCveRecord, ingestedAt: string): ChunkDocument | null {
  const cveId = record.cve?.id?.trim();
  if (!cveId) {
    return null;
  }

  const text = extractEnglishDescription(record.cve.descriptions);
  if (!text) {
    return null;
  }

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

function extractEnglishDescription(descriptions?: Array<{ lang?: string; value?: string }>): string {
  if (!descriptions?.length) {
    return "";
  }

  const english = descriptions.find((item) => item.lang?.toLowerCase() === "en")?.value?.trim();
  return english ?? descriptions[0]?.value?.trim() ?? "";
}

function extractSeverity(metrics?: Record<string, unknown>): number | null {
  if (!metrics) {
    return null;
  }

  for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const entries = metrics[key];
    if (!Array.isArray(entries)) {
      continue;
    }

    for (const entry of entries) {
      if (!entry || typeof entry !== "object") {
        continue;
      }

      const cvssData = (entry as { cvssData?: { baseScore?: unknown } }).cvssData;
      const score = cvssData?.baseScore;
      if (typeof score === "number") {
        return score;
      }
    }
  }

  return null;
}

function extractCwe(weaknesses?: unknown): string | null {
  if (!Array.isArray(weaknesses)) {
    return null;
  }

  for (const weakness of weaknesses) {
    const descriptions = (weakness as { description?: Array<{ value?: string }> }).description;
    if (!Array.isArray(descriptions)) {
      continue;
    }

    for (const item of descriptions) {
      const value = item?.value?.trim();
      if (value?.toUpperCase().startsWith("CWE-")) {
        return value;
      }
    }
  }

  return null;
}

function inferCategory(text: string): ChunkDocument["category"] {
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
    lower.includes("xxe") ||
    lower.includes("local file inclusion") ||
    lower.includes("remote file inclusion")
  ) {
    return "web";
  }

  if (lower.includes("buffer overflow") || lower.includes("heap overflow") || lower.includes("format string")) {
    return "memory";
  }

  if (lower.includes("race condition")) {
    return "concurrency";
  }

  if (lower.includes("type confusion")) {
    return "type-safety";
  }

  return "other";
}
