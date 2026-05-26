import type { ChunkDocument, NvdChunk } from "./schema.js";

export function dedupeChunks(chunks: ChunkDocument[]): ChunkDocument[] {
  const seen = new Map<string, ChunkDocument>();

  for (const chunk of chunks) {
    const key = dedupeKey(chunk);
    const existing = seen.get(key);

    if (!existing) {
      seen.set(key, chunk);
      continue;
    }

    seen.set(key, mergeChunk(existing, chunk));
  }

  return [...seen.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export function dedupeKey(chunk: ChunkDocument): string {
  // Both sources now key on id — NVD ids are CVE-IDs, CTFtime ids are sha1 hashes
  return `${chunk.source}:${chunk.id}`;
}

function mergeChunk(existing: ChunkDocument, candidate: ChunkDocument): ChunkDocument {
  // Category: prefer anything over "other"
  const category =
    existing.category !== "other" ? existing.category : candidate.category;

  // NVD-only fields — only attempt merge when both sides are NvdChunks
  if (existing.source === "nvd" && candidate.source === "nvd") {
    return {
      ...(existing as NvdChunk),
      category,
      cwe: existing.cwe ?? (candidate as NvdChunk).cwe,
      severity: existing.severity ?? (candidate as NvdChunk).severity,
      text: existing.text || candidate.text,
    } satisfies NvdChunk;
  }

  // CTFtime or cross-source collision (shouldn't happen, but jic)
  return {
    ...existing,
    category,
    text: existing.text || candidate.text,
  };
}