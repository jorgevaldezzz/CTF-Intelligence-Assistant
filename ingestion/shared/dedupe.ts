import type { ChunkDocument } from "./schema.js";

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
  return chunk.source === "nvd" ? `cve:${chunk.id}` : `url:${chunk.url}`;
}

function mergeChunk(existing: ChunkDocument, candidate: ChunkDocument): ChunkDocument {
  return {
    ...existing,
    category: existing.category !== "other" ? existing.category : candidate.category,
    cwe: existing.cwe ?? candidate.cwe,
    severity: existing.severity ?? candidate.severity,
    text: existing.text || candidate.text,
  };
}
