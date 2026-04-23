import type { ChunkDocument } from "./schema.js";

const MIN_TEXT_LENGTH = 40;

export function validateChunk(chunk: ChunkDocument): boolean {
  if (!chunk.id || !chunk.source || !chunk.category || !chunk.url || !chunk.ingested_at) {
    return false;
  }

  if (typeof chunk.text !== "string" || chunk.text.trim().length < MIN_TEXT_LENGTH) {
    return false;
  }

  return true;
}

export function filterValidChunks(chunks: ChunkDocument[]): ChunkDocument[] {
  return chunks.filter(validateChunk);
}
