export type ChunkSource = "nvd" | "ctftime";

// NVD-specific categories
export type NvdCategory = "web" | "memory" | "concurrency" | "type-safety" | "other";

// CTFtime-specific categories
export type CtfCategory = "web" | "pwn" | "crypto" | "forensics" | "rev" | "misc";

export type ChunkCategory = NvdCategory | CtfCategory;

interface ChunkBase {
  id: string;
  source: ChunkSource;
  category: ChunkCategory;
  text: string;
  url: string;
  ingested_at: string;
}

export interface NvdChunk extends ChunkBase {
  source: "nvd";
  category: NvdCategory;
  severity: number | null;
  cwe: string | null;
  // CTFtime fields explicitly absent — catches accidental cross-contamination
  event?: never;
  challenge?: never;
}

export interface CtfChunk extends ChunkBase {
  source: "ctftime";
  category: CtfCategory;
  event: string;
  challenge: string;
  stars?: number;
  pushed_at?: string;
  // NVD fields explicitly absent
  severity?: never;
  cwe?: never;
}

export type ChunkDocument = NvdChunk | CtfChunk;

// Shared result shape for run.ts aggregation
export interface TransformResult {
  transformed: number;
  skipped: number;
  failed: number;
}

export interface RawRecord<T = unknown> {
  source: ChunkSource;
  data: T;
  fetched_at: string;
}