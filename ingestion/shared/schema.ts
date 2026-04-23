export type ChunkSource = "nvd" | "ctftime";

export type ChunkCategory =
  | "web"
  | "memory"
  | "concurrency"
  | "type-safety"
  | "other";

export interface ChunkDocument {
  id: string;
  source: ChunkSource;
  category: ChunkCategory;
  severity: number | null;
  cwe: string | null;
  text: string;
  url: string;
  ingested_at: string;
}

export interface RawRecord<T = unknown> {
  source: ChunkSource;
  data: T;
  fetched_at: string;
}
