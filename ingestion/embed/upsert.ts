import "dotenv/config";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import path from "node:path";
import { pathToFileURL } from "node:url";

type EmbeddedRecord = {
  id: string;
  embedding?: number[];
  embeddings?: number[];
  document?: string;
  documents?: string;
  text?: string;
  metadata?: Record<string, unknown>;
  metadatas?: Record<string, unknown>;
};

// JSONL, matching embed.ts's output — one record per line. Reading this with
// fs.readFile + JSON.parse (the old approach) builds a single multi-GB JS
// string for a corpus this size and throws "RangeError: Invalid string
// length" before you ever get to upsert anything. Streaming line-by-line
// avoids ever holding more than one line in memory as a string.
const DEFAULT_EMBEDDED_PATH = path.resolve("data/chunks/all.embedded.jsonl");
const DEFAULT_CHROMA_BASE_URL = (process.env.CHROMA_URL ?? "http://localhost:8000").replace(
  /\/+$/,
  ""
);
const DEFAULT_COLLECTION = process.env.CHROMA_COLLECTION ?? "ctf-intelligence";
const DEFAULT_TENANT = process.env.CHROMA_TENANT ?? "default_tenant";
const DEFAULT_DATABASE = process.env.CHROMA_DATABASE ?? "default_database";
const DEFAULT_BATCH_SIZE = Number(process.env.CHROMA_BATCH_SIZE ?? "100");

function chromaHeaders(): HeadersInit {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (process.env.CHROMA_API_KEY) {
    headers["x-chroma-token"] = process.env.CHROMA_API_KEY;
  }

  return headers;
}

function tenantDbBaseUrl(baseUrl: string, tenant: string, database: string): string {
  return `${baseUrl}/api/v2/tenants/${encodeURIComponent(tenant)}/databases/${encodeURIComponent(
    database
  )}`;
}

function collectionsUrl(baseUrl: string, tenant: string, database: string): string {
  return `${tenantDbBaseUrl(baseUrl, tenant, database)}/collections`;
}

function collectionUrl(
  baseUrl: string,
  tenant: string,
  database: string,
  collectionId: string
): string {
  return `${collectionsUrl(baseUrl, tenant, database)}/${encodeURIComponent(collectionId)}`;
}

function asEmbedding(record: EmbeddedRecord): number[] | null {
  if (Array.isArray(record.embedding)) return record.embedding;
  if (Array.isArray(record.embeddings)) return record.embeddings;
  return null;
}

function asDocument(record: EmbeddedRecord): string | null {
  if (typeof record.document === "string") return record.document;
  if (typeof record.documents === "string") return record.documents;
  if (typeof record.text === "string") return record.text;
  return null;
}

function asMetadata(record: EmbeddedRecord): Record<string, unknown> | null {
  if (record.metadata && typeof record.metadata === "object") return record.metadata;
  if (record.metadatas && typeof record.metadatas === "object") return record.metadatas;
  return null;
}

// Streams the JSONL file and yields it in batches, so the caller never has to
// hold the entire corpus in memory at once — just one batch at a time.
async function* batchesFromJsonl(
  filePath: string,
  batchSize: number
): AsyncGenerator<EmbeddedRecord[]> {
  const stream = createReadStream(filePath, { encoding: "utf-8" });
  const rl = createInterface({ input: stream, crlfDelay: Infinity });

  let batch: EmbeddedRecord[] = [];
  for await (const line of rl) {
    if (!line.trim()) continue;
    let record: EmbeddedRecord;
    try {
      record = JSON.parse(line);
    } catch {
      console.warn("[upsert] skipping malformed JSONL line");
      continue;
    }
    batch.push(record);
    if (batch.length >= batchSize) {
      yield batch;
      batch = [];
    }
  }
  if (batch.length) yield batch;
}

// Resolves a collection name to its UUID, creating the collection if it
// doesn't exist yet. Chroma v2 has no "get by name" path param — you list
// collections and match on name, or create and take the ID from the response.
async function getOrCreateCollectionId(
  baseUrl: string,
  tenant: string,
  database: string,
  collectionName: string
): Promise<string> {
  const listUrl = `${collectionsUrl(baseUrl, tenant, database)}?limit=100`;
  const listRes = await fetch(listUrl, { headers: chromaHeaders() });

  if (!listRes.ok && listRes.status !== 404) {
    throw new Error(`Failed to list collections: ${listRes.status} ${listRes.statusText}`);
  }

  if (listRes.ok) {
    const collections = (await listRes.json()) as Array<{ id: string; name: string }>;
    const match = collections.find((c) => c.name === collectionName);
    if (match) return match.id;
  }

  const createRes = await fetch(collectionsUrl(baseUrl, tenant, database), {
    method: "POST",
    headers: chromaHeaders(),
    body: JSON.stringify({
      name: collectionName,
      configuration: { hnsw: { space: "cosine" } },
      get_or_create: true,
    }),
  });

  if (!createRes.ok) {
    throw new Error(
      `Failed to create collection "${collectionName}": ${createRes.status} ${createRes.statusText}`
    );
  }

  const created = (await createRes.json()) as { id: string };
  return created.id;
}

export async function getCollectionCount(
  baseUrl: string,
  tenant: string,
  database: string,
  collectionId: string
): Promise<number> {
  const response = await fetch(`${collectionUrl(baseUrl, tenant, database, collectionId)}/count`, {
    headers: chromaHeaders(),
  });

  if (response.status === 404) return 0;

  if (!response.ok) {
    throw new Error(`Count request failed: ${response.status} ${response.statusText}`);
  }

  const payload = await response.json();

  if (typeof payload === "number") return payload;
  if (typeof payload?.count === "number") return payload.count;

  throw new Error("Unexpected count response shape from Chroma");
}

async function upsertBatch(
  baseUrl: string,
  tenant: string,
  database: string,
  collectionId: string,
  records: EmbeddedRecord[]
): Promise<void> {
  const ids: string[] = [];
  const embeddings: number[][] = [];
  const documents: string[] = [];
  const metadatas: Record<string, unknown>[] = [];

  for (const record of records) {
    const embedding = asEmbedding(record);
    const document = asDocument(record);
    const metadata = asMetadata(record);

    if (!record.id || !embedding || !document) {
      throw new Error(`Invalid embedded record: ${JSON.stringify(record).slice(0, 200)}`);
    }

    ids.push(record.id);
    embeddings.push(embedding);
    documents.push(document);
    metadatas.push(metadata ?? {});
  }

  const response = await fetch(`${collectionUrl(baseUrl, tenant, database, collectionId)}/upsert`, {
    method: "POST",
    headers: chromaHeaders(),
    body: JSON.stringify({
      ids,
      embeddings,
      documents,
      metadatas,
    }),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`Upsert request failed: ${response.status} ${response.statusText} ${body}`);
  }
}

export async function upsertFromEmbeddedJson(opts?: {
  embeddedPath?: string;
  chromaBaseUrl?: string;
  collection?: string;
  tenant?: string;
  database?: string;
  batchSize?: number;
}): Promise<number> {
  const embeddedPath = opts?.embeddedPath ?? DEFAULT_EMBEDDED_PATH;
  const chromaBaseUrl = opts?.chromaBaseUrl ?? DEFAULT_CHROMA_BASE_URL;
  const collection = opts?.collection ?? DEFAULT_COLLECTION;
  const tenant = opts?.tenant ?? DEFAULT_TENANT;
  const database = opts?.database ?? DEFAULT_DATABASE;
  const batchSize = opts?.batchSize ?? DEFAULT_BATCH_SIZE;

  const collectionId = await getOrCreateCollectionId(chromaBaseUrl, tenant, database, collection);
  console.log(`[upsert] Using collection "${collection}" (id: ${collectionId})`);

  let total = 0;
  for await (const batch of batchesFromJsonl(embeddedPath, batchSize)) {
    await upsertBatch(chromaBaseUrl, tenant, database, collectionId, batch);
    total += batch.length;
    console.log(`[upsert] Upserted ${total} so far`);
  }

  if (total === 0) {
    console.log(`[upsert] No embedded records found at ${embeddedPath}`);
  }

  return total;
}

async function main() {
  const inserted = await upsertFromEmbeddedJson();
  console.log(`[upsert] Done. Records processed: ${inserted}`);
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(process.argv[1]).href : false;

if (isMain) {
  main().catch((err) => {
    console.error("[upsert] Fatal:", err);
    process.exit(1);
  });
}