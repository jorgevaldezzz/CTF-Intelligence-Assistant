import "dotenv/config";
import OpenAI from "openai";

const EMBED_MODEL = "text-embedding-3-small";

const CHROMA_BASE_URL = (process.env.CHROMA_URL ?? "http://localhost:8000").replace(/\/+$/, "");
const COLLECTION = process.env.CHROMA_COLLECTION ?? "ctf-intelligence";
const TENANT = process.env.CHROMA_TENANT ?? "default_tenant";
const DATABASE = process.env.CHROMA_DATABASE ?? "default_database";

function chromaHeaders(): HeadersInit {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (process.env.CHROMA_API_KEY) headers["x-chroma-token"] = process.env.CHROMA_API_KEY;
  return headers;
}

function collectionsUrl(): string {
  return `${CHROMA_BASE_URL}/api/v2/tenants/${encodeURIComponent(TENANT)}/databases/${encodeURIComponent(
    DATABASE
  )}/collections`;
}

async function resolveCollectionId(): Promise<string> {
  const res = await fetch(`${collectionsUrl()}?limit=100`, { headers: chromaHeaders() });
  if (!res.ok) throw new Error(`Failed to list collections: ${res.status} ${res.statusText}`);
  const collections = (await res.json()) as Array<{ id: string; name: string }>;
  const match = collections.find((c) => c.name === COLLECTION);
  if (!match) throw new Error(`Collection "${COLLECTION}" not found — did upsert.ts run against this same CHROMA_URL/tenant/database?`);
  return match.id;
}

interface RawQueryResult {
  ids: string[][];
  distances: number[][];
  documents: string[][];
  metadatas: Record<string, unknown>[][];
}

export interface RetrievedChunk {
  id: string;
  text: string;
  citation: string;
  url: string;
  score: number;
  source: string;
}

function formatCitation(metadata: Record<string, unknown>): string {
  if (metadata.source === "nvd") {
    return `${metadata.id ?? ""} (${metadata.severity ?? "no severity"}, ${metadata.cwe ?? "no CWE"})`;
  }
  return `${metadata.challenge ?? "?"} — ${metadata.event ?? "?"}`;
}

// One raw call to Chroma's query endpoint, optionally filtered by `where`.
// Kept separate from retrieve() so hybrid mode can call this twice (once per
// source pool) without duplicating the HTTP/embedding logic.
async function rawQuery(
  vector: number[],
  topK: number,
  where?: Record<string, unknown>
): Promise<RetrievedChunk[]> {
  const collectionId = await resolveCollectionId();

  const res = await fetch(`${collectionsUrl()}/${encodeURIComponent(collectionId)}/query`, {
    method: "POST",
    headers: chromaHeaders(),
    body: JSON.stringify({
      query_embeddings: [vector],
      n_results: topK,
      where: where && Object.keys(where).length ? where : undefined,
    }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Query failed: ${res.status} ${res.statusText} ${body}`);
  }

  const result = (await res.json()) as RawQueryResult;
  const ids = result.ids[0] ?? [];
  const distances = result.distances[0] ?? [];
  const documents = result.documents[0] ?? [];
  const metadatas = result.metadatas[0] ?? [];

  return ids.map((id, i) => ({
    id,
    text: documents[i],
    citation: formatCitation(metadatas[i] ?? {}),
    url: (metadatas[i]?.url as string) ?? "",
    score: 1 - distances[i], // cosine distance -> similarity
    source: (metadatas[i]?.source as string) ?? "unknown",
  }));
}

export async function retrieve(
  query: string,
  opts: {
    topK?: number;
    source?: "nvd" | "ctftime";
    category?: string;
    hybrid?: boolean;
    ctfFloor?: number;
  } = {}
): Promise<RetrievedChunk[]> {
  const { topK = 8, source, category, hybrid = true, ctfFloor } = opts;

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) throw new Error("OPENAI_API_KEY not set");
  const client = new OpenAI({ apiKey });

  const embedRes = await client.embeddings.create({ model: EMBED_MODEL, input: query });
  const vector = embedRes.data[0].embedding;

  // Explicit source filter (e.g. debugging, --source=ctftime) bypasses
  // hybrid merging entirely — you get exactly what you asked for.
  if (source) {
    const where: Record<string, unknown> = { source };
    if (category) where.category = category;
    return rawQuery(vector, topK, where);
  }

  if (!hybrid) {
    const where: Record<string, unknown> = {};
    if (category) where.category = category;
    return rawQuery(vector, topK, where);
  }

  // Hybrid mode: query each source pool separately so neither pool can
  // fully crowd the other out of results. This cuts both ways:
  // - NVD has ~79x more chunks than CTF, so an unfiltered search can bury
  //   CTF results purely on volume even when they're relevant.
  // - CTF writeups are narrative first-person prose; a narratively-phrased
  //   question can score CTF chunks HIGHER on raw embedding similarity than
  //   topically-exact NVD matches, purely on writing-style similarity, not
  //   relevance. (Found this by hand: an SSRF question phrased narratively
  //   pulled 8/8 CTF results, zero NVD, despite NVD having CVEs explicitly
  //   tagged CWE-918 SSRF with near-identical wording to the question.)
  // Reserving a floor for only one side re-introduces the same problem in
  // the other direction depending on how a question happens to be phrased —
  // so both pools get a guaranteed minimum here, not just CTF.
  const minPerSource = ctfFloor ?? Math.max(1, Math.ceil(topK * 0.25));

  const nvdWhere: Record<string, unknown> = { source: "nvd" };
  const ctfWhere: Record<string, unknown> = { source: "ctftime" };
  if (category) {
    nvdWhere.category = category;
    ctfWhere.category = category;
  }

  const [nvdResults, ctfResults] = await Promise.all([
    rawQuery(vector, topK, nvdWhere),
    rawQuery(vector, topK, ctfWhere),
  ]);

  // Reserve each pool's own best results first, then fill remaining slots
  // with whatever scores highest across both pools combined.
  const nvdFloorPicks = nvdResults.slice(0, minPerSource);
  const ctfFloorPicks = ctfResults.slice(0, minPerSource);
  const reservedIds = new Set([...nvdFloorPicks, ...ctfFloorPicks].map((r) => r.id));

  const remainingPool = [...nvdResults, ...ctfResults]
    .filter((r) => !reservedIds.has(r.id))
    .sort((a, b) => b.score - a.score);

  const fillSlots = Math.max(0, topK - nvdFloorPicks.length - ctfFloorPicks.length);
  const merged = [...nvdFloorPicks, ...ctfFloorPicks, ...remainingPool.slice(0, fillSlots)];

  // Final sort by score for display — the floor guarantees already happened,
  // this is just presentation order.
  return merged.sort((a, b) => b.score - a.score);
}

async function main() {
  const rawArgs = process.argv.slice(2);
  const sourceArg = rawArgs.find((a) => a.startsWith("--source="));
  const source = sourceArg ? (sourceArg.split("=")[1] as "nvd" | "ctftime") : undefined;
  const noHybrid = rawArgs.includes("--no-hybrid");
  const query = rawArgs
    .filter((a) => !a.startsWith("--source=") && a !== "--no-hybrid")
    .join(" ");

  if (!query) {
    console.error(
      'Usage: npx tsx scripts/query.ts "your test question here" [--source=ctftime] [--no-hybrid]'
    );
    process.exit(1);
  }

  const results = await retrieve(query, { source, hybrid: !noHybrid });
  console.log(
    `\nQuery: "${query}"${source ? ` (source=${source})` : ""}${noHybrid ? " (hybrid off)" : ""}\n`
  );
  if (!results.length) {
    console.log("(no results)");
  }
  results.forEach((r, i) => {
    console.log(`${i + 1}. [${r.score.toFixed(3)}] [${r.source}] ${r.citation}`);
    console.log(`   ${r.text.slice(0, 150).replace(/\n/g, " ")}...`);
    console.log(`   ${r.url}\n`);
  });
}

import { pathToFileURL } from "node:url";
const isMain = process.argv[1] ? import.meta.url === pathToFileURL(process.argv[1]).href : false;
if (isMain) {
  main().catch((err) => {
    console.error("Fatal error in query.ts:", err);
    process.exit(1);
  });
}