import "dotenv/config";
import fs from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import path from "node:path";
import { pathToFileURL } from "node:url";
import OpenAI from "openai";

// Matches your Phase 1 ChunkDocument shape (NvdChunk | CtfChunk):
// id, source, category, text, url, ingested_at, + source-specific fields.
type ChunkDocument = {
  id: string;
  source: "nvd" | "ctftime";
  category: string;
  text: string;
  url: string;
  ingested_at: string;
  [key: string]: unknown; // severity/cwe for nvd, event/challenge/stars for ctftime
};

// Shape upsert.ts reads: { id, embedding, document, metadata }
type EmbeddedRecord = {
  id: string;
  embedding: number[];
  document: string;
  metadata: Record<string, unknown>;
};

const MODEL = "text-embedding-3-small"; // 1536 dims
const BATCH_SIZE = Number(process.env.EMBED_BATCH_SIZE ?? "100");
const MAX_RETRIES = 5;

const CHUNKS_PATH = path.resolve("data/chunks/all.json");
// JSONL, not a single JSON array: at ~113k chunks x 1536-dim vectors, a single
// JSON.stringify()/JSON.parse() over the whole corpus builds one JS string
// well past V8's string-length ceiling (RangeError: Invalid string length).
// One record per line means no read, write, or parse ever touches more than
// one line/batch at a time, however large the corpus gets.
const OUTPUT_PATH = path.resolve("data/chunks/all.embedded.jsonl");
const LOG_PATH = path.resolve("data/chunks/embed.log");

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Streams the existing output file line-by-line to collect already-embedded
// IDs, rather than reading the whole file into one string (same overflow
// risk as the write side once the file gets large).
async function loadExistingIds(filePath: string): Promise<Set<string>> {
  const ids = new Set<string>();
  let stream;
  try {
    stream = createReadStream(filePath, { encoding: "utf-8" });
  } catch {
    return ids;
  }

  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of rl) {
      if (!line.trim()) continue;
      try {
        const record = JSON.parse(line);
        if (record?.id) ids.add(record.id);
      } catch {
        // Skip a malformed/partial line (e.g. process was killed mid-write) —
        // that record will just get re-embedded, which is harmless.
      }
    }
  } catch {
    // File doesn't exist yet on first run — that's fine, empty set.
  }
  return ids;
}

async function embedBatchWithRetry(client: OpenAI, inputs: string[]): Promise<number[][]> {
  let attempt = 0;
  while (true) {
    try {
      const res = await client.embeddings.create({ model: MODEL, input: inputs });
      return res.data.map((d) => d.embedding);
    } catch (err) {
      attempt++;
      if (attempt > MAX_RETRIES) throw err;
      const backoffMs = 1000 * 2 ** attempt;
      console.warn(`  batch failed (attempt ${attempt}/${MAX_RETRIES}), retrying in ${backoffMs}ms`);
      await sleep(backoffMs);
    }
  }
}

// metadata should not duplicate the full document text as a value — Chroma
// (and most vector stores) store metadata for filtering, not for holding the
// same text twice. Keep `text` out of metadata, everything else in.
//
// Also strip null/undefined values: Chroma's metadata schema only accepts
// string/number/boolean. Your real schema.ts has severity/cwe typed as
// `number | null` / `string | null` for NVD chunks — a null there would
// otherwise get sent straight to Chroma and rejected (or coerced badly).
// Optional fields (stars, pushed_at, etc.) can also be `undefined`, which
// JSON.stringify drops silently anyway, but we filter explicitly to be safe.
function toMetadata(chunk: ChunkDocument): Record<string, unknown> {
  const { text, ...rest } = chunk;
  const cleaned: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(rest)) {
    if (value !== null && value !== undefined) {
      cleaned[key] = value;
    }
  }
  return cleaned;
}

async function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const limitArg = args.find((a) => a.startsWith("--limit="));
  const limit = limitArg ? parseInt(limitArg.split("=")[1], 10) : undefined;

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey && !dryRun) {
    console.error("OPENAI_API_KEY not set. Use --dry-run to test without calling the API.");
    process.exit(1);
  }

  let raw: string;
  try {
    raw = await fs.readFile(CHUNKS_PATH, "utf-8");
  } catch {
    console.error(`Could not read ${CHUNKS_PATH}. Run your Phase 1 pipeline first (run.ts) to produce it.`);
    process.exit(1);
  }

  const chunks: ChunkDocument[] = JSON.parse(raw);
  const working = limit ? chunks.slice(0, limit) : chunks;

  const existingIds = await loadExistingIds(OUTPUT_PATH);
  const toEmbed = working.filter((c) => !existingIds.has(c.id));

  console.log(
    `Embedding ${toEmbed.length} new chunks (${working.length - toEmbed.length} already embedded, resumable)`
  );

  const client = apiKey ? new OpenAI({ apiKey }) : (null as unknown as OpenAI);
  await fs.mkdir(path.dirname(OUTPUT_PATH), { recursive: true });

  let embedded = 0;
  let failed = 0;
  const totalBatches = Math.ceil(toEmbed.length / BATCH_SIZE);

  for (let i = 0; i < toEmbed.length; i += BATCH_SIZE) {
    const batch = toEmbed.slice(i, i + BATCH_SIZE);
    const batchNum = Math.floor(i / BATCH_SIZE) + 1;
    console.log(`  batch ${batchNum}/${totalBatches}`);

    const batchRecords: EmbeddedRecord[] = [];

    if (dryRun) {
      for (const chunk of batch) {
        batchRecords.push({
          id: chunk.id,
          embedding: new Array(1536).fill(0),
          document: chunk.text,
          metadata: toMetadata(chunk),
        });
        embedded++;
      }
    } else {
      try {
        const vectors = await embedBatchWithRetry(client, batch.map((c) => c.text));
        batch.forEach((chunk, idx) => {
          batchRecords.push({
            id: chunk.id,
            embedding: vectors[idx],
            document: chunk.text,
            metadata: toMetadata(chunk),
          });
          embedded++;
        });
      } catch (err) {
        failed += batch.length;
        console.error(`  batch failed permanently: ${(err as Error).message}`);
      }
    }

    // Append this batch's lines only — never re-serializes anything already
    // on disk, so the write cost per batch stays constant no matter how far
    // through the corpus we are.
    if (batchRecords.length) {
      const lines = batchRecords.map((r) => JSON.stringify(r)).join("\n") + "\n";
      await fs.appendFile(OUTPUT_PATH, lines);
    }
  }

  await fs.mkdir(path.dirname(LOG_PATH), { recursive: true });
  await fs.appendFile(
    LOG_PATH,
    `[${new Date().toISOString()}] embed: total=${working.length} embedded=${embedded} failed=${failed}\n`
  );

  console.log(`Done: embedded=${embedded} failed=${failed} output=${OUTPUT_PATH}`);
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(process.argv[1]).href : false;

if (isMain) {
  main().catch((err) => {
    console.error("Fatal error in embed.ts:", err);
    process.exit(1);
  });
}