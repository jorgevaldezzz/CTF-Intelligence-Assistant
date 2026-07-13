import "dotenv/config";
import fs from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import path from "node:path";
import { pathToFileURL } from "node:url";
import OpenAI from "openai";

type ChunkDocument = {
  id: string;
  source: "nvd" | "ctftime";
  category: string;
  text: string;
  url: string;
  ingested_at: string;
  [key: string]: unknown;
};

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
const OUTPUT_PATH = path.resolve("data/chunks/all.embedded.jsonl");
const LOG_PATH = path.resolve("data/chunks/embed.log");

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function loadExistingIds(filePath: string): Promise<Set<string>> {
  const ids = new Set<string>();

  let stream;
  try {
    stream = createReadStream(filePath, { encoding: "utf-8" });
  } catch {
    return ids;
  }

  const rl = createInterface({
    input: stream,
    crlfDelay: Infinity,
  });

  try {
    for await (const line of rl) {
      if (!line.trim()) continue;

      try {
        const record = JSON.parse(line);
        if (record?.id) ids.add(record.id);
      } catch {
        // Ignore malformed lines
      }
    }
  } catch {
    // Ignore missing file
  }

  return ids;
}

async function embedBatchWithRetry(
  client: OpenAI,
  inputs: string[]
): Promise<number[][]> {
  let attempt = 0;

  while (true) {
    try {
      const res = await client.embeddings.create({
        model: MODEL,
        input: inputs,
      });

      return res.data.map((d) => d.embedding);
    } catch (err) {
      attempt++;

      if (attempt > MAX_RETRIES) {
        throw err;
      }

      const backoffMs = 1000 * 2 ** attempt;

      console.warn(
        `batch failed (attempt ${attempt}/${MAX_RETRIES}), retrying in ${backoffMs}ms`
      );

      await sleep(backoffMs);
    }
  }
}

function getAliases(id: string): string[] {
  const aliases: Record<string, string[]> = {
    "CVE-2021-44228": [
      "Log4Shell",
      "Log4Shell vulnerability",
      "Apache Log4j vulnerability",
      "Apache Log4j JNDI injection",
      "Log4j remote code execution",
      "Log4j RCE",
    ],
  };

  return aliases[id] ?? [];
}

function buildEmbeddingText(chunk: ChunkDocument): string {
  const parts: string[] = [];

  parts.push(`ID: ${chunk.id}`);
  parts.push(`Source: ${chunk.source}`);
  parts.push(`Category: ${chunk.category}`);

  const aliases = getAliases(chunk.id);

  if (aliases.length) {
    parts.push(`Aliases: ${aliases.join(", ")}`);
  }

  if (chunk.source === "nvd") {
    if (chunk.severity !== undefined) {
      parts.push(`Severity: ${chunk.severity}`);
    }

    if (chunk.cwe !== undefined) {
      parts.push(`CWE: ${chunk.cwe}`);
    }
  }

  if (chunk.source === "ctftime") {
    if (chunk.challenge) {
      parts.push(`Challenge: ${chunk.challenge}`);
    }

    if (chunk.event) {
      parts.push(`Event: ${chunk.event}`);
    }
  }

  parts.push(`Description:\n${chunk.text}`);

  return parts.join("\n\n");
}

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

  const limit = limitArg
    ? parseInt(limitArg.split("=")[1], 10)
    : undefined;

  const apiKey = process.env.OPENAI_API_KEY;

  if (!apiKey && !dryRun) {
    console.error(
      "OPENAI_API_KEY not set. Use --dry-run to test without calling the API."
    );
    process.exit(1);
  }

  let raw: string;

  try {
    raw = await fs.readFile(CHUNKS_PATH, "utf-8");
  } catch {
    console.error(
      `Could not read ${CHUNKS_PATH}. Run Phase 1 pipeline first.`
    );
    process.exit(1);
  }

  const chunks: ChunkDocument[] = JSON.parse(raw);

  const working = limit
    ? chunks.slice(0, limit)
    : chunks;

  const existingIds = await loadExistingIds(OUTPUT_PATH);

  const toEmbed = working.filter(
    (c) => !existingIds.has(c.id)
  );

  console.log(
    `Embedding ${toEmbed.length} new chunks (${working.length - toEmbed.length} already embedded, resumable)`
  );

  const client = apiKey
    ? new OpenAI({ apiKey })
    : (null as unknown as OpenAI);

  await fs.mkdir(path.dirname(OUTPUT_PATH), {
    recursive: true,
  });

  let embedded = 0;
  let failed = 0;

  const totalBatches = Math.ceil(
    toEmbed.length / BATCH_SIZE
  );

  for (
    let i = 0;
    i < toEmbed.length;
    i += BATCH_SIZE
  ) {
    const batch = toEmbed.slice(
      i,
      i + BATCH_SIZE
    );

    const batchNum =
      Math.floor(i / BATCH_SIZE) + 1;

    console.log(
      `batch ${batchNum}/${totalBatches}`
    );

    const batchRecords: EmbeddedRecord[] = [];

    const documents = batch.map(buildEmbeddingText);

    if (dryRun) {
      for (let j = 0; j < batch.length; j++) {
        batchRecords.push({
          id: batch[j].id,
          embedding: new Array(1536).fill(0),
          document: documents[j],
          metadata: toMetadata(batch[j]),
        });

        embedded++;
      }
    } else {
      try {
        const vectors =
          await embedBatchWithRetry(
            client,
            documents
          );

        batch.forEach((chunk, idx) => {
          batchRecords.push({
            id: chunk.id,
            embedding: vectors[idx],
            document: documents[idx],
            metadata: toMetadata(chunk),
          });

          embedded++;
        });
      } catch (err) {
        failed += batch.length;

        console.error(
          `batch failed permanently: ${
            (err as Error).message
          }`
        );
      }
    }

    if (batchRecords.length) {
      const lines =
        batchRecords
          .map((r) => JSON.stringify(r))
          .join("\n") + "\n";

      await fs.appendFile(
        OUTPUT_PATH,
        lines
      );
    }
  }

  await fs.mkdir(
    path.dirname(LOG_PATH),
    {
      recursive: true,
    }
  );

  await fs.appendFile(
    LOG_PATH,
    `[${new Date().toISOString()}] embed: total=${working.length} embedded=${embedded} failed=${failed}\n`
  );

  console.log(
    `Done: embedded=${embedded} failed=${failed} output=${OUTPUT_PATH}`
  );
}

const isMain =
  process.argv[1]
    ? import.meta.url ===
      pathToFileURL(process.argv[1]).href
    : false;

if (isMain) {
  main().catch((err) => {
    console.error(
      "Fatal error in embed.ts:",
      err
    );
    process.exit(1);
  });
}