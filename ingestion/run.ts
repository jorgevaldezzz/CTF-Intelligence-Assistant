import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { dedupeChunks } from "./shared/dedupe.js";
import { filterValidChunks } from "./shared/validate.js";
import type { ChunkDocument } from "./shared/schema.js";
import { fetchNvdRaw } from "./nvd/fetch.js";
import { transformNvdRecord } from "./nvd/transform.js";
import type { NvdCveRecord } from "./nvd/fetch.js";

const ROOT_DIR = path.resolve(process.cwd());
const RAW_DIR = path.join(ROOT_DIR, "data", "raw");
const CHUNKS_DIR = path.join(ROOT_DIR, "data", "chunks");
const NVD_RAW_DIR = path.join(RAW_DIR, "nvd");
const NVD_CHUNKS_DIR = path.join(CHUNKS_DIR, "nvd");

async function main(): Promise<void> {
  await mkdir(NVD_RAW_DIR, { recursive: true });
  await mkdir(NVD_CHUNKS_DIR, { recursive: true });

  const apiKey = process.env.NVD_API_KEY;
  const rawPaths = await fetchNvdRaw({ outputDir: NVD_RAW_DIR, apiKey });
  const ingestedAt = new Date().toISOString().slice(0, 10);

  const chunks: ChunkDocument[] = [];
  for (const rawPath of rawPaths) {
    const raw = JSON.parse(await readFile(rawPath, "utf8")) as {
      response?: { vulnerabilities?: NvdCveRecord[] };
    };

    const vulnerabilities = raw.response?.vulnerabilities;
    if (!Array.isArray(vulnerabilities)) {
      continue;
    }

    for (const vulnerability of vulnerabilities) {
      const chunk = transformNvdRecord(vulnerability, ingestedAt);
      if (chunk) {
        chunks.push(chunk);
      }
    }
  }

  const cleaned = filterValidChunks(dedupeChunks(chunks));

  for (const chunk of cleaned) {
    await writeFile(path.join(NVD_CHUNKS_DIR, `${chunk.id}.json`), JSON.stringify(chunk, null, 2), "utf8");
  }
}

void main();
