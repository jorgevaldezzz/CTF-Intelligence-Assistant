import path from "node:path";
import { writeFile, mkdir } from "node:fs/promises";

import { fetchNvdRaw } from "./nvd/fetch.js";
import { transformNvdRaw } from "./nvd/transform.js";
import { scrapeRepos } from "./ctftime/scrape.js";
import { fetchWriteups } from "./ctftime/fetch.js";
import { transformWriteups } from "./ctftime/transform.js";
import { dedupeChunks } from "./shared/dedupe.js";
import { filterValidChunks } from "./shared/validate.js";
import type { TransformResult } from "./shared/schema.js";

// --- Config ---

const RAW_DIR     = path.resolve("data/raw");
const CHUNKS_DIR  = path.resolve("data/chunks");
const LOG_PATH    = path.resolve("pipeline.log");

const NVD_RAW_DIR = path.join(RAW_DIR, "nvd");
const CTF_RAW_DIR = path.join(RAW_DIR, "ctftime");

// --- CLI flags ---

const args = new Set(process.argv.slice(2));
const SKIP_FETCH = args.has("--skip-fetch");
const NVD_ONLY   = args.has("--nvd-only");
const CTF_ONLY   = args.has("--ctf-only");

if (NVD_ONLY && CTF_ONLY) {
  console.error("[run] --nvd-only and --ctf-only are mutually exclusive");
  process.exit(1);
}

// --- Logging ---

interface PipelineLog {
  started_at: string;
  finished_at: string;
  flags: { skipFetch: boolean; nvdOnly: boolean; ctfOnly: boolean };
  sources: {
    nvd:     SourceLog | null;
    ctftime: SourceLog | null;
  };
  combined: {
    total_before_dedupe: number;
    total_after_dedupe:  number;
    total_after_validate: number;
    written_to: string;
  };
}

interface SourceLog {
  fetch_skipped: boolean;
  transform: TransformResult;
}

// --- Helpers ---

function runningMs(start: number): string {
  return `${((Date.now() - start) / 1000).toFixed(1)}s`;
}

async function ensureDirs() {
  await mkdir(RAW_DIR,    { recursive: true });
  await mkdir(CHUNKS_DIR, { recursive: true });
}

// --- Per-source orchestration ---

async function runNvd(skipFetch: boolean): Promise<SourceLog> {
  if (!skipFetch) {
    console.log("[nvd] Fetching from NVD API…");
    const t = Date.now();
    await fetchNvdRaw({
      outputDir: NVD_RAW_DIR,
      apiKey: process.env.NVD_API_KEY,
    });
    console.log(`[nvd] Fetch done (${runningMs(t)})`);
  } else {
    console.log("[nvd] --skip-fetch: using existing raw files");
  }

  console.log("[nvd] Transforming…");
  const t = Date.now();
  const result = await transformNvdRaw({ rawDir: NVD_RAW_DIR, chunksDir: CHUNKS_DIR });
  console.log(`[nvd] Transform done (${runningMs(t)})`);

  return { fetch_skipped: skipFetch, transform: result };
}

async function runCtf(skipFetch: boolean): Promise<SourceLog> {
  if (!skipFetch) {
    if (!process.env.GITHUB_TOKEN) {
      console.warn("[ctf] GITHUB_TOKEN not set — search rate limit is 10 req/min");
    }
    console.log("[ctf] Scraping repo list…");
    let t = Date.now();
    await scrapeRepos();
    console.log(`[ctf] Scrape done (${runningMs(t)})`);

    console.log("[ctf] Fetching READMEs…");
    t = Date.now();
    await fetchWriteups();
    console.log(`[ctf] Fetch done (${runningMs(t)})`);
  } else {
    console.log("[ctf] --skip-fetch: using existing raw files");
  }

  console.log("[ctf] Transforming…");
  const t = Date.now();
  const result = await transformWriteups();
  console.log(`[ctf] Transform done (${runningMs(t)})`);

  return { fetch_skipped: skipFetch, transform: result };
}

// --- Main ---

async function main() {
  const startedAt = new Date().toISOString();
  const wallStart = Date.now();

  console.log(`\n[run] CTF Intelligence ingestion pipeline`);
  console.log(`[run] flags: skip-fetch=${SKIP_FETCH} nvd-only=${NVD_ONLY} ctf-only=${CTF_ONLY}\n`);

  await ensureDirs();

  // Run sources
  const nvdLog  = (!CTF_ONLY) ? await runNvd(SKIP_FETCH)  : null;
  const ctfLog  = (!NVD_ONLY) ? await runCtf(SKIP_FETCH)  : null;

  // Load both chunk files, dedupe and validate across the combined corpus
  console.log("\n[run] Deduplicating and validating combined corpus…");

  const { readFile } = await import("node:fs/promises");

  async function loadChunks(filePath: string) {
    try {
      return JSON.parse(await readFile(filePath, "utf-8"));
    } catch {
      return []; // file doesn't exist yet if source was skipped
    }
  }

  const nvdChunks = CTF_ONLY  ? [] : await loadChunks(path.join(CHUNKS_DIR, "nvd.json"));
  const ctfChunks = NVD_ONLY  ? [] : await loadChunks(path.join(CHUNKS_DIR, "ctftime.json"));

  const combined        = [...nvdChunks, ...ctfChunks];
  const deduped         = dedupeChunks(combined);
  const valid           = filterValidChunks(deduped);
  const allChunksPath   = path.join(CHUNKS_DIR, "all.json");

  await writeFile(allChunksPath, JSON.stringify(valid, null, 2), "utf-8");

  // Write pipeline.log
  const finishedAt = new Date().toISOString();
  const log: PipelineLog = {
    started_at:  startedAt,
    finished_at: finishedAt,
    flags: { skipFetch: SKIP_FETCH, nvdOnly: NVD_ONLY, ctfOnly: CTF_ONLY },
    sources: {
      nvd:     nvdLog,
      ctftime: ctfLog,
    },
    combined: {
      total_before_dedupe:  combined.length,
      total_after_dedupe:   deduped.length,
      total_after_validate: valid.length,
      written_to:           allChunksPath,
    },
  };

  await writeFile(LOG_PATH, JSON.stringify(log, null, 2), "utf-8");

  // Summary
  console.log(`
[run] ✓ Done in ${runningMs(wallStart)}

  NVD chunks:         ${nvdLog?.transform.transformed  ?? "—"}
  CTFtime chunks:     ${ctfLog?.transform.transformed  ?? "—"}
  After dedupe:       ${deduped.length}
  After validation:   ${valid.length}
  Output:             ${allChunksPath}
  Log:                ${LOG_PATH}
`);
}

main().catch((err) => {
  console.error("[run] Fatal:", err);
  process.exit(1);
});