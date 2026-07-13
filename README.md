# CTF Intelligence Assistant

> Domain-specific RAG system for vulnerability research and CTF challenge support.

> **Status:** Phase 1 & 2 complete. Phase 3 (UI) not started — evaluation harness built and run against the real pipeline.

## What it does
A RAG chatbot that helps users identify and reason through CTF challenge vulnerabilities.
Given a challenge description, it retrieves relevant CVEs, known exploit patterns, and real
CTF writeups to guide troubleshooting conversationally.

Built on top of skills from CS 2340 (Promptception), applied to a domain I actually use.

## Architecture
![Architecture diagram](./docs/architecture.png)
<!-- TODO: export and commit diagram -->

**Phase 1 — Ingestion (complete).** TypeScript pipeline fetching NVD/CVE records (keyword-filtered
across 23 vulnerability-class buckets) and CTF writeups (via GitHub's `topic:ctf-writeup` API),
transformed into a unified, schema-validated, deduplicated chunk corpus.

**Phase 2 — Embedding + retrieval (complete).** Corpus embedded with OpenAI's
`text-embedding-3-small`, stored in a self-hosted Chroma vector database, queried through a
hybrid retrieval layer (see below) with a working end-to-end query CLI.

**Phase 3 — UI + evaluation.** Evaluation harness (RAGAS) is built and has been run against real
retrieval + generation output — see [Evaluation](#evaluation) below. Web UI not yet started.

## Data sources
| Source       | Count   | Coverage                                  |
|--------------|---------|--------------------------------------------|
| NVD/CVE      | 112,978 | SQL injection, XSS, buffer overflow, SSRF, LFI, ... |
| CTF writeups | 1,423   | web, pwn, crypto, forensics, rev, misc     |
| **Total**    | **114,401** | |

> Exact counts generated in `pipeline.log` after running the ingestion pipeline.

## Project structure
```
/ingestion
  /nvd
    fetch.ts          ← hits NVD API, paginates, saves raw JSON
    transform.ts       ← maps raw → chunk schema
  /ctftime
    scrape.ts          ← discovers repos via GitHub topic:ctf-writeup API
    fetch.ts           ← fetches READMEs, resume-safe tombstoning
    transform.ts        ← maps raw → chunk schema, semantic chunking on headings
  /shared
    schema.ts          ← discriminated union chunk type (NvdChunk | CtfChunk)
    dedupe.ts           ← deduplication by source:id
    validate.ts          ← filters out empty/short/broken chunks
  run.ts               ← orchestrates fetch → transform → merge → dedupe → validate
/scripts
  /eval
    generate-answer.ts  ← grounded answer generation for eval (also usable standalone)
    export-for-ragas.ts ← runs real questions through retrieve()+generateAnswer(), exports JSONL
  upsert.ts             ← embeds/writes vectors + metadata into Chroma
  query.ts              ← query CLI, hybrid NVD/CTF retrieval, citation formatting
/eval
  run_ragas.py          ← RAGAS scoring (Python — see Evaluation)
  requirements.txt
  results.json / RESULTS.md  ← latest eval output
/data
  /raw                  ← untouched API/scrape output
  /chunks               ← cleaned, schema-validated chunks (all.json) + embeddings (all.embedded.jsonl)
  /eval
    questions.json       ← eval question set
    ragas_input.jsonl     ← exported retrieve()+generate() output, RAGAS input
```

## Setup & running
### Prerequisites
- Node.js + `npx tsx`
- Python 3.13 with `pip`
- An OpenAI API key with billing enabled (embedding + generation + RAGAS's LLM judge all use it)

### Installation
```bash
npm install
pip install -r eval/requirements.txt --break-system-packages
cp .env.example .env   # fill in OPENAI_API_KEY
```

### Running the ingestion pipeline
```bash
npm run ingest              # full pipeline: fetch + transform + merge, both sources
npm run ingest:skip-fetch   # re-transform + re-merge from already-fetched raw data, no network calls
```

### Running the embedding + retrieval pipeline
```bash
npx tsx ingestion/embed/embed.ts --dry-run   # sanity-check shape, zero API cost
npx tsx ingestion/embed/embed.ts             # real embed — ~$0.50 one-time for the full corpus
npm run chroma                               # start local Chroma server (separate terminal, leave running)
npm run upsert                               # write embeddings into Chroma
```

### Querying
```bash
npx tsx scripts/query.ts "your CTF challenge description or question here"
```

Retrieval is hybrid by default: NVD (~99% of the corpus) and CTF writeups (~1.2%) are queried as
separate pools and merged, with a guaranteed floor of CTF results, rather than one combined search
where CTF chunks get statistically crowded out by NVD's volume advantage. See
[Architecture decisions](#architecture-decisions).

## Evaluation
RAGAS-based evaluation, run against the real `retrieve()` + `generateAnswer()` pipeline (not a
synthetic approximation) over a 10-question eval set of realistic CTF-challenge-style prompts.

```bash
npx tsx scripts/eval/export-for-ragas.ts
python eval/run_ragas.py
```

**Latest results** (10 questions, 6 with ground-truth reference answers):

| Metric | Score |
|---|---|
| Faithfulness (n=10) | 0.794 |
| Context recall (n=6) | 0.861 |
| Context precision (n=6) | 0.808 |

| Source group | Faithfulness |
|---|---|
| NVD-style questions (n=4) | 0.750 |
| CTF-writeup-style questions (n=6) | 0.824 |

Full per-question breakdown in [`eval/RESULTS.md`](./eval/RESULTS.md).

**Honest caveats:**
- **n=10 is a demo-scale eval, not a statistically rigorous one.** These numbers show the
  pipeline works end-to-end and that the eval harness catches real failures (see below) — they
  aren't precise enough to claim a specific faithfulness percentile with confidence.
- **`answer_relevancy` is not included.** RAGAS 0.4.3 has a broken embeddings wrapper internally
  (`AttributeError: 'OpenAIEmbeddings' object has no attribute 'embed_query'`) that isn't fixable
  from this project's side — a bug in RAGAS's own dependency chain, not in this pipeline.
- **One question (SSRF) scored faithfulness 0.000** — the model answered from general training
  knowledge instead of the retrieved context. Confirmed via manual query (`npx tsx scripts/query.ts
  "SSRF"`) that this is *not* a corpus coverage gap — the corpus has strong, directly relevant
  material (a dedicated SSRF CTF writeup at rank #1, five NVD CVEs explicitly tagged CWE-918).
  This is a pure generation-side failure: `generateAnswer()`'s system prompt says to use only the
  provided context, but doesn't stop the model from ignoring that instruction when it's confident
  in an answer from its own training data. Left in the results deliberately rather than dropped —
  a RAGAS harness that only ever returns clean numbers isn't demonstrating anything, and this is
  the eval correctly catching a real failure mode. Next step: tighten the system prompt to force
  an explicit "not covered in retrieved context" fallback rather than allowing confident
  parametric answers to slip through.

## Architecture decisions
Brief ADR-style notes on the non-obvious choices, mostly ones that only became clear after hitting
real bugs against real data at scale:

- **Semantic chunking** — writeups vary wildly in length; fixed-size chunking loses context.
- **JSONL over a single JSON array for embeddings** — at ~114k chunks × 1536-dim vectors, a single
  `JSON.stringify()`/`JSON.parse()` over the whole embedded corpus builds one JS string well past
  V8's string-length ceiling (`RangeError: Invalid string length`). One record per line means no
  read, write, or parse operation ever touches more than one line/batch at a time.
- **Chroma over Pinecone** — Pinecone's free tier caps at 100k vectors; the corpus is ~114k.
  Self-hosted Chroma (v2 REST API — the v1 surface was removed entirely as of Chroma 1.0.0)
  avoids that ceiling for local dev. Deploy target for Chroma itself is still an open question
  (serverless hosts don't map cleanly onto a persistent vector DB process).
- **Hybrid retrieval merge** — CTF writeups are ~1.2% of the corpus by volume. An unfiltered
  single search let NVD's volume advantage crowd CTF chunks out of results entirely for
  CTF-phrased queries, even when a highly relevant CTF writeup existed. Retrieval now queries
  each source pool separately and reserves a floor (~25% of top-k) for CTF results, then merges
  by score — confirmed by hand that CTF results can and do rank #1 on their own merit post-merge,
  not just fill the reserved floor.
- **`nvd.json`/`ctftime.json` are always merged into `all.json` regardless of which ingestion flag
  was passed** — `--nvd-only`/`--ctf-only` control what gets *fetched/transformed* that run, not
  what gets merged into the combined output. (Earlier version of `run.ts` gated the merge on these
  flags too, which meant running `--ctf-only` silently overwrote `all.json` with only the ~1,400
  CTF chunks, discarding the 113k already-ingested NVD corpus from the combined output. Caught via
  a chunk-count sanity check, not a crash — worth verifying `all.json`'s source counts after any
  targeted ingestion run.)

## Changelog
- `2025-04-22` — Phase 1 (partial): NVD/CVE ingestion pipeline
- `2026-07-11` — Phase 1 complete: NVD ingestion pipeline (113,055 chunks across 23 keyword buckets)
- `2026-07-12` — Phase 1 complete: CTFtime writeup ingestion added (1,423 chunks); Phase 2 complete:
  full corpus embedded and upserted into Chroma (114,401 vectors); hybrid retrieval merge added
- `2026-07-13` — RAGAS evaluation harness built and run against real pipeline output (10-question
  eval set, faithfulness/context recall/context precision)
- `TBD` — Phase 3: web UI, deployment