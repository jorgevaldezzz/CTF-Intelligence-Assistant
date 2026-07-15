# CTF Intelligence Assistant

> Domain-specific RAG system for vulnerability research and CTF challenge support.

A retrieval-augmented security research system that investigates how well retrieval-augmented
generation can support real vulnerability-research and CTF exploitation reasoning — not just a
chatbot wrapper, but a testbed for studying retrieval quality, grounding behavior, and failure
modes over a large, structurally mixed corpus of formal vulnerability records and informal
practitioner writeups.

Originally inspired by coursework in retrieval-augmented generation and prompt engineering,
expanded into an independent security retrieval research project.

> **Status:** Phase 1 & 2 complete. Phase 3 (UI layer) deferred while retrieval quality,
> evaluation, and system behavior remain the primary focus.

## What it does
Given a CTF challenge description, it retrieves relevant CVEs, known exploit patterns, and real
CTF writeups to guide troubleshooting conversationally — grounded in retrieved evidence rather
than the model's parametric knowledge alone.

## Architecture

**Phase 1 — Ingestion (complete).** TypeScript pipeline fetching NVD/CVE records (keyword-filtered
across expanding vulnerability-class buckets) and CTF writeups (via GitHub's `topic:ctf-writeup`
API), transformed into a unified, schema-validated, deduplicated chunk corpus.

**Phase 2 — Embedding + retrieval (complete).** Corpus embedded with OpenAI's
`text-embedding-3-small`, stored in a locally deployed Chroma vector database, queried through a
hybrid retrieval layer with score normalization and LLM-based reranking.

**Phase 3 — Evaluation + UI.** Evaluation harness (RAGAS) built and run against real
retrieval + generation output. UI is planned, but current development prioritizes retrieval
quality and system reliability.

## Results

The central finding of this project: **retrieval quality, not model choice or prompt tuning, was
the dominant factor in answer quality.**

- The two largest faithfulness improvements found during evaluation both came from fixing
  *retrieval* — not from changing the generation model or prompt.
- The two data sources are complementary in a specific way: **CTF writeups provided richer,
  step-by-step exploitation context**, while **NVD provided structured, authoritative
  vulnerability metadata** (CWE, CVSS severity, affected software). Neither source alone would
  have been sufficient.
- Every generation-quality issue found traced back to *what was retrieved*, not to the language
  model's reasoning — reinforcing that for this domain, context selection matters more than
  swapping models.

See [Evaluation](#evaluation) for the numbers and [Engineering Notes](./ENGINEERING_NOTES.md)
for how these findings were reached.

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
| Faithfulness (n=10) | 0.827 |
| Context recall (n=6) | 0.861 |
| Context precision (n=6) | 1.000 |

| Source group | Faithfulness |
|---|---|
| NVD-style questions (n=4) | 0.671 |
| CTF-writeup-style questions (n=6) | 0.931 |

Full per-question breakdown in [`eval/RESULTS.md`](./eval/RESULTS.md).

**Honest caveats:**
- **n=10 is a demo-scale eval, not a statistically rigorous one.** Per-question results are noisy
  at this sample size — the aggregate shouldn't be read as a precise percentile, and which single
  question scores lowest has flipped across runs as fixes landed.
- **`answer_relevancy` is not included.** RAGAS 0.4.3 has a broken embeddings wrapper internally
  that isn't fixable from this project's side — a bug in RAGAS's own dependency chain.
- **One open, unresolved failure**: a file-upload-to-RCE question scores 0.000 faithfulness despite
  clean, relevant retrieval — the generation prompt refuses on a genuine match. See
  [Prompt Grounding Experiments](#prompt-grounding-experiments) below.
- **One known side effect**: fixing retrieval score normalization (see Engineering Notes) improved
  one previously-failing question to 1.000 but coincided with a context-recall dip on two others.
  Not yet disambiguated from eval noise at this sample size.

### Prompt Grounding Experiments
Two incidents while tuning the generation system prompt, on two different questions, showed
grounding strictness is a real precision/recall tradeoff in both directions — an under-strict
prompt fabricated an answer past a real retrieval gap (SSRF question, before the fix below), and
an over-strict prompt refused to answer despite a genuine, retrieved match (file-upload question,
still open). The stricter prompt was kept, judged a safer failure mode for this domain, but it's
a judgment call, not a solved problem.

**Results:** retrieval quality remained the bottleneck even here — the SSRF case stopped being a
prompt problem entirely once retrieval was fixed (see below), while the file-upload case remains
a genuine generation-side issue precisely because retrieval is *already* clean for it. Better
context selection resolved more failures than any prompt adjustment did.

Full incident details: [Engineering Notes](./ENGINEERING_NOTES.md#grounding-strictness-tradeoff-accepted-not-solved).

## Engineering Notes
Full debugging narratives live in [`ENGINEERING_NOTES.md`](./ENGINEERING_NOTES.md). Summarized
here for anyone skimming:

- **SSRF / cloud-metadata retrieval gap (fixed).** Cloud-metadata SSRF questions failed retrieval
  despite the relevant `CWE-918` records already existing in the corpus. Cause: a vocabulary
  mismatch — terse CVE descriptions rarely spell out exact terms like `169.254.169.254` or
  provider-specific metadata service names, so narratively-phrased questions could miss them on
  both embedding similarity and lexical matching. Fixed by enriching every CWE-918 chunk with
  AWS/Azure/GCP metadata-service terminology, IMDS, and IAM-credential language at the
  ingestion/transform layer — no changes to embeddings, vector DB, or reranker were needed.
- **UAF retrieval failure, traced through three wrong hypotheses to a real fix.** A use-after-free
  question returned zero relevant NVD results despite the corpus having strong `CWE-416` matches.
  Ruled out corpus coverage, then a reranker bug (real, fixed, but not the cause here), then hybrid
  floor logic (also not the cause), before finding the actual root cause: NVD's terse CVE text and
  CTF's narrative prose don't produce comparable embedding-similarity magnitudes, so raw
  cross-pool score comparison systematically favored CTF regardless of relevance. Fixed via
  per-pool z-score normalization before merging.
- **A known, undisambiguated side effect** and **two smaller diagnostic fixes** (an ingestion
  skip-count attribution issue, and an embed-script resumability gotcha) are documented in full
  in Engineering Notes.

## Architecture Decisions
Final design choices. See [Engineering Notes](./ENGINEERING_NOTES.md) for the investigations
behind each of these.

- **Semantic chunking** — writeups vary wildly in length; fixed-size chunking loses context.
- **JSONL over a single JSON array for embeddings** — at ~137k chunks × 1536-dim vectors, a single
  `JSON.stringify()`/`JSON.parse()` over the whole embedded corpus exceeds V8's string-length
  ceiling. One record per line avoids that entirely.
- **Chroma over Pinecone** — Pinecone's free tier caps at 100k vectors; the corpus is ~137k.
  Self-managed Chroma (v2 REST API) avoids that ceiling for local dev.
- **Hybrid retrieval with a symmetric floor plus score normalization.** Querying NVD and CTF as
  separate pools with a guaranteed floor for both, then normalizing each pool's scores
  independently before merging, prevents either pool's writing style (terse vs. narrative) from
  systematically crowding out the other regardless of actual topical relevance.
- **CWE-918 chunk enrichment.** Guaranteeing exact-phrase cloud-provider terminology in embedded
  text, rather than relying on raw CVE description wording, closes a vocabulary-mismatch gap that
  affects narrow, jargon-dense CWE categories. The pattern is intentionally generalizable to other
  CWEs, currently wired up for CWE-918 only.

## Data Sources
| Source       | Count   | Coverage                                  |
|--------------|---------|--------------------------------------------|
| NVD/CVE      | 135,839 | SQL injection, XSS, buffer overflow, SSRF, LFI, ... |
| CTF writeups | 1,456   | web, pwn, crypto, forensics, rev, misc     |
| **Total**    | **137,284** | |

> Exact counts generated in `pipeline.log` after running the ingestion pipeline.

## Project structure
```
/ingestion
  /nvd
    fetch.ts           <- hits NVD API, paginates, saves raw JSON
    transform.ts       <- maps raw -> chunk schema, CWE alias + technique + SSRF enrichment
  /ctftime
    scrape.ts          <- discovers repos via GitHub topic:ctf-writeup API
    fetch.ts           <- fetches READMEs, resume-safe tombstoning
    transform.ts       <- maps raw -> chunk schema, semantic chunking on headings
  /embed
    embed.ts           <- creates embeddings for the cleaned corpus
  /shared
    schema.ts          <- discriminated union chunk type (NvdChunk | CtfChunk)
    dedupe.ts           <- deduplication by source:id
    validate.ts          <- filters out empty/short/broken chunks
  run.ts               <- orchestrates fetch -> transform -> merge -> dedupe -> validate
/scripts
  debug.ts             <- ad hoc debugging helpers
  query.ts             <- query CLI, hybrid NVD/CTF retrieval, citation formatting
  start-chroma.ps1     <- starts the local Chroma server
  upsert.ts            <- embeds/writes vectors + metadata into Chroma
  /enrichment
    cwe.ts             <- CWE alias lookups
    technique.ts       <- ATT&CK technique extraction
  /eval
    generate-answer.ts  <- grounded answer generation for eval (also usable standalone)
    export-for-ragas.ts <- runs real questions through retrieve()+generateAnswer(), exports JSONL
  /retrieval
    chroma.ts          <- Chroma client / vector store access
    hybrid.ts          <- pool-aware hybrid retrieval merge
    rerank.ts          <- reranking layer for candidate ordering
/eval
  run_ragas.py         <- RAGAS scoring (Python)
  requirements.txt
  results.json / RESULTS.md <- latest eval output
/data
  /raw                  <- untouched API/scrape output
  /chunks               <- cleaned, schema-validated chunks (all.json) + embeddings (all.embedded.jsonl)
  /eval
    questions.json      <- eval question set
    ragas_input.jsonl   <- exported retrieve()+generate() output, RAGAS input
/ui
  index.html            <- browser UI entry point
  styles.css            <- UI styling
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
npx tsx ingestion/embed/embed.ts             # real embed — ~$0.50-1 one-time for the full corpus
npm run chroma                               # start local Chroma server (separate terminal, leave running)
npm run upsert                               # write embeddings into Chroma
```

> **Note:** the embed script's resumability is keyed by chunk ID, not content hash. After changing
> `transform.ts`'s enrichment logic, delete/move `all.embedded.jsonl` before re-embedding, or
> unchanged IDs will be skipped even though their text changed. See Engineering Notes for how this
> was caught.

### Querying
```bash
npx tsx scripts/query.ts "your CTF challenge description or question here"
```

Retrieval is hybrid by default: NVD and CTF writeups are queried as separate pools, score-normalized
independently, then merged with a guaranteed floor for both — rather than one combined search
where either pool can crowd the other out. See [Architecture Decisions](#architecture-decisions).

### Example query
```
$ npx tsx scripts/query.ts "web app export feature fetches an internal URL I supply — how could I use this to reach a cloud metadata endpoint?"
```

Retrieved sources (top results, abbreviated):
```
1. [nvd] CVE-2024-51408 (8.5, CWE-918) — AppSmith SSRF via New DataSource, retrieves AWS metadata credentials
2. [ctftime] "SSRF to IAM Credential Theft" — writeup, Vulnerable-Bank CTF
3. [nvd] CVE-2016-0896 (7.3, CWE-254) — PCF Elastic Runtime, 169.254.169.254 network restriction bypass
```

Generated answer (grounded, citing sources):
> This is server-side request forgery (SSRF) — the export feature is making a server-initiated
> request to an attacker-supplied URL. In a cloud environment, pointing that URL at
> `169.254.169.254` (the AWS/Azure/GCP metadata endpoint) can expose instance credentials via the
> Instance Metadata Service, as seen in CVE-2024-51408 [1]. A CTF writeup [2] documents the same
> pattern end-to-end, pivoting from the SSRF to IAM credential theft...

## Changelog
- `2025-04-22` — Phase 1 (partial): NVD/CVE ingestion pipeline
- `2026-07-11` — Phase 1 complete: NVD ingestion pipeline (113,055 chunks across 23 keyword buckets)
- `2026-07-12` — Phase 1 complete: CTFtime writeup ingestion added (1,423 chunks); Phase 2 complete:
  full corpus embedded and upserted into Chroma (114,401 vectors); hybrid retrieval merge added
- `2026-07-13` — RAGAS evaluation harness built and run against real pipeline output (10-question
  eval set, faithfulness/context recall/context precision)
- `2026-07-13` — Symmetric hybrid retrieval floor (both NVD and CTF pools protected, not just CTF);
  `generateAnswer()` grounding-strictness tuned and documented as a real precision/recall tradeoff
- `2026-07-15` — Expanded NVD keyword-bucket coverage (113,055 → 135,839 NVD chunks, 137,284 total).
  CWE-918 (SSRF) enrichment: guaranteed cloud-provider metadata terminology in embedded text.
  SSRF question faithfulness: 0.000 → 0.917 (verified via manual retrieval check, not eval score
  alone). Fixed a reranker prompt bias and an empty-array falsy-check bug (both real defects,
  neither the root cause of the UAF failure). Root-caused and fixed a systematic score-scale
  asymmetry between NVD and CTF pools via per-pool z-score normalization — UAF question
  faithfulness: 0.000 → 1.000. Split ingestion skip counter into duplicate/no-description causes
  for diagnosability. Open items: file-upload question still refuses on a genuine match (prompt
  grounding tradeoff, accepted not solved); reranker degrades on dense candidate pools for some
  queries even with correct retrieval (documented, not yet fixed); minor context-recall side
  effect from the normalization fix, not yet disambiguated from eval noise.
- `TBD` — Phase 3: web UI, deployment

---

**Project status:** this project prioritizes reliability and understanding actual system behavior
over adding complexity. Every fix documented here came from measuring, reproducing, and verifying
a specific failure — not from assuming a bigger model or more features would help. Retrieval
quality, evaluated honestly, drove nearly every real improvement found.