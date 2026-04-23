# CTF Intelligence Assistant

> Domain-specific RAG system for vulnerability research and CTF challenge support.

> **Status:** Phase 1 in progress - NVD ingestion complete, CTFtime scraper pending

## What it does
A RAG chatbot that helps users identify and reason through CTF challenge vulnerabilities. 
Given a challenge description or files, it retrieves relevant CVEs, known exploit patterns, 
and real CTF writeups to guide troubleshooting conversationally.

Built on top of skills from CS 2340 (Promptception), applied to a domain I actually use.

## Architecture
![Architecture diagram](./docs/architecture.png)
<!-- TODO: export and commit diagram -->  

Phase 1: Scaffold the TypeScript ingestion pipeline, with both NVD fetching and CTFtime writeups scraping.
Phase 2: Embed the cleaned chunk JSONs, store vectors plus metadata in a retrieval index.
Phase 3: Build the website then host it on Vercel and use it during the next CTF competition and improve failures based on that.

## Data sources
| Source     | Count  | Coverage                        |
|------------|--------|---------------------------------|
| NVD/CVE | ~6,200 | SQL injection, XSS, buffer overflow, ... |
| CTF writeups | ~800 | web, pwn, crypto, forensics, rev |

> Exact counts generated in `pipeline.log` after running the ingestion pipeline.

## Project structure
/ingestion
  /nvd
    fetch.ts        ← hits NVD API, paginates, saves raw JSON
    transform.ts    ← maps raw → chunk schema
  /ctftime
    scrape.ts       ← scrapes writeup list, queues URLs
    fetch.ts        ← fetches + extracts each writeup page
    transform.ts    ← maps raw → chunk schema
  /shared
    schema.ts       ← chunk TypeScript type
    dedupe.ts       ← deduplication by URL / CVE ID
    validate.ts     ← filters out empty/short/broken chunks
  run.ts            ← orchestrates the full pipeline
/data
  /raw              ← untouched API/scrape output
  /chunks           ← cleaned, schema-validated output (input to Phase 2)

## Setup & running
### Prerequisites
### Installation
### Running the ingestion pipeline
### Running the app

## Evaluation
(Fill in Phase 3 — placeholder for now)
| Metric            | Score |
|-------------------|-------|
| Faithfulness      | —     |
| Context recall    | —     |

## Architecture decisions
Brief ADR-style notes. 
- **Semantic chunking** - writeups vary wildly in length; fixed-size chunking lost context ← for when CTFtime writeups ingestion is completed

## Changelog
- `2025-04-22` - Phase 1 (partial): NVD/CVE ingestion pipeline
- `TBD` - Phase 2: embedding + retrieval
- `TBD` - Phase 3: UI + evaluation