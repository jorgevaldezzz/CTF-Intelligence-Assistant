# Engineering Notes

Detailed debugging narratives for non-obvious bugs found while building this project. The
README's Architecture Decisions section links here for anyone who wants the full story behind
a given decision; this doc is the "how we found it" version, not just "what we decided."

---

## SSRF / cloud-metadata retrieval gap (fixed)

**Symptom:** An SSRF question asking about pivoting to a cloud metadata endpoint scored 0.000
faithfulness in RAGAS eval.

**Root cause:** CWE-918 chunks didn't reliably carry exact-phrase cloud-provider terminology
(`169.254.169.254`, `Instance Metadata Service (IMDS)`, `Azure Metadata Service`, `Google Cloud
Metadata Server`, `IAM credentials`, `Cloud credential theft`) in their embedded text. Many CVE
descriptions are terse and don't spell these out even when clearly relevant, so narratively-phrased
questions could miss them on both embedding similarity and lexical matching.

**Fix:** `enrichSsrfMetadata()` in `ingestion/nvd/transform.ts` appends the full term set verbatim
to every CWE-918 chunk's embedded text. Also wired in the previously-unused `cwe.ts` alias table
and `technique.ts` extractor, which existed but were never actually called from the transform
pipeline.

**Verification:** Confirmed via `scripts/query.ts` before/after (manual retrieval check, not just
the eval score) — the fix changed what retrieval actually returns, not just the aggregate number.
Faithfulness on this question: 0.000 → 0.846-0.917 across eval runs.

---

## Grounding strictness tradeoff (accepted, not solved)

Two incidents while tuning `generateAnswer()`'s system prompt, on two different questions:

- **Under-strict** (original prompt): an SSRF question was answered confidently from the model's
  general training knowledge, ignoring that retrieved context didn't cover the specific technique
  asked about. Faithfulness: 0.000. Confirmed via manual query that the corpus *did* have on-topic
  material — the model just wasn't using it. Fixed by requiring an explicit refusal when context
  doesn't cover the *specific* thing asked.
- **Over-strict** (tightened prompt): a file-upload-to-RCE question was refused outright despite
  retrieved context containing a near-exact match (unrestricted-file-upload CVE, web-shell-upload
  language). Faithfulness: 0.000. Reproduced across multiple eval runs with different specific CVEs
  surfacing — same root cause each time, retrieval clean, generation refusing anyway.

**Decision:** kept the stricter prompt. Refusing on a real match is judged a safer failure mode
for this domain than fabricating past a real gap — but this is a judgment call, not a solved
problem. A third prompt iteration risks becoming a whack-a-mole loop without converging, so it's
documented here rather than chased further.

---

## UAF retrieval failure → reranker prompt bias → merge scoring asymmetry (fixed, with an open sub-issue)

This one went through three wrong hypotheses before landing on the real fix — kept in full because
the process is the actual engineering lesson.

**Symptom:** A use-after-free (UAF) exploitation question scored 0.000 faithfulness. Manual
retrieval showed only 1 distinct candidate surviving reranking, all CTF, zero NVD.

**Hypothesis 1 (wrong): corpus coverage gap.** Assumed the corpus simply lacked strong UAF
material. Disproven by running an NVD-only query for the same topic — 8 clean, directly relevant
`CWE-416` results came back immediately. The material was there.

**Hypothesis 2 (wrong): reranker silently failing.** Investigation found `scripts/retrieval/rerank.ts`
had a real bug — `if(!ids)` doesn't catch a valid-but-empty array (`![]` is `true`... no,
`![]` is `false` in JS, meaning the check never fires for `[]`), so an empty rerank result fell
through silently to unranked candidate order with no error surfaced. Also found the rerank prompt
had hardcoded SSRF/cloud-metadata bias baked into its ranking priorities — leftover from the SSRF
fix above, never removed, actively penalizing every non-SSRF query. Both were real bugs and were
fixed (generic prompt, `!ids || ids.length === 0` check). **But fixing both made zero measurable
difference to the UAF query** — same exact scores, same single result. This ruled out rerank as
the primary cause for this specific failure, though both fixes were correct and worth keeping.

**Hypothesis 3 (wrong): hybrid merge/floor logic.** Suspected the CTF floor was crowding out NVD
results during merge. Disproven by running the query with `--no-hybrid` (single unrestricted
search, no pool separation) — result was byte-identical to the hybrid run. NVD's `CWE-416` chunks
were losing on raw cosine similarity even with no floor logic involved at all.

**Root cause (confirmed): systematic score-scale asymmetry between pools.** Terse CVE description
text and narrative CTF writeup prose don't produce comparable embedding-similarity magnitudes even
for equally relevant content. Confirmed directly: CTF prose scored ~1.03–1.11 on this query, NVD's
genuinely relevant `CWE-416` CVEs scored ~0.63–0.68 standalone. Raw-score comparison across pools
systematically favors whichever pool's writing style happens to score higher for a given query,
independent of actual relevance. Same underlying phenomenon as the original SSRF floor problem,
just resurfacing in a form the floor couldn't fix, since a floor guarantees *inclusion*, not
survival past re-sorting/truncation.

**Fix:** `zScoreNormalize()` in `scripts/query.ts` — normalizes each pool's scores independently
(subtract pool mean, divide by pool stddev) before merging, so ranking reflects "how good is this
relative to its own pool's distribution" rather than raw magnitude. Applied to both `nvd` and `ctf`
pools right after their parallel `rawQuery` calls, before floor-slicing.

**Verification:** Pool breakdown logging added to `retrieve()` (`[retrieval] pool breakdown: {...}`)
confirmed the candidate pool went from effectively CTF-only to a balanced 15/15 NVD/CTF split.
Final reranked results for the UAF query went from 0 relevant NVD CVEs to 5. RAGAS re-run confirmed
this in aggregate: UAF question faithfulness 0.000 → 1.000.

**Open sub-issue, not fixed:** even after retrieval was fixed, the reranker itself still degraded
on this specific query — it returned only 1 ranked ID (a *format string* writeup, not UAF-specific)
despite being handed a balanced, genuinely relevant 30-document pool. Raw model output was
confirmed complete and valid JSON, not truncated — the model itself judged only 1 document
relevant, incorrectly. Likely cause: reranking ~30 documents at up to 2,200 chars each (60k+
characters) in one call to `gpt-4.1-mini` runs into "lost in the middle" attention degradation,
especially over many similarly-formatted, terse chunks (`CVE ID: ... CWE-416...` repeated many
times) where the actually relevant signal is diluted. The SQL-injection eval question didn't
trigger this because CTF writeup titles were extremely on-the-nose ("SQL Injection — Authentication
Bypass"), making relevance easy to spot even with degraded attention.

Retrieval feeds rerank a correct, balanced, relevant candidate pool now — that part is solid and
verified. Reranking quality on dense/repetitive pools is a known, documented limitation, not
chased further given the scope of this project. Reasonable future directions: shrink `CANDIDATE_K`,
truncate document text more aggressively before reranking, or use a stronger rerank model.

---

## Side effect: context_recall regression after the z-score normalization fix

The normalization fix that solved UAF retrieval also changed scoring for every other hybrid query,
since it changes which chunks win the floor/merge tradeoff generally, not just for UAF-shaped
questions. Two ground-truth questions (q001, q009) saw context_recall drop from 1.0 to 0.667/0.500
in the same eval run where UAF went from 0.000 to 1.000 faithfulness.

Given this is a demo-scale n=10 eval, it isn't possible to say with confidence whether this is
genuine noise (the README's eval caveats already document that per-question results are volatile
at this sample size) or a real, smaller side effect of the same fix. Documented rather than
resolved — would need a larger eval set to disambiguate.

---

## Ingestion skip-count attribution

A re-transform run reported 41,300 skipped chunks out of ~177k processed records — alarming at
first glance. Split the skip counter in `transform.ts` into `duplicate` vs. `no-id/no-description`
rather than guessing from the aggregate. All 41,300 turned out to be legitimate cross-bucket
dedup (the same CVE surfacing across multiple overlapping keyword buckets), zero data loss. Kept
the split counters rather than reverting — a single combined number can't distinguish "working as
intended" from "silently dropping valid records," and the five minutes it took to split them
resolved real uncertainty instead of assuming the best case.

---

## Embed-script resumability gotcha

The embed script's resumability is keyed by chunk ID, not content hash. After changing
`transform.ts`'s enrichment logic (new text appended to existing chunks), the embed script saw
familiar IDs and skipped them entirely — meaning a "successful" resumable run silently produced
zero new embeddings, since the underlying text had changed but the ID hadn't. Caught by checking
one sample line's embedding vector rather than trusting the `embedded=0` log line at face value.
Fix going forward: delete/move `all.embedded.jsonl` before any re-embed following an enrichment
change, rather than relying on resumability.