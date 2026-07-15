import OpenAI from "openai";
import type { RetrievedChunk } from "../query.js";

const MODEL = "gpt-4.1-mini";

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});


function extractJsonArray(
  text:string
):string[]|null {

  try {
    const parsed =
      JSON.parse(text);

    if(Array.isArray(parsed)){
      return parsed;
    }

  } catch {}


  const match =
    text.match(/\[[\s\S]*\]/);


  if(!match){
    return null;
  }


  try {

    const parsed =
      JSON.parse(match[0]);

    return Array.isArray(parsed)
      ? parsed
      : null;

  } catch {

    return null;

  }
}



export async function rerank(
  question:string,
  chunks:RetrievedChunk[],
  topK=8
):Promise<RetrievedChunk[]> {


  if(chunks.length <= topK){
    return chunks;
  }



  const documents =
    chunks.map((c,i)=>`

DOCUMENT ${i}

ID:
${c.id}

SOURCE:
${c.source}

SIMILARITY:
${c.score.toFixed(3)}

METADATA:
${JSON.stringify(c.metadata)}

TEXT:
${c.text.slice(0,2200)}

`).join("\n");



// NOTE: priorities here must stay generic — do not bake in terms specific
// to any one vulnerability class (e.g. SSRF/cloud-metadata terminology).
// This prompt runs for every query regardless of topic; anything added
// here to fix one query's ranking will actively bias every other query
// away from its actual topic. If a specific class needs better recall,
// fix it at the chunk-enrichment layer (transform.ts), not here.
const prompt = `

You are a cybersecurity retrieval reranker.

User question:

${question}


Rank the documents by usefulness for answering the user's specific question.

Ranking priorities:

1. Exact exploit scenario match to the user's question is the highest priority.

2. Prefer documents whose vulnerability class, CWE, or exploitation mechanism directly matches
   what the user is asking about, over documents that are only broadly related.

3. Prefer documents containing exploitation mechanics over documents that only contain
   vulnerability labels.

4. CWE similarity is useful but secondary to actual topical relevance.

5. CTF writeups containing exploit steps should rank above short CVE summaries when applicable
   and equally relevant.

6. Do not rank based only on keyword overlap.

7. Ignore severity unless relevance is otherwise equal.

8. If genuinely none of the documents are relevant to the question, return as many of the
   documents as you can rank by loose relevance rather than an empty list — the caller will
   handle final filtering.


Return ONLY a JSON array of document IDs, ordered most to least relevant.

Example:

[
"id1",
"id2",
"id3"
]


Documents:

${documents}

`;



try {

 const response =
  await client.responses.create({

   model:MODEL,

   input:prompt,

   temperature:0,

  });



 const ids =
  extractJsonArray(
   response.output_text
  );



 console.log(
  "[rerank order]",
  ids
 );



 // Diagnostic: if rerank returned suspiciously few IDs relative to the
 // candidate pool, log the raw model output so we can tell truncation
 // apart from a genuine (if surprising) low-relevance judgment.
 if(!ids || ids.length < chunks.length / 4){

  console.warn(
   "[rerank] suspiciously short result — raw output_text:",
   response.output_text
  );

 }



 // `!ids` alone does not catch a valid-but-empty array ([] is truthy in
 // JS) — that was the actual bug. An empty rerank result must be treated
 // as a failure (or at minimum, trigger the same fallback path), not
 // silently pass through as "0 ranked, fill rest from original order".
 if(!ids || ids.length === 0){

  throw new Error(
   ids
    ? "rerank returned an empty array"
    : "invalid rerank JSON"
  );

 }



 const lookup =
  new Map(
   chunks.map(
    c=>[
     c.id,
     c
    ]
   )
  );



 const ranked =
  ids
   .map(
    id=>lookup.get(id)
   )
   .filter(
    (x):x is RetrievedChunk =>
     Boolean(x)
   );



 if(ranked.length === 0){

  throw new Error(
   "rerank returned ids with no matching candidates"
  );

 }



 const seen =
  new Set(
   ranked.map(
    r=>r.id
   )
  );



 return [
  ...ranked,
  ...chunks.filter(
   c=>!seen.has(c.id)
  )
 ].slice(0,topK);



} catch(err){

 console.warn(
  "[rerank] failed, falling back to similarity-sorted order:",
  err instanceof Error
   ? err.message
   : err
 );


 return chunks
  .slice()
  .sort(
   (a,b)=>b.score-a.score
  )
  .slice(0,topK);

}

}