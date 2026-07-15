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



const prompt = `

You are a cybersecurity retrieval reranker.

User question:

${question}


Rank the documents by usefulness for answering the question.

Ranking priorities:

1. Exact exploit scenario match is the highest priority.

2. Prefer documents describing:
- cloud metadata services
- AWS EC2 metadata
- GCP metadata
- Azure IMDS
- credential theft
- internal HTTP requests
- attacker controlled URL fetching
- unauthenticated SSRF exploitation

3. Prefer documents containing exploitation mechanics over documents that only contain vulnerability labels.

4. CWE similarity is useful but secondary.

5. A generic SSRF vulnerability is less useful than a document describing metadata service access.

6. CTF writeups containing exploit steps should rank above short CVE summaries when applicable.

7. Do not rank based only on keyword overlap.

8. Ignore severity unless relevance is otherwise equal.


Return ONLY a JSON array of document IDs.

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



 if(!ids){

  throw new Error(
   "invalid rerank JSON"
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
  "[rerank] failed:",
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