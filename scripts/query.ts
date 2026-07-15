import "dotenv/config";
import OpenAI from "openai";
import { pathToFileURL } from "node:url";
import { rerank } from "./retrieval/rerank.js";


const EMBED_MODEL = "text-embedding-3-small";


const CHROMA_BASE_URL =
  (
    process.env.CHROMA_URL ??
    "http://localhost:8000"
  )
  .replace(/\/+$/, "");


const COLLECTION =
  process.env.CHROMA_COLLECTION ??
  "ctf-intelligence";


const TENANT =
  process.env.CHROMA_TENANT ??
  "default_tenant";


const DATABASE =
  process.env.CHROMA_DATABASE ??
  "default_database";



// Retrieval tuning
//
// Wide recall -> lexical boost -> LLM rerank
//
const CANDIDATE_K = 30;
const FINAL_K = 8;



function chromaHeaders(): HeadersInit {

  const headers:Record<string,string> = {
    "Content-Type":"application/json",
  };


  if(process.env.CHROMA_API_KEY){

    headers["x-chroma-token"] =
      process.env.CHROMA_API_KEY;

  }


  return headers;
}



function collectionsUrl():string {

  return `${CHROMA_BASE_URL}/api/v2/tenants/${encodeURIComponent(
    TENANT
  )}/databases/${encodeURIComponent(
    DATABASE
  )}/collections`;

}



let cachedCollectionId:string|null = null;



async function resolveCollectionId():Promise<string>{


  if(cachedCollectionId){

    return cachedCollectionId;

  }



  const res =
    await fetch(
      `${collectionsUrl()}?limit=100`,
      {
        headers:chromaHeaders(),
      }
    );



  if(!res.ok){

    throw new Error(
      `Failed listing collections: ${res.status}`
    );

  }



  const collections =
    await res.json() as Array<{
      id:string;
      name:string;
    }>;



  const match =
    collections.find(
      c=>c.name===COLLECTION
    );



  if(!match){

    throw new Error(
      `Collection "${COLLECTION}" not found`
    );

  }



  cachedCollectionId =
    match.id;


  return match.id;

}




interface RawQueryResult {

  ids?:string[][];

  distances?:number[][];

  documents?:string[][];

  metadatas?:Record<string,unknown>[][];

}



export interface RetrievedChunk {

  id:string;

  text:string;

  citation:string;

  url:string;

  score:number;

  source:string;

  metadata:Record<string,unknown>;

}





function formatCitation(
  metadata:Record<string,unknown>
):string {


  if(metadata.source==="nvd"){

    return `${metadata.id ?? ""} (${metadata.severity ?? "no severity"}, ${
      metadata.cwe ?? "no CWE"
    })`;

  }



  return `${metadata.challenge ?? "?"} — ${
    metadata.event ?? "?"
  }`;

}





async function rawQuery(
  vector:number[],
  limit:number,
  where?:Record<string,unknown>
):Promise<RetrievedChunk[]>{


  const collectionId =
    await resolveCollectionId();



  const response =
    await fetch(
      `${collectionsUrl()}/${encodeURIComponent(
        collectionId
      )}/query`,
      {

        method:"POST",

        headers:chromaHeaders(),

        body:JSON.stringify({

          query_embeddings:[
            vector
          ],

          n_results:limit,


          where:
            where &&
            Object.keys(where).length
              ? where
              : undefined,

        }),

      }
    );




  if(!response.ok){

    throw new Error(
      `Chroma query failed ${response.status}: ${
        await response.text()
      }`
    );

  }




  const result =
    await response.json() as RawQueryResult;



  const ids =
    result.ids?.[0] ?? [];


  const distances =
    result.distances?.[0] ?? [];


  const documents =
    result.documents?.[0] ?? [];


  const metadatas =
    result.metadatas?.[0] ?? [];




  return ids.map(
    (id,i)=>{


      const metadata =
        metadatas[i] ?? {};



      return {

        id,

        text:
          documents[i] ?? "",


        citation:
          formatCitation(metadata),


        url:
          (metadata.url as string)
          ?? "",


        score:
          1 -
          (distances[i] ?? 1),



        source:
          (metadata.source as string)
          ?? "unknown",



        metadata,

      };

    }
  );

}





function dedupeChunks(
  chunks:RetrievedChunk[]
):RetrievedChunk[]{


  return [
    ...new Map(
      chunks.map(
        c=>[
          c.id,
          c
        ]
      )
    ).values()
  ];

}





// Corrects a systematic scale mismatch between pools: terse CVE text and
// narrative CTF writeup prose do not produce comparable cosine-similarity
// magnitudes even when equally relevant to a query. Comparing raw scores
// across pools silently favors whichever pool happens to score higher on
// average for a given query's writing style, regardless of actual
// relevance (confirmed by hand: narrative pwn/SSRF questions scored CTF
// prose ~1.03-1.11 vs. NVD's ~0.63-0.68 on the *same* underlying topic).
// Z-score normalization within each pool ranks candidates by "how good is
// this relative to its own pool's distribution" rather than raw magnitude,
// so a genuinely strong NVD match isn't discounted just because NVD's
// overall score distribution runs lower than CTF's for that query.
function zScoreNormalize(
  chunks:RetrievedChunk[]
):RetrievedChunk[]{

  if(chunks.length===0){
    return chunks;
  }


  const scores =
    chunks.map(c=>c.score);


  const mean =
    scores.reduce(
      (a,b)=>a+b,
      0
    ) / scores.length;


  const variance =
    scores.reduce(
      (a,b)=>a+(b-mean)**2,
      0
    ) / scores.length;


  const stdDev =
    Math.sqrt(variance);


  // Guard against a degenerate pool (all identical scores, e.g. a single
  // result) where stdDev is 0 — normalizing would divide by zero.
  if(stdDev === 0){

    return chunks.map(
      c=>({
        ...c,
        score:0,
      })
    );

  }


  return chunks.map(
    c=>({
      ...c,
      score:
        (c.score - mean) / stdDev,
    })
  );

}





function lexicalBoost(
  chunks:RetrievedChunk[],
  query:string
):RetrievedChunk[]{


  const terms =
    query
      .toLowerCase()
      .split(/\s+/)
      .filter(
        x=>x.length>2
      );



  return chunks
    .map(
      chunk=>{


        const haystack =
          (
            chunk.text +
            JSON.stringify(
              chunk.metadata
            )
          )
          .toLowerCase();



        let boost = 0;



        for(const term of terms){

          if(
            haystack.includes(term)
          ){

            boost += 0.04;

          }

        }



        return {

          ...chunk,

          score:
            chunk.score +
            boost,

        };

      }
    )
    .sort(
      (a,b)=>
        b.score-a.score
    );

}





export async function retrieve(
  query:string,
  opts:{
    source?:"nvd"|"ctftime";
    category?:string;
    hybrid?:boolean;
    ctfFloor?:number;
  }={}
):Promise<RetrievedChunk[]>{


  const {

    source,

    category,

    hybrid=true,

    ctfFloor=2,

  } = opts;




  const client =
    new OpenAI({
      apiKey:
        process.env.OPENAI_API_KEY,
    });




  if(!process.env.OPENAI_API_KEY){

    throw new Error(
      "OPENAI_API_KEY missing"
    );

  }




  const embedding =
    await client.embeddings.create({

      model:EMBED_MODEL,

      input:query,

    });




  const vector =
    embedding.data[0].embedding;




  let candidates:RetrievedChunk[] = [];





  if(source){


    candidates =
      await rawQuery(
        vector,
        CANDIDATE_K,
        {
          source,
          ...(category
            ? {category}
            : {})
        }
      );



  } else if(!hybrid){


    candidates =
      await rawQuery(
        vector,
        CANDIDATE_K,
        category
          ? {category}
          : undefined
      );



  } else {



    const [

      nvd,

      ctf,

    ] =
      await Promise.all([

        rawQuery(
          vector,
          CANDIDATE_K,
          {
            source:"nvd",
            ...(category
              ? {category}
              : {})
          }
        ),



        rawQuery(
          vector,
          CANDIDATE_K,
          {
            source:"ctftime",
            ...(category
              ? {category}
              : {})
          }
        ),

      ]);




    // Normalize each pool's scores independently *before* merging, so the
    // floor/fill logic below operates on comparable relative-relevance
    // values instead of raw magnitudes that differ systematically by pool.
    const nvdNormalized =
      zScoreNormalize(nvd);


    const ctfNormalized =
      zScoreNormalize(ctf);




    candidates = [

      ...nvdNormalized.slice(
        0,
        ctfFloor
      ),

      ...ctfNormalized.slice(
        0,
        ctfFloor
      ),

      ...nvdNormalized,

      ...ctfNormalized,

    ];

  }





  candidates =
    dedupeChunks(
      candidates
    );



  candidates =
    lexicalBoost(
      candidates,
      query
    )
    .slice(
      0,
      CANDIDATE_K
    );




  console.log(
    `[retrieval] candidates ${candidates.length}`
  );


  console.log(
    "[retrieval] pool breakdown:",
    candidates.reduce(
      (acc,c)=>{
        acc[c.source] =
          (acc[c.source] ?? 0) + 1;
        return acc;
      },
      {} as Record<string,number>
    )
  );





  const results =
    await rerank(
      query,
      candidates,
      FINAL_K
    );



  console.log(
    `[rerank] returned ${results.length}`
  );



  return results;

}






async function main(){


  const args =
    process.argv.slice(2);



  const sourceArg =
    args.find(
      a=>a.startsWith(
        "--source="
      )
    );



  const source =
    sourceArg
      ? sourceArg.split("=")[1] as
        "nvd"|"ctftime"
      : undefined;



  const noHybrid =
    args.includes(
      "--no-hybrid"
    );



  const query =
    args
      .filter(
        a=>
          !a.startsWith(
            "--source="
          )
          &&
          a!=="--no-hybrid"
      )
      .join(" ");





  if(!query){

    console.error(
      'Usage: npx tsx scripts/query.ts "question"'
    );

    process.exit(1);

  }





  const results =
    await retrieve(
      query,
      {
        source,
        hybrid:!noHybrid,
      }
    );




  console.log(
    `\nQuery: "${query}"\n`
  );




  results.forEach(
    (r,i)=>{


      console.log(
        `${i+1}. [reranked from ${r.score.toFixed(3)}] [${r.source}] ${r.citation}`
      );


      console.log(
        `   ${r.text
          .slice(0,180)
          .replace(/\n/g," ")
        }...`
      );


      console.log(
        `   ${r.url}\n`
      );

    }
  );

}





const isMain =
  process.argv[1]
    ? import.meta.url ===
      pathToFileURL(
        process.argv[1]
      ).href
    : false;




if(isMain){

  main()
    .catch(err=>{

      console.error(
        "Fatal error:",
        err
      );

      process.exit(1);

    });

}