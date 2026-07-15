import type { NvdChunk, NvdCategory, TransformResult } from "../shared/schema.js";
import type { NvdCveRecord } from "./fetch.js";
import { readFile, readdir, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/";


// Transform one NVD CVE record into an enriched searchable chunk.
export function transformNvdRecord(
  record: NvdCveRecord,
  ingestedAt: string
): NvdChunk | null {

  const cveId =
    record.cve?.id?.trim();

  if (!cveId) {
    return null;
  }


  const description =
    extractEnglishDescription(
      record.cve.descriptions
    );


  if (!description) {
    return null;
  }


  const severity =
    extractSeverity(
      record.cve.metrics
    );


  const cwe =
    extractCwe(
      record.cve.weaknesses
    );

const tags =
  inferAttackTags(
    description,
    cwe
  );


const category =
  inferCategory(
    description,
    cwe,
    tags
  );


const enrichedText = `
CVE ID:
${cveId}

Category:
${category}

CWE:
${cwe ?? "Unknown"}

Severity:
${severity ?? "Unknown"}

Attack Tags:
${tags.join(", ")}

Security Concepts:
${inferSecurityConcepts(
  description,
  cwe,
  tags
)}

Description:
${description}
`.trim();


  return {
    id: cveId,
    source: "nvd",
    category,
    severity,
    cwe,
    text: enrichedText,
    url: `${NVD_DETAIL_URL}${cveId}`,
    ingested_at: ingestedAt,
  };
}



// Mirrors the shape expected by the ingestion pipeline.
export async function transformNvdRaw(opts: {
  rawDir: string;
  chunksDir: string;
}): Promise<TransformResult> {

  await mkdir(
    opts.chunksDir,
    {
      recursive:true,
    }
  );


  const files =
    (
      await readdir(
        opts.rawDir
      )
    )
    .filter(
      f=>f.endsWith(".json")
    );


  const ingestedAt =
    new Date().toISOString();


  let transformed = 0;
  let skipped = 0;
  let failed = 0;


  const seen =
    new Set<string>();

  const seenLower =
    new Set<string>();


  const allChunks:NvdChunk[] = [];


  for(const file of files){

    try{

      const raw =
        JSON.parse(
          await readFile(
            path.join(
              opts.rawDir,
              file
            ),
            "utf-8"
          )
        );


      const vulnerabilities:NvdCveRecord[] =
        raw?.response?.vulnerabilities ?? [];


      for(const record of vulnerabilities){

        const chunk =
          transformNvdRecord(
            record,
            ingestedAt
          );


        if(!chunk){

          skipped++;
          continue;

        }


        if(
          seen.has(chunk.id) ||
          seenLower.has(chunk.id.toLowerCase())
        ){

          skipped++;
          continue;

        }


        seen.add(chunk.id);

        seenLower.add(
          chunk.id.toLowerCase()
        );

        allChunks.push(chunk);

        transformed++;

      }


    }catch(err){

      console.error(
        `[nvd/transform] Failed on ${file}:`,
        err
      );

      failed++;

    }

  }



  const outPath =
    path.join(
      opts.chunksDir,
      "nvd.json"
    );


  await writeFile(
    outPath,
    JSON.stringify(
      allChunks,
      null,
      2
    ),
    "utf-8"
  );


  console.log(
    `[nvd/transform] ${transformed} chunks → ${outPath} | skipped: ${skipped} | failed: ${failed}`
  );


  return {
    transformed,
    skipped,
    failed,
  };
}



// Extract English CVE description.
function extractEnglishDescription(
  descriptions?: Array<{
    lang?: string;
    value?: string;
  }>
):string {

  if(!descriptions?.length){
    return "";
  }


  const english =
    descriptions.find(
      d =>
        d.lang?.toLowerCase()==="en"
    )
    ?.value
    ?.trim();


  return (
    english ??
    descriptions[0]?.value?.trim() ??
    ""
  );
}


// Extract CVSS score.
function extractSeverity(
  metrics?:Record<string,unknown>
):number|null {

  if(!metrics){
    return null;
  }


  for(
    const key of [
      "cvssMetricV31",
      "cvssMetricV30",
      "cvssMetricV2",
    ]
  ){

    const entries =
      metrics[key];


    if(!Array.isArray(entries)){
      continue;
    }


    for(const entry of entries){

      const score =
        (
          entry as {
            cvssData?:{
              baseScore?:unknown;
            }
          }
        )
        ?.cvssData
        ?.baseScore;


      if(typeof score==="number"){
        return score;
      }

    }

  }


  return null;
}



// Extract CWE.
function extractCwe(
  weaknesses?:unknown
):string|null {

  if(!Array.isArray(weaknesses)){
    return null;
  }


  for(const weakness of weaknesses){

    const descriptions =
      (
        weakness as {
          description?:
          Array<{
            value?:string;
          }>
        }
      )
      .description;


    if(!Array.isArray(descriptions)){
      continue;
    }


    for(const item of descriptions){

      const value =
        item?.value?.trim();


      if(
        value &&
        value
        .toUpperCase()
        .startsWith("CWE-")
      ){

        return value;

      }

    }

  }


  return null;
}



// Add semantic concepts that embeddings understand better.
function inferSecurityConcepts(
  text:string,
  cwe:string|null,
  tags:string[]
):string {

  const lower =
    text.toLowerCase();

  const concepts:string[] = [
    ...tags.map(
      t => t.replace("-", " ")
    )
  ];



  if(
    cwe==="CWE-918" ||
    lower.includes("ssrf") ||
    lower.includes(
      "server-side request forgery"
    )
  ){

    concepts.push(
      "Server Side Request Forgery SSRF"
    );

  }

  if(
  lower.includes("ssrf") ||
  lower.includes("server-side request forgery") ||
  cwe === "CWE-918"
){
  concepts.push(
    "SSRF arbitrary URL fetch internal service access localhost cloud metadata 169.254.169.254"
  );
}


  if(
    lower.includes("metadata") ||
    lower.includes("169.254.169.254") ||
    lower.includes("instance metadata") ||
    lower.includes("cloud")
  ){

    concepts.push(
  "Cloud metadata service AWS EC2 metadata endpoint 169.254.169.254 IMDS instance credentials IAM tokens"
);

  }


  if(
    lower.includes("internal") ||
    lower.includes("localhost") ||
    lower.includes(
      "private network"
    )
  ){

    concepts.push(
      "Internal network access localhost private services"
    );

  }


  if(
    lower.includes("unauthenticated")
  ){

    concepts.push(
      "Unauthenticated remote access"
    );

  }


  if(
    lower.includes("url") ||
    lower.includes("request")
  ){

    concepts.push(
      "Remote URL fetching outbound requests"
    );

  }


  return concepts.join(", ");
}



// Extract attack vocabulary useful for retrieval.
function inferAttackTags(
  text:string,
  cwe:string|null
):string[] {

  const lower =
    text.toLowerCase();

  const tags = new Set<string>();


  if(
    cwe === "CWE-918" ||
    lower.includes("ssrf") ||
    lower.includes("server-side request forgery")
  ){
    tags.add("ssrf");
  }


  if(
    lower.includes("169.254.169.254") ||
    lower.includes("metadata service") ||
    lower.includes("instance metadata")
  ){
    tags.add("cloud-metadata");
  }


  if(
    lower.includes("sql injection") ||
    lower.includes("sqli")
  ){
    tags.add("sql-injection");
  }


  if(
    lower.includes("command injection") ||
    lower.includes("shell injection")
  ){
    tags.add("command-injection");
  }


  if(
    lower.includes("deserialization")
  ){
    tags.add("deserialization");
  }


  if(
    lower.includes("prototype pollution")
  ){
    tags.add("prototype-pollution");
  }


  if(
    lower.includes("xxe") ||
    lower.includes("xml external entity")
  ){
    tags.add("xxe");
  }


  if(
    lower.includes("path traversal") ||
    lower.includes("directory traversal")
  ){
    tags.add("path-traversal");
  }


  if(
    lower.includes("file upload")
  ){
    tags.add("file-upload");
  }


  if(
    lower.includes("buffer overflow") ||
    lower.includes("use after free")
  ){
    tags.add("memory-corruption");
  }


  return [...tags];
}


// Infer SSRF and cloud attack vectors.
function inferSsrfAndCloud(
  text:string
):string {

  const lower =
    text.toLowerCase();


  const terms:string[] = [];


  const mappings:Array<[string,string]> = [

    [
      "metadata",
      "cloud metadata endpoint"
    ],

    [
      "169.254.169.254",
      "AWS EC2 metadata IP"
    ],

    [
      "credential",
      "cloud credential theft"
    ],

    [
      "token",
      "access token exposure"
    ],

    [
      "request",
      "server initiated request"
    ],

    [
      "fetch",
      "URL fetch primitive"
    ],

    [
      "proxy",
      "open proxy behavior"
    ],

  ];



  for(const [
    keyword,
    meaning
  ] of mappings){

    if(lower.includes(keyword)){
      terms.push(meaning);
    }

  }


  return terms.join(", ");
}



// Infer broad vulnerability category.
function inferCategory(
  text:string,
  cwe:string|null,
  tags:string[]
):NvdCategory {


  const lower =
    text.toLowerCase();


  if(tags.some(
    t =>
      [
        "ssrf",
        "sql-injection",
        "command-injection",
        "xxe",
        "prototype-pollution",
        "path-traversal"
      ].includes(t)
  )){
    return "web";
  }


  if(
    cwe?.startsWith("CWE-787") ||
    cwe === "CWE-125" ||
    cwe === "CWE-416"
  ){
    return "memory";
  }


  if(
    lower.includes("sql injection") ||
    lower.includes("xss") ||
    lower.includes(
      "cross-site scripting"
    ) ||
    lower.includes(
      "path traversal"
    ) ||
    lower.includes(
      "directory traversal"
    ) ||
    lower.includes(
      "command injection"
    ) ||
    lower.includes(
      "deserialization"
    ) ||
    lower.includes(
      "ssrf"
    ) ||
    lower.includes(
      "xxe"
    ) ||
    lower.includes(
      "local file inclusion"
    ) ||
    lower.includes(
      "remote file inclusion"
    )
  ){

    return "web";

  }



  if(
    lower.includes(
      "buffer overflow"
    ) ||
    lower.includes(
      "heap overflow"
    ) ||
    lower.includes(
      "format string"
    )
  ){

    return "memory";

  }


  if(
    lower.includes(
      "race condition"
    )
  ){

    return "concurrency";

  }


  if(
    lower.includes(
      "type confusion"
    )
  ){

    return "type-safety";

  }


  return "other";
}