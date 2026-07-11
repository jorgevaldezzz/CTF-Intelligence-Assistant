import fs from "fs/promises";
import path from "path";
import crypto from "crypto";
import type { CtfChunk, CtfCategory } from "../shared/schema.js";

const RAW_READMES_DIR = path.resolve("data/raw/ctftime/readmes");
const CHUNKS_DIR = path.resolve("data/chunks");

const MIN_CHUNK_CHARS = 200;
const MAX_CHUNK_CHARS = 4000;

const CTF_CATEGORY_PATTERNS: Record<CtfCategory, RegExp> = {
  web:       /\b(sql\s*i(njection)?|xss|csrf|ssrf|lfi|rfi|ssti|xxe|idor|path\s*trav|open\s*redir|web)\b/i,
  pwn:       /\b(buffer\s*overflow|heap|rop|ret2|shellcode|format\s*string|pwn|binary\s*exploit)\b/i,
  crypto:    /\b(crypto(graphy)?|aes|rsa|ecc|hash|padding\s*oracle|block\s*cipher|stream\s*cipher)\b/i,
  forensics: /\b(forensics?|steganograph|pcap|memory\s*dump|disk\s*image|carv)\b/i,
  rev:       /\b(reverse\s*eng|reversing|decompil|disassembl|anti[-\s]?debug|obfuscat|crackme)\b/i,
  misc:      /\b(misc|osint|jail|sandbox|blockchain|smart\s*contract)\b/i,
};

interface RawReadme {
  id: number;
  full_name: string;
  html_url: string;
  description: string | null;
  topics: string[];
  stargazers_count: number;
  pushed_at: string;
  readme: string;
  skip?: boolean;
}

// --- Helpers ---

function detectPrimaryCategory(text: string): CtfCategory | null {
  for (const [cat, re] of Object.entries(CTF_CATEGORY_PATTERNS) as [CtfCategory, RegExp][]) {
    if (re.test(text)) return cat;
  }
  return null;
}

function extractEventAndChallenge(
  heading: string,
  fullName: string
): { event: string; challenge: string } {
  const cleaned = heading.replace(/^#+\s*/, "").trim();
  const dashIdx = cleaned.indexOf(" - ");
  if (dashIdx !== -1) {
    return {
      event: cleaned.slice(0, dashIdx).trim() || fullName,
      challenge: cleaned.slice(dashIdx + 3).trim() || cleaned,
    };
  }
  return { event: fullName, challenge: cleaned || fullName };
}

function stableId(fullName: string, heading: string): string {
  return crypto
    .createHash("sha1")
    .update(`${fullName}::${heading}`)
    .digest("hex")
    .slice(0, 16);
}

// --- Semantic chunking ---

function semanticChunks(readme: string): Array<{ heading: string; body: string }> {
  const lines = readme.split("\n");
  const sections: Array<{ heading: string; lines: string[] }> = [];
  let current: { heading: string; lines: string[] } | null = null;

  for (const line of lines) {
    if (/^#{2,3}\s+\S/.test(line)) {
      if (current) sections.push(current);
      current = { heading: line.trim(), lines: [] };
    } else {
      (current ??= { heading: "", lines: [] }).lines.push(line);
    }
  }
  if (current) sections.push(current);

  // Merge undersized sections upward
  const merged: Array<{ heading: string; body: string }> = [];
  for (const sec of sections) {
    const body = sec.lines.join("\n").trim();
    const fullText = `${sec.heading}\n${body}`.trim();
    if (fullText.length < MIN_CHUNK_CHARS && merged.length > 0) {
      merged[merged.length - 1].body += "\n\n" + fullText;
    } else {
      merged.push({ heading: sec.heading, body });
    }
  }

  // Split oversized sections on paragraph breaks
  const result: Array<{ heading: string; body: string }> = [];
  for (const { heading, body } of merged) {
    if (body.length <= MAX_CHUNK_CHARS) {
      result.push({ heading, body });
      continue;
    }
    const paragraphs = body.split(/\n{2,}/);
    let accumulator = "";
    let partIndex = 0;
    for (const para of paragraphs) {
      if ((accumulator + para).length > MAX_CHUNK_CHARS && accumulator.length > 0) {
        result.push({ heading: `${heading} (part ${++partIndex})`, body: accumulator.trim() });
        accumulator = para;
      } else {
        accumulator += (accumulator ? "\n\n" : "") + para;
      }
    }
    if (accumulator.trim()) {
      result.push({ heading: `${heading} (part ${++partIndex})`, body: accumulator.trim() });
    }
  }

  return result;
}

// --- Validation (inline, no external dep) ---

function isValidCtfChunk(chunk: CtfChunk): boolean {
  return (
    chunk.id.length > 0 &&
    chunk.text.length >= MIN_CHUNK_CHARS &&
    chunk.url.startsWith("https://") &&
    chunk.event.length > 0 &&
    chunk.challenge.length > 0
  );
}

// --- Main export ---

export interface TransformResult {
  transformed: number;
  skipped: number;
  failed: number;
}

export async function transformWriteups(): Promise<TransformResult> {
  await fs.mkdir(CHUNKS_DIR, { recursive: true });

  const files = (await fs.readdir(RAW_READMES_DIR)).filter((f) => f.endsWith(".json"));

  let transformed = 0;
  let skipped = 0;
  let failed = 0;
  const allChunks: CtfChunk[] = [];

  for (const file of files) {
    const raw: RawReadme = JSON.parse(
      await fs.readFile(path.join(RAW_READMES_DIR, file), "utf-8")
    );

    if (raw.skip) {
      skipped++;
      continue;
    }

    try {
      const sections = semanticChunks(raw.readme);

      for (const { heading, body } of sections) {
        const text = heading ? `${heading}\n\n${body}` : body;
        const category = detectPrimaryCategory(text);

        // No recognizable CTF content — skip
        if (!category) {
          skipped++;
          continue;
        }

        const { event, challenge } = extractEventAndChallenge(heading, raw.full_name);

        const chunk: CtfChunk = {
          id: stableId(raw.full_name, heading),
          source: "ctftime",
          category,
          text: text.slice(0, MAX_CHUNK_CHARS),
          url: raw.html_url,
          ingested_at: new Date().toISOString(),
          event,
          challenge,
          ...(raw.stargazers_count > 0 && { stars: raw.stargazers_count }),
          ...(raw.pushed_at && { pushed_at: raw.pushed_at }),
        };

        if (isValidCtfChunk(chunk)) {
          allChunks.push(chunk);
          transformed++;
        } else {
          skipped++;
        }
      }
    } catch (err) {
      console.error(`[transform] Failed on ${file}:`, err);
      failed++;
    }
  }

  const outPath = path.join(CHUNKS_DIR, "ctftime.json");
  await fs.writeFile(outPath, JSON.stringify(allChunks, null, 2));
  console.log(
    `[transform] ${transformed} chunks → ${outPath} | skipped: ${skipped} | failed: ${failed}`
  );

  return { transformed, skipped, failed };
}