import "dotenv/config";
import fs from "node:fs/promises";
import path from "node:path";
import { retrieve } from "../query";
import { generateAnswer } from "./generate-answer";

// This is the bridge between the TS retrieval pipeline and RAGAS (Python).
// RAGAS's evaluate() expects a row per question with: question, answer,
// contexts (list of strings), and optionally ground_truth. We produce that
// here by actually running each question through the real system —
// retrieve() then generateAnswer() — so the eval measures what a user would
// really get, not a synthetic approximation of it.

const QUESTIONS_PATH = path.resolve("data/eval/questions.json");
const OUTPUT_PATH = path.resolve("data/eval/ragas_input.jsonl");

interface EvalQuestion {
  id: string;
  question: string;
  ground_truth?: string | null;
  expected_source?: "nvd" | "ctftime";
  _comment?: string; // placeholder marker, filtered out below
}

interface RagasRow {
  question: string;
  answer: string;
  contexts: string[];
  ground_truth?: string;
  // Extra fields beyond what RAGAS reads, kept for your own debugging/analysis
  _id: string;
  _expected_source?: string;
  _retrieved_sources: string[];
}

// RAGAS's faithfulness metric has to fit the full answer PLUS all contexts
// into a structured-output call that breaks the answer into atomic
// statements and verdicts each one — an unbounded context (some CTF README
// chunks are long) risks hitting the LLM's max_tokens limit on that step
// and failing with IncompleteOutputException. Cap each context chunk's
// length here, specifically for the eval export — this doesn't touch the
// production retrieve() path or what a real user actually sees, and
// generateAnswer() above still gets the FULL untruncated context (it needs
// the complete text to answer well) — only the copy written out for RAGAS
// to score is shortened.
const MAX_CONTEXT_CHARS = 1500;

function truncateContext(text: string): string {
  return text.length > MAX_CONTEXT_CHARS ? text.slice(0, MAX_CONTEXT_CHARS) + "..." : text;
}

async function main() {
  const idFilter = process.argv.find((a) => a.startsWith("--id="))?.split("=")[1];

  const raw = await fs.readFile(QUESTIONS_PATH, "utf-8");
  let questions: EvalQuestion[] = JSON.parse(raw).filter(
    (q: EvalQuestion) => !q._comment // drop the placeholder example row
  );

  if (idFilter) {
    questions = questions.filter((q) => q.id === idFilter);
    if (!questions.length) {
      console.error(`No question with id "${idFilter}" found in ${QUESTIONS_PATH}`);
      process.exit(1);
    }
  }

  if (!questions.length) {
    console.error(
      `No real questions found in ${QUESTIONS_PATH} — it's still just the placeholder. Add real questions first.`
    );
    process.exit(1);
  }

  console.log(`Running ${questions.length} questions through retrieve() + generateAnswer()...`);

  const rows: RagasRow[] = [];

  for (const q of questions) {
    console.log(`  [${q.id}] ${q.question.slice(0, 60)}...`);
    const contexts = await retrieve(q.question, { topK: 8 });
    const answer = await generateAnswer(q.question, contexts);

    rows.push({
      question: q.question,
      answer,
      contexts: contexts.map((c) => truncateContext(c.text)),
      ...(q.ground_truth ? { ground_truth: q.ground_truth } : {}),
      _id: q.id,
      _expected_source: q.expected_source,
      _retrieved_sources: contexts.map((c) => c.source),
    });
  }

  await fs.mkdir(path.dirname(OUTPUT_PATH), { recursive: true });
  const outputPath = idFilter
    ? path.resolve(`data/eval/ragas_input.${idFilter}.jsonl`)
    : OUTPUT_PATH;
  const lines = rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
  await fs.writeFile(outputPath, lines);

  console.log(`\nWrote ${rows.length} rows to ${outputPath}`);
  if (!idFilter) console.log(`Next: python eval/run_ragas.py`);
}

main().catch((err) => {
  console.error("Fatal error in export-for-ragas.ts:", err);
  process.exit(1);
});