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

async function main() {
  const raw = await fs.readFile(QUESTIONS_PATH, "utf-8");
  const questions: EvalQuestion[] = JSON.parse(raw).filter(
    (q: EvalQuestion) => !q._comment // drop the placeholder example row
  );

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
      contexts: contexts.map((c) => c.text),
      ...(q.ground_truth ? { ground_truth: q.ground_truth } : {}),
      _id: q.id,
      _expected_source: q.expected_source,
      _retrieved_sources: contexts.map((c) => c.source),
    });
  }

  await fs.mkdir(path.dirname(OUTPUT_PATH), { recursive: true });
  const lines = rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
  await fs.writeFile(OUTPUT_PATH, lines);

  console.log(`\nWrote ${rows.length} rows to ${OUTPUT_PATH}`);
  console.log(`Next: python eval/run_ragas.py`);
}

main().catch((err) => {
  console.error("Fatal error in export-for-ragas.ts:", err);
  process.exit(1);
});