import "dotenv/config";
import OpenAI from "openai";
import type { RetrievedChunk } from "../query";

const CHAT_MODEL = "gpt-4o-mini"; // cheap, fast, fine for grounded Q&A — swap if you want a stronger judge/generator later

// Produces the "answer" RAGAS scores. Deliberately instructed to only use
// the provided context — this is the actual system under test end-to-end
// (retrieval + generation), not just retrieval in isolation.
export async function generateAnswer(question: string, contexts: RetrievedChunk[]): Promise<string> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) throw new Error("OPENAI_API_KEY not set");
  const client = new OpenAI({ apiKey });

  const contextBlock = contexts
    .map((c, i) => `[${i + 1}] (${c.citation})\n${c.text}`)
    .join("\n\n");

  const res = await client.chat.completions.create({
    model: CHAT_MODEL,
    messages: [
      {
        role: "system",
        content:
          "You are a CTF/vulnerability research assistant. Answer the question using ONLY the numbered context provided. " +
          "If the context does not contain material directly relevant to the SPECIFIC vulnerability or technique asked about, " +
          "respond with exactly: \"The retrieved context doesn't contain relevant information for this question.\" " +
          "Do not answer from general knowledge, even if you are confident in the answer — an answer not grounded in the " +
          "provided context is a failure, regardless of whether it happens to be correct. " +
          "Reference sources by their citation when relevant. Keep your answer focused and under 200 words.",
      },
      {
        role: "user",
        content: `Context:\n${contextBlock}\n\nQuestion: ${question}`,
      },
    ],
    temperature: 0,
    // RAGAS's faithfulness metric breaks the full answer into atomic
    // statements via structured output — an unbounded answer risks that
    // step hitting its own max_tokens ceiling and failing with
    // IncompleteOutputException. Capping here keeps answers focused AND
    // keeps eval scoring reliable.
    max_tokens: 500,
  });

  return res.choices[0]?.message?.content ?? "";
}