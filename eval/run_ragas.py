"""
RAGAS evaluation harness.

Evaluates RAG output quality using RAGAS 0.4.3.

Current metrics:
- faithfulness (all rows, no reference required)
- context_recall (rows with ground_truth only)
- context_precision (rows with ground_truth only)

answer_relevancy is permanently disabled because RAGAS 0.4.3 has
a broken embeddings wrapper internally (AttributeError:
'OpenAIEmbeddings' object has no attribute 'embed_query') — this is
a bug inside ragas's own dependency chain, not something fixable
from our side.
"""

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from datasets import Dataset
from openai import OpenAI

from ragas import evaluate
from ragas.llms import llm_factory
from ragas.metrics import Faithfulness, ContextRecall, ContextPrecision


INPUT_PATH = Path("data/eval/ragas_input.jsonl")
RESULTS_PATH = Path("eval/results.json")
SUMMARY_MD_PATH = Path("eval/RESULTS.md")


def load_rows(path: Path) -> list[dict]:
    if not path.exists():
        print(
            f"No input found at {path}. "
            "Run: npx tsx scripts/eval/export-for-ragas.ts first."
        )
        sys.exit(1)

    rows = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    return rows


def main():

    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY missing.")
        sys.exit(1)

    client = OpenAI()

    judge_llm = llm_factory(
        "gpt-4.1-mini",
        client=client,
    )

    faithfulness = Faithfulness(llm=judge_llm)
    context_recall = ContextRecall(llm=judge_llm)
    context_precision = ContextPrecision(llm=judge_llm)


    rows = load_rows(INPUT_PATH)

    print(f"Loaded {len(rows)} rows from {INPUT_PATH}")

    has_ground_truth = [
        r for r in rows
        if r.get("ground_truth")
    ]

    print(f"  {len(has_ground_truth)} rows have ground_truth")
    print(
        f"  {len(rows) - len(has_ground_truth)} rows "
        "have no ground_truth"
    )


    results_summary = {}


    #
    # Tier 1: Faithfulness
    #
    base_dataset = Dataset.from_list(
        [
            {
                "user_input": r["question"],
                "response": r["answer"],
                "retrieved_contexts": r["contexts"],
            }
            for r in rows
        ]
    )


    print("\nRunning faithfulness on all rows...")

    base_result = evaluate(
        base_dataset,
        metrics=[
            faithfulness
        ],
        raise_exceptions=True,
        batch_size=1,
    )


    base_df = base_result.to_pandas()

    results_summary["all_rows"] = {
        "count": len(rows),
        "scores": (
            base_df
            .mean(numeric_only=True)
            .to_dict()
        ),
    }


    #
    # Breakdown by source
    #
    # NOTE: export-for-ragas.ts writes this field as `_expected_source`
    # (with the leading underscore) — looking it up as `expected_source`
    # (no underscore) silently returns None for every row and makes this
    # whole breakdown quietly empty with no error. Keep the underscore.
    base_df["_expected_source"] = [
        r.get("_expected_source")
        for r in rows
    ]

    by_source = {}

    for source in base_df["_expected_source"].dropna().unique():

        subset = base_df[
            base_df["_expected_source"] == source
        ]

        by_source[source] = {
            "count": len(subset),
            "scores": (
                subset
                .drop(columns=["_expected_source", "_id"], errors="ignore")
                .mean(numeric_only=True)
                .to_dict()
            ),
        }


    results_summary["by_expected_source"] = by_source



    #
    # Tier 2: Context recall + Context precision
    #
    if has_ground_truth:

        gt_dataset = Dataset.from_list(
            [
                {
                    "user_input": r["question"],
                    "response": r["answer"],
                    "retrieved_contexts": r["contexts"],
                    "reference": r["ground_truth"],
                }
                for r in has_ground_truth
            ]
        )


        print(
            "\nRunning context_recall + context_precision on "
            f"{len(has_ground_truth)} rows..."
        )


        gt_result = evaluate(
            gt_dataset,
            metrics=[
                context_recall,
                context_precision,
            ],
            raise_exceptions=True,
            batch_size=1,
        )


        gt_df = gt_result.to_pandas()


        results_summary["ground_truth_rows"] = {
            "count": len(has_ground_truth),
            "scores": (
                gt_df
                .mean(numeric_only=True)
                .to_dict()
            ),
        }

    else:

        gt_df = None
        results_summary["ground_truth_rows"] = None


    #
    # Per-question breakdown
    #
    # Tag both dataframes with the question id so we can join them
    # reliably, rather than assuming row order lines up across two
    # separate evaluate() calls.
    base_df["_id"] = [r["_id"] for r in rows]
    if has_ground_truth:
        gt_df["_id"] = [r["_id"] for r in has_ground_truth]

    gt_lookup = (
        gt_df.set_index("_id").to_dict(orient="index")
        if has_ground_truth
        else {}
    )

    per_question = []

    for r in rows:
        qid = r["_id"]
        base_row = base_df[base_df["_id"] == qid].iloc[0]
        entry = {
            "id": qid,
            "question": r["question"],
            "expected_source": r.get("_expected_source"),
            "faithfulness": float(base_row["faithfulness"]),
        }
        if qid in gt_lookup:
            if "context_recall" in gt_lookup[qid]:
                entry["context_recall"] = float(gt_lookup[qid]["context_recall"])
            if "context_precision" in gt_lookup[qid]:
                entry["context_precision"] = float(gt_lookup[qid]["context_precision"])
        per_question.append(entry)

    results_summary["per_question"] = per_question


    #
    # Write JSON
    #
    RESULTS_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        RESULTS_PATH,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            results_summary,
            f,
            indent=2
        )


    #
    # Write Markdown
    #
    lines = [
        "# RAGAS Evaluation Results\n",
        f"Evaluated {len(rows)} questions.\n",
    ]


    lines.append(
        "## Faithfulness\n"
    )

    for metric, score in results_summary["all_rows"]["scores"].items():
        lines.append(
            f"- **{metric}**: {score:.3f}"
        )


    if results_summary["by_expected_source"]:

        lines.append(
            "\n## Breakdown by expected_source\n"
        )

        for source, data in results_summary["by_expected_source"].items():

            lines.append(
                f"\n**{source}** ({data['count']} questions)"
            )

            for metric, score in data["scores"].items():
                lines.append(
                    f"- {metric}: {score:.3f}"
                )


    if results_summary["ground_truth_rows"]:

        lines.append(
            "\n## Context Recall / Context Precision\n"
        )

        for metric, score in results_summary["ground_truth_rows"]["scores"].items():

            lines.append(
                f"- **{metric}**: {score:.3f}"
            )


    lines.append("\n## Per-Question Results\n")
    lines.append("| ID | Question | Source | Faithfulness | Context Recall | Context Precision |")
    lines.append("|---|---|---|---|---|---|")
    for pq in per_question:
        q_short = pq["question"][:60].replace("|", "\\|")
        if len(pq["question"]) > 60:
            q_short += "..."
        cr = f"{pq['context_recall']:.3f}" if "context_recall" in pq else "—"
        cp = f"{pq['context_precision']:.3f}" if "context_precision" in pq else "—"
        lines.append(
            f"| {pq['id']} | {q_short} | {pq.get('expected_source') or '—'} | "
            f"{pq['faithfulness']:.3f} | {cr} | {cp} |"
        )


    with open(
        SUMMARY_MD_PATH,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(lines) + "\n"
        )


    print(
        f"\nWrote {RESULTS_PATH}"
    )

    print(
        f"Wrote {SUMMARY_MD_PATH}"
    )


if __name__ == "__main__":
    main()