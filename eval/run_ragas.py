"""
RAGAS evaluation harness.

Evaluates RAG output quality using RAGAS 0.4.3.

Current metrics:
- faithfulness (all rows, no reference required)
- context_recall (rows with ground_truth only)

answer_relevancy is temporarily disabled because RAGAS 0.4.3 has
an embeddings compatibility issue with OpenAIEmbeddings.embed_query().
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
from ragas.metrics import Faithfulness, ContextRecall


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
    base_df["_expected_source"] = [
        r.get("expected_source")
        for r in rows
    ]

    by_source = {}

    for source in base_df["_expected_source"].dropna().unique():

        subset = base_df[
            base_df["_expected_source"] == source
        ]

        by_source[source] = {
            "count": len(subset),
            "scores": {
                col: float(subset[col].mean())
                for col in subset.columns
                if col != "_expected_source"
                and subset[col].dtype != object
            },
        }


    results_summary["by_expected_source"] = by_source



    #
    # Tier 2: Context recall
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
            "\nRunning context_recall on "
            f"{len(has_ground_truth)} rows..."
        )


        gt_result = evaluate(
            gt_dataset,
            metrics=[
                context_recall
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

        results_summary["ground_truth_rows"] = None



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
            "\n## Context Recall\n"
        )

        for metric, score in results_summary["ground_truth_rows"]["scores"].items():

            lines.append(
                f"- **{metric}**: {score:.3f}"
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