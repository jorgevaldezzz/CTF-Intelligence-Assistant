# RAGAS Evaluation Results

Evaluated 10 questions.

## Faithfulness

- **faithfulness**: 0.808

## Breakdown by expected_source


**nvd** (4 questions)
- faithfulness: 0.659

**ctftime** (6 questions)
- faithfulness: 0.907

## Context Recall / Context Precision

- **context_recall**: 0.917
- **context_precision**: 0.831

## Per-Question Results

| ID | Question | Source | Faithfulness | Context Recall | Context Precision |
|---|---|---|---|---|---|
| q001 | CTF web challenge: the login page's source code shows the qu... | nvd | 1.000 | 1.000 | 0.938 |
| q002 | CTF pwn challenge: checksec shows no stack canary, NX enable... | ctftime | 1.000 | 1.000 | 0.958 |
| q003 | CTF crypto challenge: I'm given an RSA public key with a ver... | ctftime | 0.667 | 1.000 | 1.000 |
| q004 | CTF forensics challenge: I've been given a raw memory dump (... | ctftime | 0.778 | — | — |
| q005 | During a CTF, I found that a web app's 'export report' featu... | nvd | 1.000 | 1.000 | 0.483 |
| q006 | CTF rev challenge: I've got a stripped 64-bit ELF binary wit... | ctftime | 1.000 | — | — |
| q007 | CTF web challenge: a file upload feature accepts images, but... | nvd | 0.000 | 1.000 | 1.000 |
| q008 | CTF misc challenge: I'm given a .pcap file and told the flag... | ctftime | 1.000 | — | — |
| q009 | CTF web challenge: I noticed the app lets me request `/downl... | nvd | 0.636 | 0.500 | 0.607 |
| q010 | CTF pwn challenge: the binary uses malloc/free and I suspect... | ctftime | 1.000 | — | — |
