# RAGAS Evaluation Results

Evaluated 10 questions.

## Faithfulness

- **faithfulness**: 0.876

## Breakdown by expected_source


**nvd** (4 questions)
- faithfulness: 0.750

**ctftime** (6 questions)
- faithfulness: 0.961

## Context Recall / Context Precision

- **context_recall**: 0.944
- **context_precision**: 0.803

## Per-Question Results

| ID | Question | Source | Faithfulness | Context Recall | Context Precision |
|---|---|---|---|---|---|
| q001 | CTF web challenge: the login page's source code shows the qu... | nvd | 1.000 | 1.000 | 0.938 |
| q002 | CTF pwn challenge: checksec shows no stack canary, NX enable... | ctftime | 1.000 | 0.667 | 0.958 |
| q003 | CTF crypto challenge: I'm given an RSA public key with a ver... | ctftime | 0.889 | 1.000 | 0.833 |
| q004 | CTF forensics challenge: I've been given a raw memory dump (... | ctftime | 0.875 | — | — |
| q005 | During a CTF, I found that a web app's 'export report' featu... | nvd | 1.000 | 1.000 | 0.483 |
| q006 | CTF rev challenge: I've got a stripped 64-bit ELF binary wit... | ctftime | 1.000 | — | — |
| q007 | CTF web challenge: a file upload feature accepts images, but... | nvd | 0.000 | 1.000 | 1.000 |
| q008 | CTF misc challenge: I'm given a .pcap file and told the flag... | ctftime | 1.000 | — | — |
| q009 | CTF web challenge: I noticed the app lets me request `/downl... | nvd | 1.000 | 1.000 | 0.607 |
| q010 | CTF pwn challenge: the binary uses malloc/free and I suspect... | ctftime | 1.000 | — | — |
