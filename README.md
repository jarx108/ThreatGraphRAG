# ThreatGraph GraphRAG — Milestone 2 Repository Checkpoint

Cyber Threat Intelligence GraphRAG project for CS 6338 Knowledge Engineering.

## Checkpoint contents

- `schema.cypher` — Neo4j constraints, indexes, vector index, and intended CTI relationship vocabulary.
- `prompts/extraction_prompt.txt` — strict JSON LLM extraction prompt.
- `scripts/parse_extraction.py` — extraction-output validation.
- `tests/test_parser.py` — parser tests for valid/malformed outputs.
- `scripts/build_benchmarks.py` — deterministic benchmark builder using official MITRE Enterprise ATT&CK v19.2 STIX.
- `data/gold_triples.json` — generated 60-triple benchmark after running the builder.
- `data/eval_queries.json` — generated 24 multi-hop QA benchmark after running the builder.

## Why benchmarks are generated

The benchmark script derives relationships from the official MITRE ATT&CK STIX bundle rather than manually inventing cybersecurity facts. This makes each benchmark record traceable to a STIX relationship ID and pins the checkpoint to Enterprise ATT&CK v19.2.

## Setup

Python 3.10+ is sufficient for the checkpoint scripts.

Generate the benchmark files:

```bash
python scripts/build_benchmarks.py
```

Run parser tests:

```bash
python -m unittest tests.test_parser -v
```

Validate a model extraction:

```bash
python scripts/parse_extraction.py path/to/extraction.json
```

Load `schema.cypher` in Neo4j Browser or with `cypher-shell`.

## Benchmark design

`gold_triples.json` contains 60 graph relationships for extraction evaluation using Precision, Recall, and F1.

`eval_queries.json` contains 24 two-hop questions following:

`ThreatGroup -USES-> Technique <-MITIGATES- Mitigation`

These records can later be expanded with other path shapes such as:

`ThreatGroup -USES-> Software -USES-> Technique`

The same QA set should be used for the text-only RAG baseline and GraphRAG system.

## Data source

MITRE ATT&CK STIX Data:
https://github.com/mitre-attack/attack-stix-data

Pinned benchmark release:
Enterprise ATT&CK v19.2 (released August 5, 2026).

This project makes use of MITRE ATT&CK®.
