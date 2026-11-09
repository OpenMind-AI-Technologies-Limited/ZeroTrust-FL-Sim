# Original submitted-run audit: explicit fail-closed requirements

CYSE-D-26-01608 originally reported a 720-condition local-DP × Byzantine FL design. The original Additional files 1–3 have not been independently located. Existing independent reconstruction data, the supplemental RFA runs and the UNSW/NSL experiments **must not be relabeled as those original 720 raw results**.

## Executable structural gate

The gate `original_evidence_gate.py` accepts a genuine author-held original raw CSV and an accompanying historical provenance JSON manifest:

```bash
python research/cyse_01608/original_evidence_gate.py \
  --original-runs /secure/original/runs.csv \
  --original-provenance /secure/original/origin.json \
  --compare-independent artifacts/cyse_01608/runs.csv \
  --output artifacts/cyse_01608_original_audit/report.json
```

Inputs are **not created by the audit**. If missing, it raises an error. The manifest must declare `manuscript_id`, `declared_original_author_run: true`, the historical 40-character source commit SHA, UTC execution timestamp, source script SHA-256, original file SHA-256 and version identifiers for the two study datasets.

It checks all 720 distinct combinations (two datasets × five seeds × four methods × six privacy modes × three threats), prevents duplicate/missing rows, validates finite accuracy/loss, requires 15 clients, three Byzantine clients and 20 rounds, and checks that the original design's attacker-compliance status matches. It also compares condition-by-condition accuracy with the separately independently reconstructed study **if** that reference file is provided; disagreement is reported, not silently overwritten.

**Authenticity limit:** a self-declared JSON manifest or matching SHA-256 checks internal *consistency*, not that the original historical run truly happened. The original journal Additional Files, immutable snapshots, signed provenance or independent timestamped backups and the original code/data environment must be reconciled by the author. The gate intentionally never says 'historically verified'.

## Current project state

- The code-level audit mechanism and synthetic-fixture negative tests are implemented.
- No genuine original-author 720-run CSV or independently authenticated original provenance bundle was supplied to this branch.
- Consequently, the scientific provenance blocker is **NOT resolved**; no original-data success claim is authorized.
- RFA and server-clipped baselines are additional experiments and cannot substitute for the manuscript's original numerical evidence.

Related audit: [DATA_AVAILABILITY_AUDIT.md](DATA_AVAILABILITY_AUDIT.md). Other external historical datasets: [UNSW_NB15_EVIDENCE.md](UNSW_NB15_EVIDENCE.md), [NSL_KDD_EVIDENCE.md](NSL_KDD_EVIDENCE.md).
