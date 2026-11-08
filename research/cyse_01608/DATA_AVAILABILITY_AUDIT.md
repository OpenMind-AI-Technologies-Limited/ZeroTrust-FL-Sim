# Data Availability and Original Artifact Provenance Audit

**Audited on:** 2026-11-08
**Manuscript:** CYSE-D-26-01608, *Privacy–Robustness Trade-offs in Federated Learning: Local Differential Privacy, Byzantine Aggregation, and CKKS Secure Aggregation*.

## What the manuscript actually states

The submitted manuscript's Data and Materials Availability statement cites:

- DOI: https://doi.org/10.5281/zenodo.22711022
- Claimed supporting materials, including per-run results, aggregated privacy–robustness summaries, and paired statistical comparison outputs as **Additional files 1–3**.

The PDF statement must **not** be treated as proof that all files are publicly available at that DOI.

## Verified external metadata

We fetched and inspected both the public Zenodo record and its REST record description at https://zenodo.org/api/records/22711022.

- Record ID: 22711022; DOI: 10.5281/zenodo.22711022.
- Resource type: **Software**, title: **ZeroTrust-FL-Sim**, version **v1.0.0**, publication date **2026-09-11**.
- The Zenodo record lists exactly **one uploaded item**:
  - `smshagor-dev/ZeroTrust-FL-Sim-v1.0.0.zip`
  - Size 507,376 bytes, MD5 3d42fe791e9e79accc0e557a9c3f3a92.
- Related source: https://github.com/smshagor-dev/ZeroTrust-FL-Sim/tree/v1.0.0.

We independently inspected the GitHub `v1.0.0` source tree: **293 tracked blobs**, with no directly tracked original per-run experiment CSV, aggregate trade-off CSV or paired statistical comparison CSV. The record's software ZIP binary itself was not inspected byte-by-byte. Therefore, do not assert that it *cannot* contain unlisted evidence; rather, public provenance of the submitted numerical claims is **not independently established**.

## Impact on journal readiness

The current data-availability statement is too broad if readers are expected to retrieve the 720 experiment runs from the Zenodo DOI. A software source archive is not a substitute for traceable research outcomes. Additional files 1–3 may exist as journal submission attachments and should be recovered from the author portal or original experimental workspace.

**Never fabricate/reconstruct the original 720 CSVs** by copying this branch's independent rerun; their numerical results differ and must be kept separate.

## Required evidence package

1. Retrieve *original* source execution scripts and dataset snapshot/version hashes.
2. Retrieve the exact original 720-run CSV (dataset, seed, method, privacy mode, attack, final metrics), aggregated summaries and paired comparisons, along with the original creation timestamps where available.
3. Recompute every paper table and figure directly from these files. Record and explain any discrepancies.
4. Produce a **new immutable Zenodo dataset record/version** containing source commit, raw data, scripts, manifest, dependencies, benchmark identifiers, security assumptions and research reproducibility license.
5. Update the manuscript's Data Availability section to cite **both** the software DOI (as software) and the validated **dataset DOI** (as source evidence), if separate. Confirm that journal Additional Files 1–3 correspond to those exact files.
6. Add dataset checksum verification to the repository's CI so it fails on missing, mismatched or silently modified manuscript results.

## Current status

The research branch has independent, reproducible design **reimplementations**, plus additional protocol-bypass, non-IID, malicious-admission and oracle attack tests. These are new research artifacts but **do not retroactively validate the original submitted numbers**.

**Evidence classification: original 720-result provenance — unresolved.**
