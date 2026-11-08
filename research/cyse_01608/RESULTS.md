# CYSE-D-26-01608 — Execution evidence and remaining paper blockers

**Scope:** This is an independently executed study-design reimplementation. It is **not original submitted manuscript data**, a new algorithm, a privacy guarantee, or a validated Cybersecurity-journal contribution. See README.md for run instructions and experimental assumptions.

## Independent experimental execution (8 November 2026)

Local environment: Python 3.13, NumPy 2.3.5, SciPy 1.17.0, scikit-learn 1.8.0.

| Dataset grid | Runs | FL rounds | CSV SHA-256 |
| --- | ---: | ---: | --- |
| Original manuscript-design reference (IID-style, compliant) | 720 | 14,400 | 8267b5342d4e19908966d3c2f2926f0d95e36e8c09e74010307974e366557681 |
| Malicious clipping/DP bypass extension | 180 | 3,600 | d87275205b8a54dcd403bd3ed55bdb6d68d65c0b383828a521de08c188abf454 |
| Dirichlet non-IID, alpha = 0.3 extension | 120 | 2,400 | 430128e32744f1b2a5f585dcc876236cece5c84683f25a1a7a231283b51ae712 |

These are checksums for locally generated outputs, not for the original Zenodo artifact. The dedicated GitHub Actions workflow reproduces and uploads its own result artifacts. Hash equality across dependency versions/operating systems must be verified rather than assumed. The separate native CKKS benchmark has **not** been executed because a SEAL-enabled extension is not available in this local environment.

Twelve local regression tests passed. The main simulator and non-research GitHub workflows have separate scopes and may still have failures.

### Important manuscript-versus-reference checks

These are **not exact matches**, and therefore not confirmation of the manuscript's original reported data:

| Outcome (mean over 2 datasets x 5 seeds) | Submitted manuscript | Independent reimplementation |
| --- | ---: | ---: |
| Mean aggregation clean accuracy, no privacy | 93.5% approx. | 93.62% |
| Mean aggregation clean accuracy, DP sigma 0.5 | 86.9% | 86.35% |
| Mean aggregation clean accuracy, DP sigma 1 | 73.4% | 72.10% |
| Mean aggregation clean accuracy, DP sigma 2 | 57.8% | 57.00% |
| Mean aggregation clean accuracy, DP sigma 4 | 44.7% | 47.15% |
| Mean aggregation sign-flip accuracy drop, no privacy | 87.05 percentage points | 86.58 percentage points |
| Mean aggregation sign-flip drop, clipping only | 1.16 pp | 1.85 pp |
| Mean aggregation sign-flip drop, DP sigma 1 | 10.06 pp | 10.30 pp |

Likely sources of deviation include unspecified original shard/randomness conventions, malicious-client selection, and precise implementation details. No value above has been altered to match the paper.

### Preliminary bypass extension: sign-flip degradation

A key threat-model weakness in the original submitted design is **assuming malicious client releases also obey the prescribed clipping and local DP mechanism**. The new protocol-deviating extension explicitly bypasses both for malicious submissions. The table gives mean attacked-versus-benign test-accuracy degradation; each condition comprises 10 matched dataset-seed observations.

| DP mode | Aggregator | Compliant malicious clients | Bypass malicious clients | Increased degradation |
| --- | --- | ---: | ---: | ---: |
| sigma = 1 | Mean | 10.30 pp | 67.87 pp | **57.57 pp** |
| sigma = 1 | Median | 8.84 pp | 62.41 pp | **53.57 pp** |
| sigma = 1 | Multi-Krum | 6.86 pp | 52.50 pp | **45.64 pp** |

In the separate analysis, bootstrap resamples are stratified by dataset while resampling seeds within dataset. The mean DP sigma = 1 bypass-minus-compliant contrasts have 95% percentile intervals: Mean [54.61, 60.52] pp, Median [51.21, 55.83] pp, Multi-Krum [42.24, 49.05] pp. Two-sided exploratory Wilcoxon matched-pair p-values are 0.001953 each; Holm correction across all nine planned contrasts returns adjusted p = 0.017578 each for those three contrasts.

These findings refer **only to the constructed 15-client, 3-malicious, small-dataset Gaussian study**; they are not a cryptographic proof, evidence of novel defense, or a production threat guarantee. The corrected p-values are exploratory because methods/datasets and experiment design are still limited.

### Non-IID extension

For Dirichlet alpha 0.3, sign-flip mean losses at sigma 1 were Mean 5.85 pp, Median 5.32 pp and Multi-Krum 3.42 pp (10 dataset-seed observations each). These are **extensions** outside the original 720-run IID-style design, not the original paper's results. A credible heterogeneity claim needs several alpha values, stronger attack families, and more independent seeds.

## Research questions under active investigation

1. How much do privacy/robustness results change when Byzantine clients ignore clipping and Gaussian release rules?
2. Where is the failure boundary across noise, model dimensionality, attacker ratio and genuine client heterogeneity?
3. What verified cryptographic assessment/metadata-authentication protocol is necessary to combine encrypted addition with Byzantine filtering, and what overhead does it add?

The first is experimentally **probed**; the second and third are **not resolved** by this code. A new scientific security contribution must be established against recent prior art, not asserted solely because the study has a new code runner.

## Blocking work before manuscript resubmission

- Obtain original submitted Zenodo CSVs and original execution source; establish numerical and procedural correspondence with a documented provenance audit.
- Extend to realistic cybersecurity tasks and independent attacker models (adaptive/gradient-aware, backdoors, partial participation and multiple heterogeneity levels). Report attack success and detection metrics rather than accuracy alone.
- Formalize Byzantine noncompliance and specify which component *enforces* constraints; local client instructions alone cannot guarantee malicious compliance.
- Develop/evaluate a genuinely differentiable original contribution or an independently novel, formalized scientific measurement finding with rigorous baselines and theory.
- Benchmark native CKKS on real hardware, report ciphertext size and latency, key trust assumptions, metadata authentication and secure filtering; addition-only encrypted averaging is not Byzantine-robust aggregation.
- Verify formal DP assumptions, privacy unit, seed secrecy, release-level adjacency and sensitivity; seeded utility simulation does not guarantee operational DP.
- Release an immutable evidence archive with dataset versions/hashes, exact source commit, versions, seeds, per-run outputs, codebook and independent reproducibility checks.
- Run the whole repository's CI, including native and security jobs, and fix any current blockers. The isolated research test job does not certify the entire repository.

**Submission gate:** no submission-ready or accepted-paper claim is justified until evidence, scientific originality and cryptographic/security claims are independently validated.
