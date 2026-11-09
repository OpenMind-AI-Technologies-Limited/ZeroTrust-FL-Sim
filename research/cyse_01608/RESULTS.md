# CYSE-D-26-01608 — Execution evidence and remaining paper blockers

**Scope:** This is an independently executed study-design reimplementation. It is **not original submitted manuscript data**, a new algorithm, a privacy guarantee, or a validated Cybersecurity-journal contribution. See README.md for run instructions and experimental assumptions.

## Independent experimental execution (8 November 2026)

Local environment: Python 3.13, NumPy 2.3.5, SciPy 1.17.0, scikit-learn 1.8.0.

| Dataset grid | Runs | FL rounds | CSV SHA-256 |
| --- | ---: | ---: | --- |
| Original manuscript-design reference (IID-style, compliant) | 720 | 14,400 | 8267b5342d4e19908966d3c2f2926f0d95e36e8c09e74010307974e366557681 |
| Malicious clipping/DP bypass extension | 180 | 3,600 | d87275205b8a54dcd403bd3ed55bdb6d68d65c0b383828a521de08c188abf454 |
| Dirichlet non-IID, alpha = 0.3 extension | 120 | 2,400 | 430128e32744f1b2a5f585dcc876236cece5c84683f25a1a7a231283b51ae712 |

These are checksums for locally generated outputs, not for the original Zenodo artifact. The dedicated GitHub Actions workflow reproduces and uploads its own result artifacts. Hash equality across dependency versions/operating systems must be verified rather than assumed. The initial local environment lacked native SEAL, but an independent native Microsoft SEAL CKKS benchmark has since been completed in GitHub CI. See CKKS_BENCHMARK_RESULTS.md.

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



## Added 8 November 2026 — Multi-Krum malicious-admission evidence (RQ2)

The independent **oracle-labeled** supplementary experiment ran **160 cases / 3,200 FL rounds**, crossing 2 small sklearn datasets (Breast Cancer/Digits), 5 study seeds, IID vs Dirichlet alpha=0.3, malicious-client counts 3/6 among 15, clipping-only vs Gaussian sigma=1, and compliant vs protocol-bypassing sign-flip attackers. This study is **separate from the original 720-run manuscript design**. Every experiment records selected malicious client IDs by comparison against the simulator's actual attacker set; this metric is not an attack-detection precision score.

For the **IID** conditions, the mean fraction of Multi-Krum-selected updates originating from malicious clients was:

| Malicious clients | Privacy mode | Compliant | Bypass | Excess admission |
| --- | --- | ---: | ---: | ---: |
| 3/15 | clipping only | 0.000 | 0.000 | 0.000 |
| 3/15 | local DP sigma=1 | 0.193 | 0.339 | 0.146 |
| 6/15 | clipping only | 0.000 | 0.000 | 0.000 |
| 6/15 | local DP sigma=1 | 0.389 | 1.000 | 0.611 |

The DP sigma=1, 6-malicious IID contrast had a dataset-stratified percentile 95% bootstrap interval for the excess fraction of approximately **[0.579, 0.642]**, a two-sided paired Wilcoxon p=0.001953 and Holm-adjusted p=0.015625 across 8 predeclared study comparisons. The 3-malicious IID contrast's paired Wilcoxon p=0.2324 was **not** significant after multiplicity correction, despite a bootstrap percentile interval that excludes zero. This divergence means strong inference is not justified for that condition. In the non-IID, 6-malicious DP sigma=1 setting, observed excess selection was 0.343, but Holm-adjusted p=0.1367, which likewise does not meet 0.05.

These findings are **exploratory, simulator-specific, and dependent on exactly this sign-flip attack, 15 clients and the chosen small datasets**; they are not novelty, universal failure boundaries, proof of robust filtering, or deployable DP. Additional independent datasets/seeds and threat baselines are necessary.

Supporting artifacts (generated locally with source hashes and a run manifest): results_selection/selection_runs.csv, selection_summary.csv, selection_inference.csv and selection_manifest.json in the separately provided evidence archive. Branch source: selection_experiment.py and selection_inference.py. The dedicated research CI also runs a smaller two-dataset smoke matrix and checks inference cardinalities.

## Security implementation status

The Go standard library toolchain is pinned to 1.27.3 (replacing vulnerable 1.27.1), golang.org/x/net is updated to 0.62.0 with checksums regenerated by the build toolchain, and the coordinator health probe is rebuilt with explicitly patched go-jose/v4 4.1.6 and x/net 0.62.0. These patches require a green scan on the latest commit; earlier scans confirmed coordinator and recovery container gates after the patch.

The cybersecurity CSV adapter now emits macro-F1, balanced accuracy, per-class recall and confusion-matrix evidence **when genuine external CSV data is supplied**. A five-seed UNSW-NB15 real intrusion-detection extension (80 runs and 1,600 rounds) has since been completed. See UNSW_NB15_EVIDENCE.md. These results do not replace the submitted original 720-run numbers.

See SECURITY_MODEL.md for formal assumptions and claims that must **not** appear as verified paper findings.


## Subsequent verified real-data and native-CKKS evidence (2026-11-09)

- UNSW_NB15_EVIDENCE.md records the actual 80-run five-seed, sampled held-out cyber intrusion benchmark, model metrics, input checksums, paired effects and limits. The privacy-by-method interaction J was +32.41 percentage points, but Holm-adjusted p=0.5625 across 9 contrasts, so it is NOT a statistically confirmed finding.
- CKKS_BENCHMARK_RESULTS.md records 3 actual SEAL trials with 15 clients and 4096 coordinates, ~647ms sequential encryption, ~41.87ms addition and ~41.86ms decryption, ciphertext ~5.9 MB and maximum numerical error 1.67e-9. CKKS encrypted Byzantine filtering remains unimplemented.
- RESEARCH_GAP_RQS.md lists prior DP/Byzantine/cryptographic work and the evidence-supported RQ1–RQ4 boundaries. There is not yet a verified novel defense or a journal-ready research contribution.


## Second independently measured cybersecurity dataset and paired cross-study evidence

- [NSL-KDD historical publisher-split study](NSL_KDD_EVIDENCE.md): [source-verified GitHub Actions run 42582573246](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42582573246), five seeds, 80 runs, 1,600 rounds. The data are old and downloaded from a pinned non-authoritative public mirror because the original publisher no longer hosts them.
- [Two-source interaction comparison](CROSS_DATASET_RESULTS.md): [GitHub Actions run 42582952345](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42582952345) produced 30 per-seed-by-endpoint records and 9 summary contrasts. The privacy-by-bypass-by-aggregator interaction was +32.41 pp for UNSW-NB15 and +42.85 pp for NSL-KDD, equal-source descriptive mean +37.63 pp (seed-only interval 32.94–42.00 pp).
- These outcomes are **exploratory**, with only 2 historical sources, 5 seeds each, one classifier family, and one sign-flip attack. No pooled population p-value, new defense, cryptographic Byzantine filtering or true operational local DP is demonstrated. Original submitted raw files remain unrecovered.


### Independent re-execution of both external benchmarks

[Run 42583791876](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42583791876) passed end-to-end: pinned dataset download and verification, **160 real-data simulation runs / 3,200 FL rounds**, paired comparison, checksum provenance, and archived outputs. Both paired experiment CSV files matched earlier verified source-runs byte-for-byte; harmless last-decimal floating-point differences occurred in some unsw_runs.csv loss values only. This is *experimental reproducibility*, not evidence that a new defense exists or that the original submitted 720 runs have been recovered.


## RFA and server-enforced plaintext update-bound extensions (2026-11)

- [Baseline method and source details](ROBUST_BASELINES_EVIDENCE.md): additional 480 real historical intrusion-detection conditions (240 UNSW-NB15 + 240 NSL-KDD; 9,600 rounds) comparing known Mean, Multi-Krum and RFA-style geometric median to three plaintext server-gated variants.
- The fixed-server-cap projected mean admits an elementary per-round L2 replacement bound of 2fC/n (0.04 for f=3, n=15, C=0.1). This **does not bound accuracy or prove security of Krum or CKKS**.
- Sign-flip bypass heldout accuracy with DP sigma=1 remained roughly 25–28% in these two experimental datasets across RFA and the norm-gated alternatives, despite clipping; reported negative result, not a proven successful defense.
- [Original-run structural/provenance gate](ORIGINAL_DATA_GATE.md) is implemented and tested with **synthetic** fixtures. Historical original 720-run CSVs remain absent and unverified.
