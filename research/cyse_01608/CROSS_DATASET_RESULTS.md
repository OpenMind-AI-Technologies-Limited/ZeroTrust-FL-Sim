# Independent cybersecurity benchmark comparison

## Purpose and definition

The two historical intrusion-detection datasets provide an exploratory cross-source check of the same protocol-bypass and local privacy interaction. This is NOT a new algorithm or a population-level security guarantee.

For aggregator A, privacy mode p, and seed s, let E(A,p,s) be the matched additional test-accuracy degradation under a malicious clipping/noise BYPASS versus a malicious but COMPLIANT client. Let I(A,s) = E(A,DP sigma 1,s) - E(A,clipping-only,s). Define the triple interaction J(s) = I(Multi-Krum,s) - I(Mean,s).

## Verified source experiments

- [UNSW-NB15 real held-out five-seed study](UNSW_NB15_EVIDENCE.md): 6,000 training and 3,000 testing records sampled within the fixed publisher train/test split. Raw experiment evidence: https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42539230472.
- [NSL-KDD historic held-out five-seed study](NSL_KDD_EVIDENCE.md): 6,000 training and 3,000 testing records sampled within the fixed historical publisher split. Raw evidence: https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42582573246.

Both use 15 clients, 3 malicious, Dirichlet non-IID alpha 0.3, 20 rounds, sign-flip; Mean and Multi-Krum; clipping-only and DP sigma 1; compliant versus bypass attack. **160 total runs / 3,200 federated rounds**, but only two dataset sources with five seeds each.

| Dataset and endpoint | Mean triple interaction J | Seed-only percentile bootstrap 95% interval | Positive seed fraction |
| --- | ---: | ---: | ---: |
| UNSW-NB15 accuracy | +32.41 pp | 23.11–40.08 pp | 5/5 |
| NSL-KDD accuracy | +42.85 pp | 38.97–46.92 pp | 5/5 |
| Equal-source average accuracy | +37.63 pp | 32.94–42.00 pp | 10/10 |
| Equal-source average macro-F1 | +39.33 pp | 34.24–44.43 pp | 10/10 |
| Equal-source average balanced accuracy | +40.45 pp | 35.65–44.97 pp | 10/10 |

The positive direction appeared in all tested seed configurations. **Do not pool them as ten independent cybersecurity deployments or report a pooled significance p-value.** The percentile bounds reflect conditional seed variation given exactly two fixed historical datasets, *not uncertainty across unseen real-world environments*. The contrast is exploratory and emerged after prior single-dataset analyses.

## Reproducibility

[Cross-study GitHub Actions run](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42582952345) retrieved two already completed source-run artifacts, verified both original run-CSV hashes and condition counts, computed 30 per-seed-by-metric interaction rows, and exported nine summary rows plus a checksum manifest. Source code: cross_dataset_compare.py. Tests: tests/test_cross_dataset_compare.py.

Paired source CSV SHA-256 values:
- UNSW: 2486199e149fe4f50b063937852b87a57e1c6ae98881d37fa50f0519b9e32ad4
- NSL: 0d3a671b17f8360c8ca2eaf72d1443fa078329208c2760bd6d1e4f503709d68a

Generated output SHA-256:
- Per-seed effect CSV: f51ecd5fd5672b72df9dd87a586385662e534dc8297b1cd64515eede552eec7d
- Summary CSV: 6cdcb4143d2ee4f41345b70119dd7293b460d571698c4b71e826a2bb6c1717ff

These prior GitHub run artifacts have a finite retention period. To reproduce after expiry, rerun both data-study workflows with their pinned sources and rerun the comparison with the newly generated paired CSV files.

## What remains before submitting a novel scientific article?

- The original manuscript's reported 720-run raw files and original execution code have not been independently recovered; separate newly generated results must not be silently substituted.
- One attack family, one linear model, two historical datasets, five seeds, no independent modern intrusion corpus, no controlled client dropouts, and no relevant recent privacy-compatible Byzantine baselines.
- Current implementation has no enforced proof that a Byzantine client clipped/noised its encrypted update; native CKKS only performs additive averaging. Thus **joint confidential Byzantine-robust aggregation is NOT demonstrated**.
- A novel algorithm, formal security bound or independently validated novel measurement must be articulated and compared with published work. More replications alone do not establish novelty.
