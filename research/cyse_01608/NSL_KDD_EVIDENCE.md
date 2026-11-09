# NSL-KDD: independent held-out five-seed cybersecurity evaluation

This is a supplementary dataset for CYSE-D-26-01608, not the original submitted manuscript's 720-run experiment. NSL-KDD is a legacy 2009-era intrusion-detection dataset and cannot validate modern deployment performance.

## Origin and source integrity

The original University of New Brunswick dataset page, https://www.unb.ca/cic/datasets/nsl.html, states that direct downloads are no longer available. Our source is a **non-authoritative public mirror** at https://github.com/Jehuty4949/NSL_KDD, locked to Git commit 27bbbdf5c5cccf9970b8b6037a0f19dc09c5a0a9. Raw data are not redistributed by the experiment output.

| Standard file | Published rows | Git blob SHA-1 | File SHA-256 |
| --- | ---: | --- | --- |
| KDDTrain+.txt | 125,973 | 20002897492adc110190a10509aa694f26f7f308 | 1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95 |
| KDDTest+.txt | 22,544 | b30e89605285a5ccd8cf8fd38dba72906c20d3dd | fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84 |

The fixed historical publisher train/test split is respected. For each seed, 6,000 training rows and 3,000 test rows are sampled *within their own split*. The attack-type label and difficulty field are excluded from features. 38 numeric features and 3 categorical columns are preprocessed with training-only median imputation, scaling and one-hot fitting; held-out unseen categories are ignored safely. Binary normal versus attack classification is evaluated. Some attack types occur only in the test set.

## Five-seed method comparison

15 participating clients, 3 malicious; non-IID Dirichlet alpha 0.3; 20 rounds; seeds 0 to 4; Mean vs Multi-Krum; clipping-only vs local Gaussian sigma 1; compliant vs malicious protocol-bypass sign-flip.

**80 complete executions and 1,600 federated rounds.** Five-seed means of held-out test accuracy:

| Aggregator | Privacy | Benign | Compliant attack | Bypass attack |
| --- | --- | ---: | ---: | ---: |
| Mean | Clip only | 75.32% | 74.58% | 28.34% |
| Mean | DP sigma 1 | 73.91% | 70.78% | 25.27% |
| Multi-Krum | Clip only | 74.41% | 75.02% | 75.17% |
| Multi-Krum | DP sigma 1 | 70.01% | 67.87% | 25.91% |

Per-run macro-F1, balanced accuracy and confusion matrices are in the run CSV. Matched benign-versus-attacked effects are in the paired CSV. Attacked accuracy sometimes exceeds the benign counterpart; negative observed loss is not trimmed or interpreted as an actual benefit.

Triple-factor privacy-by-compliance-by-aggregator interaction, J = I(Multi-Krum) - I(Mean), averaged **+42.85 percentage points** across five seeds. The seed-conditional bootstrap interval is **38.97 to 46.92 pp**, not a population-level confidence interval. See CROSS_DATASET_RESULTS.md.

[Actual source data run](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42582573246) produced the downloadable machine-readable evidence archive (run manifest, 80-row run CSV and 40-row paired CSV).

## Important limitations

This is a relatively small subsampled evaluation with one simple model family, one sign-flip attack, five seeds, and an old data distribution. It does **not** show encrypted Byzantine filtering, a deployed differential privacy guarantee, a new algorithm, a targeted-backdoor defense, or superiority over the state of the art. Original submitted experiment data provenance remains unresolved. A second dataset does not by itself supply a novel scientific contribution.
