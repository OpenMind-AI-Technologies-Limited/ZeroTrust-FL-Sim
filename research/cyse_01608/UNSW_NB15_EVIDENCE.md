# UNSW-NB15 real network-intrusion study: verified five-seed evidence

This is a supplementary experiment for CYSE-D-26-01608, not the source of the manuscript's original 720 runs.

## Data provenance
- Publisher: UNSW Canberra, UNSW-NB15; official source https://research.unsw.edu.au/projects/unsw-nb15-dataset. Source dataset is third-party academic research data and is not redistributed by this repository.
- The 175,341 training and 82,332 testing rows came from a pinned independently hosted GitHub mirror, commit 44bbd02b9e70f74dd915218d5eb702f125341ffc. Verified input Git blob SHA-1 values were c8226c710f99228ee3ac60d3ef5a610677e3c36d (train) and 5a120da5e21fa6b0f90ad54ab22027f29c8ad2df (test).
- Verified input SHA-256: train bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa; test 734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559.
- The publisher's train/test split was preserved. Each seed sampled 6,000 training rows and 3,000 held-out testing rows from within the respective original split; this is a SUBSAMPLED evaluation, not full-dataset SOTA evidence.
- To prevent easy label leakage, id and attack_cat were excluded from model features. One-hot vocabularies, numeric imputation and scaling were fitted on the training sample only. Binary benign/attack label and numeric/categorical network attributes formed the model input.

## Controlled experiment
15 clients, 3 Byzantine clients, Dirichlet alpha=0.3, 20 rounds, 5 independent study seeds (0–4), two aggregators (Mean, Multi-Krum), clipping-only and local Gaussian sigma=1, benign versus compliant or noncompliant sign-flip attacks. 80 executions / 1,600 rounds.

Five-seed mean held-out accuracy:

| Aggregator | Privacy | Benign | Compliant attack | Bypass attack |
|---|---|---:|---:|---:|
| Mean | Clipping only | 72.29% | 70.66% | 26.47% |
| Mean | DP sigma=1 | 72.25% | 70.80% | 26.44% |
| Multi-Krum | Clipping only | 73.77% | 74.93% | 74.91% |
| Multi-Krum | DP sigma=1 | 66.47% | 59.03% | 26.42% |

Per-run macro-F1, balanced accuracy, confusion matrix and attack-induced differences appear in unsw_runs.csv and unsw_paired.csv. An attacked run can occasionally score higher than the benign comparator; negative loss should not be silently truncated.

## Matched interaction and inference
Define E(A,p) as the bypass attack's benign-matched accuracy loss minus the compliant attack's loss. Define I(A) = E(A, DP sigma=1) minus E(A, clipping only), and J = I(Multi-Krum) minus I(Mean). All contrasts are computed per matching seed on the same held-out source.

| Contrast | Mean difference | 95% seed-bootstrap interval | Wilcoxon p | Holm p |
|---|---:|---:|---:|---:|
| I(Mean) | +0.17 percentage points | [-1.03, 2.37] | 0.625 | 1.0 |
| I(Multi-Krum) | +32.59 percentage points | [25.55, 39.31] | 0.0625 | 0.5625 |
| J | +32.41 percentage points | [23.11, 40.08] | 0.0625 | 0.5625 |

The family comprises 9 exploratory tests: accuracy, macro-F1 and balanced accuracy for the three method contrasts. None passed Holm correction. Five seed-bootstrap intervals only represent conditional seed variation on one source, not out-of-dataset uncertainty or a security guarantee.

## Auditable workflow and limitations
- Five-seed real-data benchmark GitHub Actions: https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42538421001
- Five-seed interaction analysis GitHub Actions: https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42539230472
- The latter artifact includes unsw_manifest.json, unsw_runs.csv, unsw_paired.csv, unsw_interaction.csv and unsw_interaction_manifest.json; the manifest records source/data checksums.
- This is an exploratory one-dataset evaluation with a simple linear classifier, sign-flip attacks, 5 seeds, fixed privacy settings, sampled train/test rows and simulated clients. It does NOT demonstrate independent dataset generalization, a new algorithm, a production DP guarantee, secure encrypted Byzantine filtering, or statistical confirmation of the primary interaction.
