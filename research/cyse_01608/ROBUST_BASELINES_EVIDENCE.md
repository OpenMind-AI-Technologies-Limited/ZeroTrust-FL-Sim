# RFA and plaintext server-gated aggregation: actual two-source baseline evidence

**Status:** independent experiment extension for CYSE-D-26-01608; original submitted 720-run manuscript data are NOT recovered or replaced.

## Method and prior-art distinction

Six methods were evaluated: arithmetic Mean; Multi-Krum; **RFA-style geometric median** estimated by an unweighted smoothed Weiszfeld procedure; and three server-enforced norm-gated variants (Mean, geometric median, Multi-Krum). The RFA-style estimator and norm projection are **existing techniques, not novel algorithms**. The RFA benchmark is a documented implementation choice, not a claim of exact algorithm/parameter equivalence to every reference paper.

- RFA background: Pillutla et al., *Robust Aggregation for Federated Learning*, IEEE TSP 2022 / arXiv 1912.13445, geometric-median aggregation and Weiszfeld-based approximation.
- Contemporary comparisons use RFA, Multi-Krum and FLTrust as established representative baselines; see the 2025 research discussion https://doi.org/10.1186/s40537-025-01165-y.
- FLTrust with a clean server-held root dataset is a **different trust model and has not been implemented in this branch**; avoid implying that server clipping is an equivalent FLTrust comparison.

### Explicit trust and privacy boundary

The server norm gate operates on client-submitted **plaintext or noisy plaintext** update vectors, enforcing norm at most C=0.1 before performing one of the aggregation rules. Thus, it can constrain even noncompliant Byzantine *magnitudes*. However, the server observes update contents, and client identity/authentication must be provided by a separate trusted channel. The norm gate cannot prove which client ran Gaussian noise locally, cannot protect against a coordinated in-ball adaptive attack, and does **not** operate on opaque CKKS ciphertext. Under honest locally private random releases, server postprocessing would not add privacy cost, but these experiments use fixed and discoverable noise seeds and demonstrate **no operational LDP guarantee**.

A simple deterministic mathematical check for server-clipped Mean: with n clients and f attacker positions, let P_C(x)=x·min(1,C/||x||). For the same honest vectors and two arbitrary Byzantine inputs, the mean update difference is bounded in L2 by **2fC/n** by the triangle inequality. With n=15, f=3 and C=0.1, that is 0.04 per-round update L2. This does NOT bound model accuracy, Krum selection, or convergence, and is not claimed as a new theorem. The bound is covered by tests/test_robust_baselines.py.

## Verified real-source experiment

- [Success: GitHub Actions 42587967166](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42587967166), both dataset jobs passed after correcting the initial CI expected-run-count assertion.
- Data sources: pinned historical UNSW-NB15 and NSL-KDD publisher train/test splits, source hashes verified before execution; train-only normalization; 6000 training and 3000 heldout test rows per seed.
- Five seeds; 15 clients, 3 Byzantine; non-IID Dirichlet alpha 0.3; 20 rounds; two privacy modes (clip-only, local Gaussian sigma 1), two attacker compliance settings and benign/sign-flip conditions.
- Six aggregators × five seeds × two privacy modes × two compliance policies × two attack states = **240 executions / 4800 rounds per dataset**. Across both datasets: **480 executions / 9600 rounds**. These are highly correlated simulation conditions, not 480 independent statistical replicates.
- All raw rows, paired effects, class-imbalance-aware metrics and source checksum manifests are archived as two separate GitHub artifacts; original dataset bytes are never redistributed.

### Observed mean held-out test accuracy under Byzantine protocol bypass

| Dataset | Rule | Clipping-only | Gaussian sigma 1 |
| --- | --- | ---: | ---: |
| UNSW-NB15 | Mean | 26.47% | 26.44% |
| UNSW-NB15 | Multi-Krum | 74.91% | 26.42% |
| UNSW-NB15 | RFA-style geometric median | 74.26% | 26.43% |
| UNSW-NB15 | Server-clipped Mean | 70.66% | 27.10% |
| UNSW-NB15 | Server-clipped RFA-style median | 74.23% | 27.15% |
| UNSW-NB15 | Server-clipped Multi-Krum | 74.93% | 26.14% |
| NSL-KDD | Mean | 28.34% | 25.27% |
| NSL-KDD | Multi-Krum | 75.17% | 25.91% |
| NSL-KDD | RFA-style geometric median | 74.92% | 26.95% |
| NSL-KDD | Server-clipped Mean | 74.58% | 26.86% |
| NSL-KDD | Server-clipped RFA-style median | 74.87% | 26.97% |
| NSL-KDD | Server-clipped Multi-Krum | 75.02% | 27.79% |

All numbers are *five-seed averages under the bypass sign-flip condition*. They are not pooled significance estimates. Full clean/compliant/bypass outcomes, macro-F1 and balanced accuracy can be independently checked in baseline_runs.csv, baseline_pairs.csv and baseline_summary.csv. Do not misrepresent 25–27% accuracy as strong cybersecurity protection.

### Observed negative scientific result

Although the plaintext norm gate gives a per-message magnitude bound, the tested Gaussian sigma=1 release tends to reduce useful update directionality under this high-dimensional, low-C setup. Even RFA-style aggregation and norm-gated variants collapsed to low held-out accuracies under malicious protocol bypass. Thus **post-noise norm projection alone did not solve the measured privacy–robustness failure**. This directly argues *against* claiming a finished novel defense and motivates different trust/noise/verification architectures.

### Remaining publication conditions

The original 720-run author dataset and its Additional Files 1–3 have not been independently recovered. The original-data structural gate (original_evidence_gate.py) rejects missing, incomplete and modified source files and checks a user-provided historical manifest; self-declared metadata cannot establish historic authenticity.

At least one genuinely new protocol/algorithm or rigorously differentiated threat-model finding, current SOTA comparators, stronger adaptive/targeted attacks, modern intrusion data and an implementable CKKS-compatible Byzantine input-validity proof are still necessary for claims exceeding this measured negative result. **CKKS additive averaging cannot directly perform these plaintext selection functions.**

The research branch remains draft; do not merge code or resubmit the paper solely because tests pass.
