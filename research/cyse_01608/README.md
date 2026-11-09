# CYSE-D-26-01608 — Privacy/Byzantine/CKKS paper study

This directory is a **separate, auditable implementation of the experimental design** in the manuscript *Privacy–Robustness Trade-offs in Federated Learning: Local Differential Privacy, Byzantine Aggregation, and CKKS Secure Aggregation*. It is **not a claim that this is the original experiment source**. Do not represent newly generated numerical outputs as the originally submitted 720 results unless source artifacts are independently matched.

**Research identity:** the manuscript is about local DP, Byzantine robustness and separately examined CKKS additive aggregation. It is not a Zero-Trust control-plane paper. The primary submitted matrix uses IID-style partitioning, not non-IID; non-IID is a later robustness extension.

## Run the manuscript-design matrix

From the repository root:

~~~bash
python -m pip install numpy scipy scikit-learn pytest
python research/cyse_01608/reproduce.py --output artifacts/cyse_01608
pytest -q research/cyse_01608/tests
~~~

Default design: **2 datasets × 5 seeds × 4 aggregators × 6 privacy modes × 3 threat states = 720 runs**, each 20 full-participation rounds (14,400 rounds total). This independent implementation uses 75/25 stratified train/test partition, train-only standardization, Breast Cancer Wisconsin Diagnostic and Digits, 15 clients (3 malicious), zero-initialized linear softmax model, local full-batch step, rate 0.12, L2=0.0001, C=0.1, replacement-adjacency sensitivity 2C, sign flip -5u, cyclic label flip, mean, median, 3-per-tail trimmed mean and Multi-Krum f=3, k=5.

Generated evidence in output directory:

- **runs.csv**: final held-out accuracy and loss for each executed condition.
- **paired.csv**: benign-matched attack losses (percentage points).
- **summary.csv**: per-dataset descriptive attack-loss means.
- **manifest.json**: complete parameters, seed matrix, software versions and SHA-256 checksum.

The submitted paper does not expose every original numerical/RNG convention. **A similar result is not exact replication.** Main code here is separate from the repository's existing synthetic/Fashion-MNIST/CIFAR-10 simulator.

## Additional experiments — not part of original 720 runs

Protocol-deviating adversaries that ignore malicious-client clipping/noise:

~~~bash
python research/cyse_01608/reproduce.py --output artifacts/cyse_01608_bypass --attacker-compliance bypass --datasets breast_cancer --aggregators mean median --privacy-modes clip_only dp_1 --threats benign sign_flip
~~~

Non-IID robustness extension:

~~~bash
python research/cyse_01608/reproduce.py --output artifacts/cyse_01608_non_iid --partition dirichlet --alpha 0.3 --datasets digits --aggregators mean median --privacy-modes none dp_1
~~~

## Security boundaries and next academic work

1. The Gaussian stream is deterministically seeded to make paired utility comparisons possible. If the seed is disclosed/predictable, this process **does not satisfy operational differential privacy**. RDP figures are idealized mechanism calculations assuming proper private randomness and stated sensitivity/release assumptions.
2. Malicious clients cannot be assumed to follow clipping/privacy instructions. The bypass extension studies this issue but is not itself a defense or cryptographic proof.
3. **CKKS operations are not mixed into this experiment runner.** The separate native CKKS path supports encrypted additive averaging, not encrypted median/Multi-Krum or verified malicious-input filtering. Authenticated weights and cryptographic binding need separately specified protocol and independent testing.
4. Academic novelty requires verified prior-work comparison, stronger threat baselines, independent seeds and statistical uncertainty, secure privacy-inference evaluation, encryption overhead, and security analysis. This runner is a reproducibility foundation, **not a finished Cybersecurity submission**.
5. The manuscript cites additional CSVs/Zenodo artifacts that must be independently acquired and compared with these generated results. Differences in seed handling, client shard assignment, malicious client selection, and regularization may change results. Never silently replace original results.

For native CKKS testing, build with ZTFL_ENABLE_CKKS=ON and run the existing privacy tests. A skipped native CKKS test is not evidence that cryptographic integration passed.


## Independent evidence and statistical audit

See RESULTS.md for three executed experiment grids, exact local CSV checksums, preliminary bypass comparisons, and mandatory submission gates. For a paired security-compliance analysis after producing the reference and bypass CSVs:

~~~bash
python research/cyse_01608/security_analysis.py --compliant artifacts/cyse_01608/paired.csv --bypass artifacts/cyse_01608_bypass/paired.csv --output artifacts/cyse_01608_bypass/security_comparison.csv
~~~

The analysis resamples seeds **within each dataset** for bootstrap intervals and applies Holm correction across reported Wilcoxon paired comparisons.

## CKKS overhead (native build only)

~~~bash
python research/cyse_01608/ckks_benchmark.py --clients 15 --dimension 10000 --trials 10 --output artifacts/cyse_01608/ckks_benchmark.csv
~~~

This requires native Microsoft SEAL support; it fails explicitly when unavailable. Any numbers are for additive CKKS *correctness, latency and ciphertext volume*, not secure Byzantine filtering or authenticated ciphertext-bound weights.


## Crossed privacy/Byzantine sensitivity experiments

The isolated stress runner compares the same held-out test set under paired benign and malicious executions and sweeps client heterogeneity, Byzantine-client count, privacy mode, aggregation rule and attacker compliance. The reported operational failure fraction counts study-specific attack-induced accuracy losses above an **explicitly selected** threshold; this is not a proven security bound.

~~~bash
python research/cyse_01608/stress_matrix.py --output artifacts/cyse_01608_stress --datasets breast_cancer digits --seeds 0 1 2 3 4 --partitions iid dirichlet --alphas 0.3 1.0 --malicious-clients 1 3 6 --aggregators mean median multi_krum --privacy-modes clip_only dp_1 --threats sign_flip --attacker-compliance compliant bypass --rounds 20
~~~

Expected output: stress_pairs.csv, stress_summary.csv and stress_manifest.json. The full command is a large execution and may require batching; an interrupted batch is *not* considered completed or included in paper results.

## Actual cybersecurity CSV datasets

The optional CSV loader never downloads or invents an intrusion dataset. Provide your own legally usable benchmark. Specify the true label and, when available, a site/device/session group to prevent leakage from correlated training/test rows. Explicitly exclude IPs, flow identifiers, timestamps, attack label aliases or other columns that could leak target information. Numeric features only are accepted; missing numeric values are imputed using training statistics, and scaling is fitted on training rows only.

Example (replace all column names and path with those of the real dataset):

~~~bash
python research/cyse_01608/cyber_experiment.py --csv /path/to/intrusion_flows.csv --label attack_label --group device_id --exclude flow_id source_ip destination_ip timestamp --output artifacts/cyse_01608_intrusion --partition dirichlet --alpha 0.3 --seeds 0 1 2 3 4 --rounds 20
~~~

The output includes cyber_runs.csv, cyber_pairs.csv and cyber_manifest.json with dataset SHA-256, splits, feature names and source checksum. The generic cybersecurity CSV adapter tests use synthetic fixtures, but a separate actual UNSW-NB15 heldout evaluation has now been completed (UNSW_NB15_EVIDENCE.md); all adapter tests use clearly labeled synthetic fixtures. Class imbalance (macro-F1), targeted/backdoor attack success, external validity and independent data-source verification are still required for journal-level conclusions. The original 720-condition Breast Cancer/Digits evidence remains unchanged and separate.


## Newly measured cybersecurity and CKKS results

- [Five-seed UNSW-NB15 real heldout evaluation](UNSW_NB15_EVIDENCE.md)
- [Measured native SEAL/CKKS timing and accuracy](CKKS_BENCHMARK_RESULTS.md)
- [Focused research questions and prior art](RESEARCH_GAP_RQS.md)
- [Original additional files and DOI audit](DATA_AVAILABILITY_AUDIT.md)

These newer studies must not be represented as the submitted manuscript's original 720 runs or proof of a newly invented encrypted Byzantine defense.
