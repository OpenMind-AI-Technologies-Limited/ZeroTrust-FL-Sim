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
