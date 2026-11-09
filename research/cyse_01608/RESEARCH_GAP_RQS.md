# Research novelty audit and focused questions for CYSE-D-26-01608

The original manuscript studies clipping, local Gaussian differential privacy, Byzantine aggregation and separately CKKS addition. The repository title ZeroTrust-FL-Sim does not establish that this particular manuscript contributes Zero Trust access control.

## Existing scientific literature limiting novelty claims
- Practical Differentially Private and Byzantine-resilient Federated Learning, SIGMOD 2023: https://shao3wangdi.github.io/papers/SIGMOD2023_Byzantine.pdf. The intersection of DP and Byzantine robustness is not novel in itself.
- BVDFed, Byzantine-resilient and verifiable aggregation for differentially private federated learning, Frontiers of Computer Science, DOI https://doi.org/10.1007/s11704-023-3142-5.
- SAMFL, secure aggregation with Byzantine-robustness by functional encryption, Journal of Systems Architecture, DOI https://doi.org/10.1016/j.sysarc.2024.103304.
- Byzantine-Robust and Differentially Private Federated Optimization under Weaker Assumptions, UAI 2026: https://proceedings.mlr.press/v337/islamov26a.html. Novelty there includes algorithmic and formal convergence/privacy analysis.
- BPFLH, Byzantine-Robust Privacy-Preserving Federated Learning for Heterogeneous Data, IEEE TDSC 2026, https://doi.org/10.1109/TDSC.2026.3661522. Existing joint CKKS/Byzantine literature rules out a first-ever claim.
- Byzantine-resilient federated learning with dynamic scoring matrix and variant PBFT consensus under differential privacy, Information Sciences, DOI https://doi.org/10.1016/j.ins.2025.122682.

These sources are research context; every reference should still receive a complete independent bibliography check when drafting the manuscript. Merely composing existing Mean, Median, Multi-Krum, clipping, Gaussian privacy and CKKS addition is not a new security mechanism.

## Formalized diagnostic (not a novel algorithm)
Let n clients include a Byzantine subset B of size f. Honest clients produce clipped local updates and noisy releases. A restricted compliant adversary also applies clipping/noise to its poisoned updates, whereas a compromised noncompliant adversary bypasses them. The aggregator has no inherent proof that the client followed its local protocol. For held-out accuracy, define L(A,p,q,s) as matched benign accuracy minus attacked accuracy for aggregator A, privacy configuration p, adversary compliance q and seed s. The excess bypass effect is E(A,p,s)=L(A,p,bypass,s)-L(A,p,compliant,s). The privacy interaction is I(A,s)=E(A,DP,s)-E(A,clip-only,s). The aggregator interaction J(s)=I(Multi-Krum,s)-I(Mean,s).

### Research questions
- RQ1: How much does the DP/Byzantine robustness conclusion change when Byzantine clients bypass assumed clipping/noise?
- RQ2: Which privacy noise, fault counts and client heterogeneity settings increase the admission of malicious updates by Krum-style distance selection? Ground truth is simulator-only and is not an attack-detector output.
- RQ3: Does the privacy-by-bypass interaction recur under a real held-out intrusion-detection workload, using accuracy, macro-F1, balanced accuracy and matched inference?
- RQ4 (OPEN): Which authenticated encrypted-input proof, trusted key management and privacy-compatible filtering protocol could actually deliver Byzantine robustness with CKKS, and at what bandwidth and computational cost?

## Evidence and remaining originality gap
- RQ1: independent reference reproduction and compromised-client stress data. Original manuscript outputs remain unverified.
- RQ2: Multi-Krum malicious-admission study, conditional exploratory effects, limited to two small tasks/5 seeds and basic attack configurations.
- RQ3: sampled real UNSW-NB15 five-seed 80-run experiment. Primary method interaction +32.41 pp; Holm-adjusted p=0.5625. No statistically confirmed effect after correction.
- RQ4: native CKKS addition shows correctness, timing and ciphertext overhead; cryptographically verifiable encrypted Byzantine filtering is NOT implemented.
- Original 720-run raw data: Zenodo 10.5281/zenodo.22711022 is a software ZIP, not independently verified Additional Files 1-3.

Before journal submission, independently recover original submitted CSVs or transparently replace manuscript tables with newly generated evidence; test at least another independent cybersecurity dataset and stronger adaptive/targeted attacks, compare to contemporary privacy-compatible Byzantine baselines, establish a genuinely new finding or algorithm with a testable formal hypothesis and sufficient statistical power, and keep all encryption/DP claims aligned with actual implemented guarantees.
