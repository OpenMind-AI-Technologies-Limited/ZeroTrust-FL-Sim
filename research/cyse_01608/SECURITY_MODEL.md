# CYSE-D-26-01608 security model and claim boundaries

**Paper area:** Privacy–robustness interactions in federated learning with local Gaussian update privacy, Byzantine aggregation and separate CKKS encrypted averaging. The repo title "ZeroTrust-FL-Sim" **does not make this a Zero Trust paper**. The original manuscript reported IID-style Breast Cancer/Digits experiments.

## Formal system / threat model

At training round t, there are n=15 participating clients (unless a sensitivity extension changes the attacker count). A subset B of size f is Byzantine. Honest clients compute an update u_i from their local shard. For the clipped/noisy local release, the experiment uses:

- bar(u_i) = u_i * min(1, C / ||u_i||_2)
- released_i = bar(u_i) + xi_i, xi_i ~ N(0, (2 C sigma)^2 I_d)
- C = 0.1 in the original reconstruction; 20 full-participation rounds; user-specified delta.

The Gaussian RDP formula is for **replace-client adjacency of the clipped update release with L2 sensitivity at most 2C**, under *fresh, unpredictable randomness and stated composition assumptions*. It does **not** automatically provide record-level privacy, immunity from membership inference, or privacy for a compromised client that disregards the prescribed mechanism.

**Simulator limitation:** the experiment fixes and publishes deterministic random seeds for utility comparison. Anyone able to reproduce those released noise vectors can subtract them. It is therefore **not a deployed local-DP system**; quoted epsilon values are reference accounting calculations for the ideal Gaussian mechanism under appropriate secret randomness.

### Byzantine attacker variants

- **Compliant:** the simulator creates an adversarial update but subsequently applies prescribed clipping/noise to it. This is a *restricted, non-worst-case* attacker.
- **Protocol bypass:** the adversary emits an arbitrary sign-flipped or other attack update without applying the honest clipping/noise rules. This represents a compromised client and tests the actual server's vulnerability to unenforced instructions.
- **ALIE statistics oracle:** the adversary is allowed to see the exact pre-privacy honest gradient statistics. This is deliberately **stronger** than the information ordinarily visible in a CKKS-encrypted setting; it is an upper-bound-style stress baseline, not a claim about server access to plaintext.

No tested experiment currently models a formally adaptive attacker with deployed cryptographic zero-knowledge proofs, client collusion with a key authority, a verified per-user privacy budget under subsampling, or real-world training devices.

### Robust aggregation limitations

- Mean and componentwise median/trimmed mean do not output per-client attack labels.
- Multi-Krum chooses k client updates based on pairwise update distances with assumptions n >= 2f + 3, 1 <= k <= n-f-2.
- The **selected malicious fraction** in the RQ2 extension uses *ground truth simulator attacker IDs* divided by k, averaged over all rounds. It is a measured *malicious admission frequency*, **not** classification precision/recall, a proof of Byzantine detection, or attribution of every accuracy loss to a selected update.
- Data heterogeneity, DP dispersion, dimensionality, attack intensity and attacker fraction may invalidate a transfer of results beyond the tested settings. All empirical findings require independent replication and appropriate uncertainty bounds.

### Encrypted aggregation limits

The native SEAL/CKKS path performs encrypted weighted addition and later decryption by a separate key-holder. It does **not** securely compute Krum, Multi-Krum, median or trimming over ciphertext. A cryptographic ciphertext confidentiality claim requires review of key generation, parameter security, decryption location, collusion and membership assumptions.

The optional server-side expected-weight registry check rejects obvious inconsistent *metadata*. It is **not** a zero-knowledge range proof, proof-of-knowledge of plaintext, bound-enforcement proof, authenticity guarantee for an untrusted client, or cryptographic binding of the claimed weight to the encrypted vector. Byzantine clients that possess valid credentials can still encrypt poisoned updates.

No paper should claim confidential and Byzantine-robust aggregation jointly until the secure filtering/validation protocol has been implemented, formalized, benchmarked and attacked.

## Claim-evidence audit matrix

| Candidate claim | Evidence source | Current scientific status |
| --- | --- | --- |
| Basic Gaussian accountant matches reference epsilon values | reproduce.py + test_reproduce.py | Arithmetic validated for stated assumptions |
| Vanilla robust aggregators outperform mean in some attacks | Independent 720-run grid | Studied, not novel on its own; manuscript source mismatch remains |
| Byzantine DP/clipping noncompliance increases degradation in studied conditions | Stress and paired inference CSVs | Supported within the small simulated dataset/seed grid; external validity unresolved |
| DP noise affects Multi-Krum malicious-admission frequency | selection_experiment.py + selection_inference.py | Instrumented and locally evaluated; oracle labels and two small datasets only |
| Heterogeneity changes robustness | Dirichlet extensions | Preliminary, broader heterogeneity/attack regimes required |
| Secure encrypted Byzantine filtering with CKKS | Not implemented | **Unsupported: do not claim** |
| A production formal local DP guarantee | Deterministic research simulator | **Unsupported: do not claim** |
| Novel security theorem, new algorithm or first-ever combined architecture | None yet | **Unsupported: do not claim** |
| Sampled real network intrusion benchmark | UNSW-NB15 official train/test split, 80 real runs/5 seeds | Exploratory evaluation completed; no state-of-the-art superiority, generalization, or novel algorithm demonstrated |

## Manuscript submission gate

1. Audit the original claimed 720 outcomes against immutable original raw files, datasets, exact seeds/code commit and artifact DOI. This reimplementation must never silently substitute for them.
2. Develop a distinguishable, original cybersecurity finding/theorem/algorithm against state-of-the-art privacy-compatible Byzantine defenses; state the *precise* conditions under which it differs.
3. Test independent realistic network-intrusion datasets with group/site isolation, macro-F1, attack success, class distribution, overhead and meaningful uncertainty.
4. Test adaptive/targeted attack classes, malicious fractions, non-IID alpha values, privacy budgets and aggregation alternatives; choose primary contrasts **before** looking at significance.
5. For CKKS, provide correct key-management and threat model, inspect ciphertext weighting/authentication, use genuine native measurements, quantify communication/latency, and do not equate encrypted averaging with a robust MPC protocol.
6. Keep all CI/security checks green and release a reproducible artifact with original data rights, source hashes and independent instructions.

**Status:** research instrumented; *not submission-ready* and no journal acceptance/novelty guarantee.
