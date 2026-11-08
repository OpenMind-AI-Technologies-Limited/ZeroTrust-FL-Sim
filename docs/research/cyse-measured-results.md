# Cybersecurity zero-trust FL: measured research results (November 2026)

**Study:** Recovery-Consistent Policy Gating for Federated Learning: Commit-Time Authorization, Replay Safety, and Failure Fencing  
**Original desk-rejected manuscript:** CYSE-D-26-01599. This document summarizes *new evidence*; it is not a claim of acceptance or full paper readiness.  
**Code merged from PR #120:** [e7c3e351](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/commit/e7c3e3515d93519dc365862e5b2a4392d5072f05)  
**Actual evidence run source commit:** `544e3de9ef7d120e2e412d5916a896b76071fdcf` (PR before squash).  
**CI:** [#42532410754](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42532410754) — passed all four jobs.  
**Security:** [#42532410760](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42532410760) — passed source/dependency, three container scan, and fuzzing jobs.  
**Research evidence:** [#42532410756](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42532410756) — passed; downloadable workflow artifact `ztfl-security-evidence-e94f3c8df5abb31c446e4aa30a1f9c8a018e1c1f`.  
**Release evidence:** [#42532410748](https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42532410748) — passed.

## RQ1: matched policy-decision ablations

Recorded `ZTFL_AUTHZ_ABLATION` events from `authorization-ablation-events.jsonl`, 6 cases per profile. **A=accept; D=deny**. B1 and B2 are test-built variants, not third-party production competitors.

| Case | B1 JWT/role | B2 + active enrollment | P + freshness/replay |
|---|---|---|---|
| Legitimate | A | A | A |
| Unenrolled | A | D | D |
| Revoked | A | D | D |
| Wrong role | D | D | D |
| Replayed nonce | A | A | D |
| Stale timestamp | A | A | D |

## RQ1/RQ3: actual round-model mutations

Recorded `ZTFL_MODEL_BASELINE` events from `model-mutation-baselines.jsonl`; the B1/B2 adapter executes matched quorum-1 vector-round transitions and the P condition invokes the production durable coordinator. **C=committed; D=denied**.

| Case | B1 | B2 | P durable |
|---|---|---|---|
| Legitimate | C | C | C |
| Unenrolled | C | D | D |
| Revoked | C | D | D |
| Observer role | D | D | D |
| First use of nonce | C | C | C |
| Same nonce in successor round | C | C | D |

There are 18 recorded model-mutation outcomes and 18 decision-only outcomes. These are deterministic mechanism-ablation checks, **not** independent published-system benchmarks or vulnerability prevalence estimates.

## RQ2: bounded formal specification and recovery fencing

`scripts/research/check_authorization_model.py` reports **285 states and 695 transitions**, depth <=9, no specified invariant violation inside bounds (2 workers, 2 nonce options each, 3 model commits, <=1 ambiguous storage failure). A deliberately unsafe replay mutant yields a two-step counterexample after 73 states. It is an *abstract specification checker* rather than a formal verification of the Go implementation. Separate Go regression tests exercise commit, rollback, fail-stop fencing and revocation/update races, without establishing universal replicated-system linearizability.

## RQ4: measured in-process overhead

Recorded in `round-transition-microbenchmark.txt`, five repeated 25-operation trials on the same Intel Xeon CI runner:

| Condition | Five ns/op observations | Median |
|---|---|---|
| Authenticated in-memory model-state transition | 83389, 83082, 81481, 81512, 96445 | **83.082 microseconds** |
| Authenticated file-durable model-state transition | 567008, 565331, 556815, 586266, 605802 | **567.008 microseconds** |

The median ratio is **6.825×**, measuring a local file-durable snapshot and audit transition, not full network TLS, larger models, distributed persistence, or FL training. The paired token/role interceptor benchmark medians were 70.006 and 70.244 microseconds with and without an active-registration rule; differences are descriptive only.

## RQ5: coordinator availability observation

One fixed-quorum 3-of-3 test recorded rejection of a revoked worker; the round remained incomplete with only two lawful updates and advanced after a newly authorized replacement submitted. These are real Go coordinator state transitions, **not non-IID learning convergence measurements**.

## Additional independent smoke benchmarks, NOT directly attributable to policy gating

The release and Docker integration workflows also produced raw `network.csv` 4-KiB/100-request plaintext and mTLS *echo* comparisons and synthetic malicious-client/non-IID aggregation simulations. They are useful *platform diagnostics*, not causal evidence about the full policy-gated FL security layer. Never mix them into RQ4/RQ5 as if they were measurements of policy-gated update latency or learning impact.

## Open scientific limitations before claiming stronger novelty

- Compare independently implemented stateful zero-trust FL baselines.
- Execute full gRPC/mTLS application-path latencies (p50/p95/p99), throughput, memory/CPU and 10–100+ worker scale under matched hardware and load.
- Evaluate FL **learning accuracy, convergence and round availability under revocation/churn** with fixed real non-IID datasets and repeated seeds.
- Extend model checking to implementation-level state-machine/linearizability testing and multi-coordinator semantics, including loss of storage, clock drift and independent control plane failures.
- Archive the exact raw results at a permanent DOI, independently verify every reference, confirm institutional metadata and ask the journal whether a substantially rewritten manuscript can be treated as a new submission after rejection.

**Research integrity:** Do not claim 100% security, unrestricted invariant proof, journal acceptance, or results from experiments absent from the logged artifacts.
