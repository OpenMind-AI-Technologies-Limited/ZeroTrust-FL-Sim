# Zero-trust FL security study: reproducible evaluation protocol

**Target study:** Policy-gated zero-trust authorization in federated coordination.  
**Primary subject:** access-control and coordinator-state integrity; **not** a new non-IID aggregation algorithm.  
**Status:** pre-registered experimental plan. No new measurements or security claims are implied by this document.

## Scientific problem

Authentication and role checking do not, alone, guarantee that the worker remains authorized at the instant a federated model update commits. The coordinator must preserve identity binding, lease and credential generation, replay state, round/version constraints, and recovery behavior across state-changing requests.

The novelty hypothesis is *transaction-coupled authorization and durable replay/revocation state for FL round transitions*. This is not a claim that zero-trust FL or stateful security primitives are new. Prior-art review is required before using any novelty claim in a manuscript.

## Research questions

- **RQ1 — Security effectiveness:** Compared with mTLS + token/RBAC with equivalent identity assumptions, how does stateful policy gating affect unauthorized model-state commits and false denial of legitimate requests?
- **RQ2 — Recovery:** Under injected crash and persistence faults, how often are credential generations, revoked leases, and consumed nonces reconstructed incorrectly?
- **RQ3 — Concurrency:** Can a revoked, rotated, or replaying worker commit an update after the relevant security transition has been durably acknowledged?
- **RQ4 — Overhead:** What is the incremental p50/p95/p99 request latency, CPU cost, memory, and accepted request throughput over matched baselines?
- **RQ5 — FL impact:** What are round-completion, availability and training outcomes under worker churn, non-IID data, and revocation, holding all learning parameters fixed?

## Mechanisms and threat assumptions

- Secure transport uses mutual TLS 1.3; valid identity certificates and signed claims do not imply honest model content.
- The coordinator and credential issuer belong to the trusted computing base.
- The attacker may delay, replay, reorder, substitute, duplicate and race otherwise valid requests; compromised valid clients may submit malicious updates.
- TLS and signature primitive breaks, a fully compromised coordinator, and stolen *all-factor* identity evidence are outside the strongest claims.
- The atomicity requirement applies to state accepted by a *durably acknowledged* coordinator operation. A failed persistence/rollback operation must be explicitly classified; do not call it proven fail-closed without evidence.
- Non-IID partitions are a controlled covariate for RQ5 only, not a separate primary research contribution.

## Required baseline conditions

1. **B0:** Transport-only identity check (negative security control, not the principal competing baseline).
2. **B1:** mTLS + signed token + equivalent method-specific role policies, no stateful lifecycle/replay controls.
3. **B2:** B1 + enrollment lease and credential generation, without durable replay/revocation recovery.
4. **P:** Full policy-gated stateful coordinator using the same transport, cryptographic algorithms, hardware, workloads, model and concurrency.

Implement each baseline as a documented, isolated configuration or variant, without intentionally inserting vulnerabilities beyond the specified removed control. Run all scenarios on the same commit and environments. The production policy must not be disabled as a hidden global switch.

## Test matrix

| ID | Scenario | Measured outcome | Related RQ |
| --- | --- | --- | --- |
| S01 | Missing/rogue certificate and invalid signed token | Reject/accept confusion count | RQ1 |
| S02 | Certificate/token mismatch, role mismatch, unenrolled update | Unauthorized state commits | RQ1 |
| S03 | Stale model version, stale round, duplicated request nonce | Rejection codes, model-version changes | RQ1/RQ3 |
| S04 | Concurrent update vs credential rotation | Unauthorized post-rotation commits | RQ3 |
| S05 | Concurrent update vs administrative revocation | Unauthorized post-revocation commits | RQ3 |
| S06 | Crash before/after state commit and during recovery | Invariant violations and recovery time | RQ2 |
| S07 | Persistence write/rename/fsync faults | Ack/durable-state contradictions | RQ2 |
| S08 | Concurrent clients and repeated authenticated requests | p50/p95/p99 latency, throughput, CPU, memory | RQ4 |
| S09 | Non-IID partition, worker churn and revocation | Round completion and model test metrics | RQ5 |
| S10 | Replay cache, generations, tombstones and durability ablations | Relative effects under matched load | RQ1–RQ5 |

All attack outcomes must report both the RPC status **and** post-condition state, including persistent state after restart. An expected exception is not itself proof of model integrity.

## Recording requirements

For every run, preserve: full Git SHA, source tree cleanliness, OS/kernel, Go/Python/compiler versions, CPU and memory, dependency versions, dataset checksum, synthetic seed(s), load generator, participant count, number of attempts, number of successful/denied mutations, latency distribution, database/store mode, network conditions, cryptographic configuration, complete commands, timestamps and warm-up definition.

Record events individually before aggregation. Publish raw CSV/JSON and an explicit command that reconstructs every figure. Use repeated independent runs for performance and FL measurements; report median, dispersion and confidence intervals. Do not convert deterministic 22/22 acceptance cases to a general security probability.

## Formal specification and fail-stop recovery

The safety objective is **commit-time authorization**, not permanent trust in the contents of model updates. A successful acknowledged transition must pair the selected worker/credential generation, current round/version, request nonce, and the durable update or revocation state. A failed disk commit with successful rollback returns an error and retains the old valid state. **If the rollback itself cannot be persisted, the durable service is fenced and all six RPC methods return Unavailable until independently validated recovery.** This is not a guarantee that a failed revocation was applied; a failed revocation with successful rollback leaves the old lease in force.

The abstract checker at `scripts/research/check_authorization_model.py` explores **two workers, two nonces each, up to three model commits, nine transitions and at most one ambiguous persistence fault**, including either result of that failed disk write. Its unsafe replay mutant must yield a counterexample. Passing the checker establishes properties of that bounded *specification*, not correspondence with Go code or correctness for arbitrary concurrency sizes. The accompanying Go race and fault-injection tests exercise selected implementation paths separately.

## Automated implementation evidence

The `research-security-evidence.yml` workflow records commit-pinned Go regression and race-test JSON for coordinator, security, and protocol cases. These artifacts are **software-validation evidence**, not a measured B0/B1/B2/P comparison. If the runner is unable to execute, report that limitation rather than claiming passing results.

## Outstanding gates before Cybersecurity submission

- Implement and run B1/B2/P with the same security scenarios, and publish raw records.
- Add controlled concurrent revoke/rotate/crash injection, including durable store failure at each commit boundary.
- Make the registration and heartbeat mutation-freshness policy explicit and compatible across Go/Python clients and test harnesses.
- Clarify whether a failed revocation leaves a previously authorized client active and what operational retry/quarantine guarantee applies.
- Replace the unavailable historical MinIO fixture with a verified, content-pinned trusted S3-compatible service for the full PostgreSQL/S3 recovery tests.
- Resolve all dependency/container vulnerability gates, including third-party health-probe binaries.
- Run RQ4/RQ5 performance/FL scenarios and report measured values. Do not substitute test pass counts or generic plaintext/mTLS echo timings.
- Reconcile README architecture claims with the checked-out coordinator's actual aggregation and model-round behavior.
- Independently verify closest prior art, reference accuracy and journal requirements.

**Manuscript rule:** Only describe experiments that were actually executed at a recorded commit. Keep source-code details in the artifact package; present scientific methods, problem formulation, uncertainty, results and threats to validity in the manuscript.
