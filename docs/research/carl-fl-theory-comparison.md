# Scientific contribution protocol: CARL-FL

**Status:** research specification and proposed conditional guarantees. This document is not a claim of a newly invented cryptographic primitive or independent proof that the actual implementation has no vulnerabilities.

## Core research question

How can a zero-trust federated learning coordinator prevent an authenticated but no-longer-authorized client from changing model state across concurrent revocation, request replay, crash, and ambiguous persistent rollback?

### Candidate contribution: CARL-FL

**CARL-FL = Commit-Aware Replay and Lifecycle Gating for Federated Learning**. It is a coordinated authorization rule with one mutation serialization point, an authoritative versioned persistent state, and an explicit fail-stop branch for uncertain rollback. The contribution claimed is the FL *commit-boundary coupling and its conditional safety characterization*, not novelty in certificates, JWT, nonces, serializability, or write-ahead durability.

Let coordinator state S=(E,G,N,R,V,U,D,F). E is enrollment/lease, G generation, N consumed nonce records, R/V model round/version, U pending updates, D last known durable snapshot, F fail-stop fence. A state-changing command q refers to identity i, observed model version and round, timestamp and nonce.

Admission predicate:
A(q,S) = TLSBind(i) AND TokenBind(i) AND RBAC(i,q) AND LeaseValid(i,E) AND GenerationValid(i,G) AND TimeFresh(q) AND NonceUnused(q,N) AND (if update: RoundVersionMatch(q,R,V)).

**CARL-FL transition algorithm**

1. Serialize the model-changing operation with enrollment, rotation, revocation and recovery-state mutations. Reject if the coordinator is fenced.
2. Verify the authenticated identity, signed claims, method policy, current lease/generation, timestamp, nonce and FL round/version against the same in-memory state. A negative decision makes no acknowledged mutation.
3. Stage the pending update or revocation and its nonce consumption in a transition candidate S'.
4. Construct the durable snapshot of pending updates, accepted nonces, current credentials, revocations and model round/version.
5. Attempt the durable commit of S'. Only after the commit is confirmed may the operation return success.
6. If the commit fails, restore S and confirm its durable restoration. Do not report success.
7. If restoration cannot be confirmed, enter F=1, reject *every* externally visible RPC, and permit service to resume only after authoritative recovery.

The published pseudo-algorithm should reflect these operations and limitations, rather than describe Go source code or repository tests.

**Safety statement S1 (conditional commit authorization):** If (i) signed identities are unforgeable, (ii) the coordinator is trusted, (iii) mutations use a single linearizable serialization order and never bypass the admission predicate, and (iv) success is acknowledged only after the durable transition is confirmed, then each acknowledged update was authorized at its transition linearization point. This is a proof about the abstract transition rules, not a fully verified software guarantee.

**Proof sketch:** Induct on the sequence of acknowledged transitions. Initially there is no acknowledged unauthorized model mutation. A nonmutation does not modify the model. For a model mutation, the serialization point evaluates A(q,S) against the current state. Only A=true can stage an update; only a confirmed durable commit can acknowledge it. A revocation that precedes the mutation at the same serialization point has changed E or G; subsequent requests from that generation fail A. The invariant is preserved.

**Safety statement S2 (uncertain rollback containment):** Under the same assumptions, if the coordinator cannot determine the authoritative durable post-state after a failed transition, F=1 prevents any *subsequent acknowledged* command until recovery. This does not assert that the failed revocation took effect or that already-acknowledged earlier commands are undone.

**Liveness tradeoff:** If a training round requires q distinct eligible submissions and the number m of available eligible workers is less than q, no legal algorithm using the unchanged quorum rule can complete that round without restored eligibility or additional participants. The security rule intentionally does not admit a revoked client just to satisfy the quorum.

**Cost:** Indexed identity/nonce/round checks have average O(1) lookup, subject to validation and attacker-controlled cache growth. Building a full persistent snapshot costs at least O(|E|+|N|+|U|+d) where d is the pending/model vector size, in addition to storage synchronization. This cost can exceed token verification in small FL round workloads. The time complexity claim is for this snapshot design, not for an optimized journal.

## Independent published-method comparison (not a head-to-head experiment)

| Source | Published algorithmic focus, supported by source | Question this study adds | Head-to-head implementation reproduced? |
| --- | --- | --- | --- |
| Zhang et al., IEEE TMC 2025, DOI 10.1109/TMC.2025.3591632 | Dirichlet trust estimation; dynamic participant selection; min-max betrayal-loss optimization | Is the model-state commit transaction replay/lease/revocation consistent? | No |
| Sun et al., IEEE JSAC 2025, DOI 10.1109/JSAC.2025.3560041 | OptCSS trust-based client selection; generator training; data-free FL knowledge transfer | Is per-operation authorization replay-safe and durable at commit? | No |
| Lv et al., Computer Networks 2025, DOI 10.1016/j.comnet.2025.111459 | Asynchronous FL and zero-trust coordination in industrial control contexts | Can durable revocation be linearized with round updates? | No |
| Chamkoori and Ghasemi, J. Comput. Networks Commun. 2026, DOI 10.1155/jcnc/8893656 | Continuous identity/device/trust evaluation, secure aggregation and adaptive feedback in threat-intelligence FL | Is an acknowledged update coupled to recoverable authority and nonce state? | No |
| Chang and Xu, IEEE Access 2026, DOI 10.1109/ACCESS.2026.3669103 | Session lifecycle and network ACL authorization/revocation latency | Does FL-specific model version/round move atomically with revocation/replay state? | No |
| This study | Per-update commit-time predicate, durable acknowledgement and ambiguous-rollback fencing | Same FL transaction boundary | Implemented coordinator experiments, not a published-method reimplementation |

'Not reported' in a paper is different from absence of a property in every implementation; inspect complete primary manuscripts before making any novelty claim of priority. Since the compared methods target different objectives and datasets, **do not compare their accuracy or latency numbers against ours numerically**.

## Evidence tiers

- The controlled B1/B2/P in-process policy ablations isolate security-mechanism effects and use intentionally weakened comparators. They are not independently implemented state-of-the-art systems.
- The new real TLS/gRPC integration evaluation uses the **full production coordinator** and a secure transport, not a synthetic interceptor alone. It demonstrates exactly the adversarial traces tested, not general 95% attack resistance.
- The 12-seed non-IID availability simulation measures training progress independently; it does not implement the actual network and coordinator.
- A bounded state-machine check is a finite specification check. Additional distributed formal verification (TLA+/Ivy/Alloy or equivalent) and replication of published algorithms remain separate research work.

## Submission gating

Do not call the paper a verified state-of-the-art win without independent implementations, shared datasets, attacker workloads and paired repeated measurements. Authors must verify the novelty scope, accurate author contributions, original raw measurements, declarations, and submission requirements.
