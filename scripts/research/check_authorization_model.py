"""Bounded, executable abstract model of FL authorization/durable-state safety.

This script explores a finite-state SPECIFICATION, not the Go implementation.
Passing it must never be presented as proof that the actual coordinator is safe.
The unsafe mutant tests whether the checker can detect a missing durable commit.
"""
from __future__ import annotations

import argparse
import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path

WORKERS = 2
NONCES_PER_WORKER = 2
MAX_UPDATES = 3
MAX_STEPS = 9


@dataclass(frozen=True)
class State:
    mem_version: int = 0
    disk_version: int = 0
    mem_revoked: int = 0
    disk_revoked: int = 0
    mem_nonces: int = 0
    disk_nonces: int = 0
    acked_revoke: int = 0
    acked_updates: int = 0
    fenced: bool = False
    fault_used: bool = False
    replay_violation: bool = False
    post_revoke_violation: bool = False


def invalid(state: State) -> str | None:
    if state.acked_updates != state.disk_version:
        return "acknowledged model state differs from durable model version"
    if state.acked_revoke & ~state.disk_revoked:
        return "acknowledged revocation absent from durable state"
    if not state.fenced and (
        state.mem_version != state.disk_version
        or state.mem_revoked != state.disk_revoked
        or state.mem_nonces != state.disk_nonces
    ):
        return "unfenced volatile and durable security state disagree"
    if state.replay_violation:
        return "same nonce committed more than once"
    if state.post_revoke_violation:
        return "model update committed after acknowledged revocation"
    return None


def transitions(state: State, unsafe: bool = False) -> list[tuple[str, State]]:
    s = state
    result: list[tuple[str, State]] = []
    if s.fenced:
        # A successful operator-controlled recovery reopens only the state
        # that is actually durable, never the speculative in-memory state.
        result.append((
            "verified_recovery",
            State(
                mem_version=s.disk_version,
                disk_version=s.disk_version,
                mem_revoked=s.disk_revoked,
                disk_revoked=s.disk_revoked,
                mem_nonces=s.disk_nonces,
                disk_nonces=s.disk_nonces,
                acked_revoke=s.acked_revoke,
                acked_updates=s.acked_updates,
                fenced=False,
                fault_used=s.fault_used,
            ),
        ))
        return result

    for worker in range(WORKERS):
        worker_bit = 1 << worker
        if not (s.mem_revoked & worker_bit):
            result.append((
                f"revoke_worker_{worker}",
                State(
                    mem_version=s.mem_version,
                    disk_version=s.disk_version,
                    mem_revoked=s.mem_revoked | worker_bit,
                    disk_revoked=s.disk_revoked | worker_bit,
                    mem_nonces=s.mem_nonces,
                    disk_nonces=s.disk_nonces,
                    acked_revoke=s.acked_revoke | worker_bit,
                    acked_updates=s.acked_updates,
                    fault_used=s.fault_used,
                ),
            ))
            if not s.fault_used:
                # Ambiguous failed disk write + failed durable rollback.
                # Model both possible surviving disk states and FENCE.
                for changed in (False, True):
                    result.append((
                        f"uncertain_revoke_failure_worker_{worker}_diskchanged_{changed}",
                        State(
                            mem_version=s.mem_version,
                            disk_version=s.disk_version,
                            mem_revoked=s.mem_revoked,
                            disk_revoked=s.disk_revoked | (worker_bit if changed else 0),
                            mem_nonces=s.mem_nonces,
                            disk_nonces=s.disk_nonces,
                            acked_revoke=s.acked_revoke,
                            acked_updates=s.acked_updates,
                            fenced=True,
                            fault_used=True,
                        ),
                    ))
        for nonce_no in range(NONCES_PER_WORKER):
            nonce_bit = 1 << (worker * NONCES_PER_WORKER + nonce_no)
            if s.mem_version >= MAX_UPDATES:
                continue
            if s.mem_revoked & worker_bit:
                continue
            if s.mem_nonces & nonce_bit:
                if unsafe:
                    # The intentionally unsafe mutant illustrates a replay bug.
                    result.append((
                        f"UNSAFE_reuse_nonce_{worker}_{nonce_no}",
                        State(
                            mem_version=s.mem_version + 1,
                            disk_version=s.disk_version + 1,
                            mem_revoked=s.mem_revoked,
                            disk_revoked=s.disk_revoked,
                            mem_nonces=s.mem_nonces,
                            disk_nonces=s.disk_nonces,
                            acked_revoke=s.acked_revoke,
                            acked_updates=s.acked_updates + 1,
                            replay_violation=True,
                        ),
                    ))
                continue
            result.append((
                f"commit_update_worker_{worker}_nonce_{nonce_no}",
                State(
                    mem_version=s.mem_version + 1,
                    disk_version=s.disk_version + 1,
                    mem_revoked=s.mem_revoked,
                    disk_revoked=s.disk_revoked,
                    mem_nonces=s.mem_nonces | nonce_bit,
                    disk_nonces=s.disk_nonces | nonce_bit,
                    acked_revoke=s.acked_revoke,
                    acked_updates=s.acked_updates + 1,
                    fault_used=s.fault_used,
                ),
            ))
    result.append(("restart_from_durable", State(
        mem_version=s.disk_version,
        disk_version=s.disk_version,
        mem_revoked=s.disk_revoked,
        disk_revoked=s.disk_revoked,
        mem_nonces=s.disk_nonces,
        disk_nonces=s.disk_nonces,
        acked_revoke=s.acked_revoke,
        acked_updates=s.acked_updates,
        fault_used=s.fault_used,
    )))
    return result


def explore(*, unsafe: bool = False) -> dict[str, object]:
    initial = State()
    queue = deque([(initial, ())])
    seen = {initial}
    transitions_checked = 0
    maximum_depth = 0
    while queue:
        state, trace = queue.popleft()
        maximum_depth = max(maximum_depth, len(trace))
        problem = invalid(state)
        if problem is not None:
            return {
                "ok": False, "reason": problem,
                "states_checked": len(seen),
                "transitions_checked": transitions_checked,
                "counterexample": list(trace),
            }
        if len(trace) >= MAX_STEPS:
            continue
        for label, next_state in transitions(state, unsafe=unsafe):
            transitions_checked += 1
            if next_state not in seen:
                seen.add(next_state)
                queue.append((next_state, (*trace, label)))
    return {
        "ok": True, "states_checked": len(seen),
        "transitions_checked": transitions_checked,
        "max_depth": maximum_depth,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    correct = explore()
    mutant = explore(unsafe=True)
    report = {
        "kind": "bounded_abstract_specification",
        "not_an_implementation_proof": True,
        "bounds": {
            "workers": WORKERS,
            "nonces_per_worker": NONCES_PER_WORKER,
            "max_model_commits": MAX_UPDATES,
            "max_trace_length": MAX_STEPS,
            "ambiguous_persistence_failure": "at most once",
        },
        "correct_specification": correct,
        "unsafe_nonce_mutant": mutant,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    if not correct["ok"] or mutant["ok"]:
        raise SystemExit("abstract checker failed or unsafe mutant was not detected")


if __name__ == "__main__":
    main()
