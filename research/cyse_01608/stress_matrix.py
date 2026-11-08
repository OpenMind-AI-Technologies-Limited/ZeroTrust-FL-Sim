"""Exploratory privacy/Byzantine/non-IID sensitivity study.

Operational failure thresholds are user-defined accuracy-loss endpoints, NOT
cryptographic security theorems. Use results only with the exact manifest.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
from collections import defaultdict
from pathlib import Path

import numpy as np

from reproduce import AGGREGATORS, DATASETS, PRIVACY_MODES, Config, run_case

COLUMNS = (
    "dataset", "seed", "partition", "alpha", "malicious_clients",
    "attacker_compliance", "aggregator", "privacy_mode", "threat",
    "benign_accuracy", "attacked_accuracy", "accuracy_drop_pp",
    "operational_failure", "failure_threshold_pp",
)
SUMMARY_COLUMNS = (
    "partition", "alpha", "malicious_clients", "attacker_compliance",
    "aggregator", "privacy_mode", "threat", "observations",
    "mean_accuracy_drop_pp", "median_accuracy_drop_pp",
    "operational_failure_fraction",
)


def _write(path: Path, rows: list[dict], columns: tuple[str, ...]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def sweep(
    *, output: Path, datasets: tuple[str, ...], seeds: tuple[int, ...],
    partitions: tuple[str, ...], alphas: tuple[float, ...],
    malicious_counts: tuple[int, ...], aggregators: tuple[str, ...],
    modes: tuple[str, ...], threats: tuple[str, ...],
    compliance: tuple[str, ...], rounds: int,
    failure_threshold_pp: float = 20.0,
) -> dict:
    if failure_threshold_pp <= 0 or not np.isfinite(failure_threshold_pp):
        raise ValueError("failure threshold must be finite and positive")
    if not all((datasets, seeds, partitions, malicious_counts, aggregators, modes, threats, compliance)):
        raise ValueError("experiment selections must be nonempty")
    if any(x not in DATASETS for x in datasets):
        raise ValueError("unknown dataset")
    if any(x not in AGGREGATORS for x in aggregators):
        raise ValueError("unknown aggregator")
    if any(x not in PRIVACY_MODES for x in modes):
        raise ValueError("unknown privacy mode")
    if any(x not in {"sign_flip", "label_flip"} for x in threats):
        raise ValueError("unknown attack")
    if any(x not in {"compliant", "bypass"} for x in compliance):
        raise ValueError("unknown attacker compliance policy")
    if any(x not in {"iid", "dirichlet"} for x in partitions):
        raise ValueError("unknown partition")
    if any(x <= 0 for x in alphas):
        raise ValueError("alpha must be positive")
    if rounds < 1:
        raise ValueError("rounds must be positive")

    choices = [(p, a) for p in partitions for a in ((0.3,) if p == "iid" else alphas)]
    if not choices:
        raise ValueError("at least one partition/alpha combination required")
    output.mkdir(parents=True, exist_ok=True)
    pairs = []
    executions = 0

    for dataset, seed, (partition, alpha), f, rule, mode, attack, conform in itertools.product(
        datasets, seeds, choices, malicious_counts, aggregators, modes, threats, compliance
    ):
        config = Config(
            partition=partition, alpha=alpha, malicious_clients=f,
            attacker_compliance=conform, rounds=rounds,
            multi_krum_k=min(5, 15 - f - 2), trim_each_tail=3,
        )
        clean = run_case(dataset, seed, rule, mode, "benign", config)
        attacked = run_case(dataset, seed, rule, mode, attack, config)
        executions += 2
        drop_pp = 100.0 * (clean["final_accuracy"] - attacked["final_accuracy"])
        pairs.append(
            dict(
                dataset=dataset, seed=seed, partition=partition,
                alpha=alpha if partition == "dirichlet" else "",
                malicious_clients=f, attacker_compliance=conform,
                aggregator=rule, privacy_mode=mode, threat=attack,
                benign_accuracy=clean["final_accuracy"],
                attacked_accuracy=attacked["final_accuracy"],
                accuracy_drop_pp=drop_pp,
                operational_failure=int(drop_pp >= failure_threshold_pp),
                failure_threshold_pp=failure_threshold_pp,
            )
        )

    _write(output / "stress_pairs.csv", pairs, COLUMNS)
    by_condition = defaultdict(list)
    for record in pairs:
        key = tuple(record[k] for k in SUMMARY_COLUMNS[:7])
        by_condition[key].append(record)
    summary = []
    for key, records in sorted(by_condition.items()):
        losses = np.asarray([item["accuracy_drop_pp"] for item in records])
        summary.append(
            dict(zip(SUMMARY_COLUMNS[:7], key))
            | {
                "observations": len(records),
                "mean_accuracy_drop_pp": float(np.mean(losses)),
                "median_accuracy_drop_pp": float(np.median(losses)),
                "operational_failure_fraction": float(
                    np.mean([item["operational_failure"] for item in records])
                ),
            }
        )
    _write(output / "stress_summary.csv", summary, SUMMARY_COLUMNS)
    manifest = {
        "kind": "exploratory Byzantine-privacy-nonIID sensitivity",
        "status": "independent reimplementation; not original manuscript results",
        "scenarios": len(pairs),
        "executed_runs": executions,
        "total_rounds": executions * rounds,
        "datasets": datasets,
        "seeds": seeds,
        "partitions": partitions,
        "alphas": alphas,
        "malicious_clients": malicious_counts,
        "aggregators": aggregators,
        "privacy_modes": modes,
        "threats": threats,
        "attacker_compliance": compliance,
        "failure_threshold_pp": failure_threshold_pp,
        "note": "threshold measures accuracy loss; it is not a security proof",
        "privacy_warning": "seeded DP demonstrations are not operational DP",
        "stress_pairs_sha256": hashlib.sha256(
            (output / "stress_pairs.csv").read_bytes()
        ).hexdigest(),
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (output / "stress_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("artifacts/cyse_01608_stress"))
    parser.add_argument("--datasets", nargs="+", choices=DATASETS, default=list(DATASETS))
    parser.add_argument("--seeds", type=int, nargs="+", default=list(range(5)))
    parser.add_argument("--partitions", nargs="+", choices=("iid", "dirichlet"), default=["iid", "dirichlet"])
    parser.add_argument("--alphas", type=float, nargs="+", default=[0.3, 1.0])
    parser.add_argument("--malicious-clients", type=int, nargs="+", default=[1, 3, 6])
    parser.add_argument("--aggregators", nargs="+", choices=AGGREGATORS, default=["mean", "median", "multi_krum"])
    parser.add_argument("--privacy-modes", nargs="+", choices=PRIVACY_MODES, default=["clip_only", "dp_1"])
    parser.add_argument("--threats", nargs="+", choices=("sign_flip", "label_flip"), default=["sign_flip"])
    parser.add_argument("--attacker-compliance", nargs="+", choices=("compliant", "bypass"), default=["compliant", "bypass"])
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--failure-threshold-pp", type=float, default=20.0)
    args = parser.parse_args()
    manifest = sweep(
        output=args.output, datasets=tuple(args.datasets),
        seeds=tuple(args.seeds), partitions=tuple(args.partitions),
        alphas=tuple(args.alphas), malicious_counts=tuple(args.malicious_clients),
        aggregators=tuple(args.aggregators), modes=tuple(args.privacy_modes),
        threats=tuple(args.threats), compliance=tuple(args.attacker_compliance),
        rounds=args.rounds, failure_threshold_pp=args.failure_threshold_pp,
    )
    print(json.dumps({
        "scenarios": manifest["scenarios"],
        "executed_runs": manifest["executed_runs"],
        "rounds": manifest["total_rounds"],
        "sha256": manifest["stress_pairs_sha256"],
    }, indent=2))


if __name__ == "__main__":
    main()
