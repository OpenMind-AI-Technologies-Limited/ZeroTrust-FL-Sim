"""Evaluate a provided real cybersecurity CSV under the FL privacy/attack matrix.

No network dataset is fetched, and no cybersecurity results are fabricated.
Statistical significance, class-imbalance metrics and novelty require further work.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
from pathlib import Path

from cyber_data import prepare_csv
from reproduce import (
    AGGREGATORS, FIELDS, PRIVACY_MODES, THREATS,
    Config, paired_results, run_case,
)


def run_csv_benchmark(
    *, csv_path: Path, label: str, group: str | None,
    exclude: tuple[str, ...], output: Path, seeds: tuple[int, ...],
    aggregators: tuple[str, ...], privacy_modes: tuple[str, ...],
    threats: tuple[str, ...], compliance: tuple[str, ...],
    rounds: int, partition: str, alpha: float,
) -> dict:
    if any(rule not in AGGREGATORS for rule in aggregators):
        raise ValueError("unsupported aggregator")
    if any(mode not in PRIVACY_MODES for mode in privacy_modes):
        raise ValueError("unsupported privacy mode")
    if any(threat not in THREATS or threat == "benign" for threat in threats):
        raise ValueError("unsupported attack threat")
    if any(c not in {"compliant", "bypass"} for c in compliance):
        raise ValueError("unsupported attacker compliance")
    if not all((seeds, aggregators, privacy_modes, threats, compliance)):
        raise ValueError("experiment selections cannot be empty")
    if rounds < 1:
        raise ValueError("rounds must be positive")
    output.mkdir(parents=True, exist_ok=True)
    runs = []
    split_metadata = []
    seen_clean_keys = set()
    for seed in seeds:
        prepared = prepare_csv(
            csv_path, label_column=label, group_column=group,
            exclude_columns=exclude, seed=seed
        )
        split_metadata.append(prepared.metadata)
        for aggregator, privacy, threat, policy in itertools.product(
            aggregators, privacy_modes, threats, compliance
        ):
            config = Config(
                rounds=rounds, partition=partition, alpha=alpha,
                attacker_compliance=policy
            )
            dataset_name = "cyber_csv:" + csv_path.stem
            benign = run_case(
                dataset_name, seed, aggregator, privacy, "benign",
                config, external_task=prepared.data
            )
            attacked = run_case(
                dataset_name, seed, aggregator, privacy, threat,
                config, external_task=prepared.data
            )
            clean_key = (
                seed, aggregator, privacy, policy, config.partition, config.alpha
            )
            if clean_key not in seen_clean_keys:
                runs.append(benign)
                seen_clean_keys.add(clean_key)
            runs.append(attacked)

    with (output / "cyber_runs.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(runs)
    pairs = paired_results(runs)
    with (output / "cyber_pairs.csv").open("w", newline="", encoding="utf-8") as f:
        columns = list(pairs[0]) if pairs else []
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(pairs)

    manifest = {
        "study": "CYSE-01608 real cybersecurity CSV extension",
        "status": "exploratory; not the original 720-run submitted experiment",
        "dataset_file_name": csv_path.name,
        "dataset_sha256": split_metadata[0]["dataset_sha256"],
        "split_manifests": split_metadata,
        "runs": len(runs), "paired_attacks": len(pairs),
        "rounds_per_run": rounds, "seeds": seeds,
        "aggregators": aggregators, "privacy_modes": privacy_modes,
        "threats": threats, "attacker_compliance": compliance,
        "partition": partition, "alpha": alpha,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "warning": (
            "No dataset-specific leakage audit, class-imbalance metrics, "
            "state-of-art baselines or cryptographic security proofs yet. "
            "Deterministically seeded noise is not production differential privacy."
        ),
    }
    (output / "cyber_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--label", required=True)
    parser.add_argument("--group", default=None)
    parser.add_argument("--exclude", nargs="*", default=[])
    parser.add_argument("--output", type=Path, default=Path("artifacts/cyse_01608_cyber"))
    parser.add_argument("--seeds", nargs="+", type=int, default=list(range(5)))
    parser.add_argument("--aggregators", nargs="+", choices=AGGREGATORS, default=["mean", "median", "multi_krum"])
    parser.add_argument("--privacy-modes", nargs="+", choices=PRIVACY_MODES, default=["clip_only", "dp_1"])
    parser.add_argument("--threats", nargs="+", choices=("sign_flip", "label_flip"), default=["sign_flip"])
    parser.add_argument("--attacker-compliance", nargs="+", choices=("compliant", "bypass"), default=["compliant", "bypass"])
    parser.add_argument("--partition", choices=("iid", "dirichlet"), default="dirichlet")
    parser.add_argument("--alpha", type=float, default=0.3)
    parser.add_argument("--rounds", type=int, default=20)
    args = parser.parse_args()
    manifest = run_csv_benchmark(
        csv_path=args.csv, label=args.label, group=args.group,
        exclude=tuple(args.exclude), output=args.output, seeds=tuple(args.seeds),
        aggregators=tuple(args.aggregators), privacy_modes=tuple(args.privacy_modes),
        threats=tuple(args.threats), compliance=tuple(args.attacker_compliance),
        rounds=args.rounds, partition=args.partition, alpha=args.alpha
    )
    print(json.dumps({
        "dataset_sha256": manifest["dataset_sha256"],
        "runs": manifest["runs"], "pairs": manifest["paired_attacks"]
    }, indent=2))


if __name__ == "__main__":
    main()
