"""Execute a real network-intrusion benchmark using a validated NSL-KDD split.

This is an external-validity extension, not the submitted 720-run dataset
nor a new privacy mechanism or independently validated defense.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
from pathlib import Path

from reproduce import Config, FIELDS, paired_results, run_case
from nsl_data import EXPECTED_GIT_BLOBS, prepare_nsl

MODES = ("none", "clip_only", "dp_1", "dp_2")
RULES = ("mean", "median", "multi_krum")
POLICIES = ("compliant", "bypass")
ATTACKS = ("sign_flip", "label_flip")

METRICS = ("macro_f1", "balanced_accuracy", "per_class_recall_json", "confusion_matrix_json")


def experiment(
    train_csv: Path,
    test_csv: Path,
    output: Path,
    *,
    seeds: tuple[int, ...] = (0, 1),
    aggregators: tuple[str, ...] = ("mean", "median", "multi_krum"),
    privacy_modes: tuple[str, ...] = ("clip_only", "dp_1"),
    policies: tuple[str, ...] = ("compliant", "bypass"),
    attacks: tuple[str, ...] = ("sign_flip",),
    rounds: int = 20,
    malicious_clients: int = 3,
    partition: str = "dirichlet",
    alpha: float = 0.3,
    train_limit: int | None = 12000,
    test_limit: int | None = 6000,
    check_blobs: bool = True,
    strict_official_count: bool = True,
) -> dict:
    if not seeds or not aggregators or not privacy_modes or not policies or not attacks:
        raise ValueError("all experimental factors must be nonempty")
    if set(aggregators) - set(RULES) or set(privacy_modes) - set(MODES):
        raise ValueError("invalid aggregator/privacy mode")
    if set(policies) - set(POLICIES) or set(attacks) - set(ATTACKS):
        raise ValueError("invalid attacker compliance or attack")
    output.mkdir(parents=True, exist_ok=True)
    runs: list[dict] = []
    split_manifests = []
    for seed in seeds:
        task, metadata = prepare_nsl(
            train_csv, test_csv, seed=seed, train_limit=train_limit, test_limit=test_limit,
            expected_train_blob=EXPECTED_GIT_BLOBS["train"] if check_blobs else None,
            expected_test_blob=EXPECTED_GIT_BLOBS["test"] if check_blobs else None,
            require_standard_counts=strict_official_count,
        )
        split_manifests.append(metadata)
        for rule, mode, policy in itertools.product(aggregators, privacy_modes, policies):
            cfg = Config(
                rounds=rounds, malicious_clients=malicious_clients,
                partition=partition, alpha=alpha, attacker_compliance=policy,
                multi_krum_k=min(5, 15-malicious_clients-2)
            )
            clean = run_case(
                "NSL-KDD", seed, rule, mode, "benign", cfg,
                external_task=task, include_classification_metrics=True
            )
            runs.append(clean)
            for attack in attacks:
                runs.append(run_case(
                    "NSL-KDD", seed, rule, mode, attack, cfg,
                    external_task=task, include_classification_metrics=True
                ))
    all_columns = FIELDS + METRICS
    with (output / "nsl_runs.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=all_columns)
        writer.writeheader()
        writer.writerows(runs)

    # Re-use the same dataset/seed/aggregator/privacy/compliance pairings
    # used by the original design. Balanced accuracy and macro-F1 expose
    # behaviour obscured by overall accuracy on imbalanced attack classes.
    paired = paired_results(runs)
    clean_index = {}
    attack_index = {}
    keys = ("dataset", "seed", "partition", "alpha", "aggregator", "privacy_mode", "attacker_compliance")
    for row in runs:
        key = tuple(row[k] for k in keys)
        if row["threat"] == "benign":
            clean_index[key] = row
        else:
            attack_index[key + (row["threat"],)] = row
    for row in paired:
        key = tuple(row[k] for k in keys)
        clean = clean_index[key]
        attacked = attack_index[key + (row["threat"],)]
        row["macro_f1_drop_pp"] = 100*(clean["macro_f1"] - attacked["macro_f1"])
        row["balanced_accuracy_drop_pp"] = 100*(
            clean["balanced_accuracy"] - attacked["balanced_accuracy"]
        )
    with (output / "nsl_paired.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = list(paired[0]) if paired else []
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(paired)

    manifest = {
        "kind": "exploratory external-validity NSL-KDD intrusion-detection FL extension",
        "not_original_manuscript_data": True,
        "is_official_split": True,
        "dataset_manifests": split_manifests,
        "seeds": seeds,
        "aggregators": aggregators,
        "privacy_modes": privacy_modes,
        "policies": policies,
        "attacks": attacks,
        "rounds_per_run": rounds,
        "federated_executions": len(runs),
        "federated_rounds": len(runs)*rounds,
        "partition": partition,
        "dirichlet_alpha": alpha,
        "malicious_clients": malicious_clients,
        "warning": [
            "The official test set is held out, but subsampling is possible and must be reported.",
            "Research seeds expose local Gaussian noise and do not meet operational local DP.",
            "No novel Byzantine filtering or CKKS robust aggregation is implemented here.",
            "No independent target/backdoor adversarial evaluation is demonstrated.",
        ],
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "runs_sha256": hashlib.sha256((output / "nsl_runs.csv").read_bytes()).hexdigest(),
    }
    (output / "nsl_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", type=Path, required=True)
    parser.add_argument("--test", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("artifacts/cyse_01608_nsl_nb15"))
    parser.add_argument("--seeds", nargs="+", type=int, default=[0, 1])
    parser.add_argument("--aggregators", nargs="+", choices=RULES, default=["mean", "median", "multi_krum"])
    parser.add_argument("--privacy-modes", nargs="+", choices=MODES, default=["clip_only", "dp_1"])
    parser.add_argument("--attacker-compliance", nargs="+", choices=POLICIES, default=["compliant", "bypass"])
    parser.add_argument("--attacks", nargs="+", choices=ATTACKS, default=["sign_flip"])
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--malicious-clients", type=int, default=3)
    parser.add_argument("--partition", choices=("iid", "dirichlet"), default="dirichlet")
    parser.add_argument("--alpha", type=float, default=.3)
    parser.add_argument("--train-limit", type=int, default=12000)
    parser.add_argument("--test-limit", type=int, default=6000)
    args = parser.parse_args()
    result = experiment(
        args.train, args.test, args.output, seeds=tuple(args.seeds),
        aggregators=tuple(args.aggregators), privacy_modes=tuple(args.privacy_modes),
        policies=tuple(args.attacker_compliance), attacks=tuple(args.attacks),
        rounds=args.rounds, malicious_clients=args.malicious_clients,
        partition=args.partition, alpha=args.alpha,
        train_limit=args.train_limit, test_limit=args.test_limit
    )
    print(json.dumps({
        "federated_executions": result["federated_executions"],
        "federated_rounds": result["federated_rounds"],
        "runs_sha256": result["runs_sha256"],
    }, indent=2))


if __name__ == "__main__":
    main()
