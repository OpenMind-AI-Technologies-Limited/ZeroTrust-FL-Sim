"""Research question RQ2: measure Byzantine update admission into Multi-Krum.

This is an *oracle-labeled* diagnostic: the simulator knows which clients it
corrupted. Multi-Krum does not output those identities as malicious labels.
An admitted attack update is not necessarily causally responsible for model
degradation. Security interpretations require independent experiments.
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

from reproduce import Config, run_case

FIELDS = (
    "dataset", "seed", "partition", "alpha", "malicious_clients",
    "privacy_mode", "attacker_compliance", "attack",
    "selected_malicious_fraction", "selected_counts_per_round_json",
    "attacked_accuracy",
)
SUMMARY_FIELDS = (
    "dataset", "partition", "alpha", "malicious_clients",
    "privacy_mode", "attacker_compliance", "attack",
    "runs", "mean_selected_malicious_fraction", "std_selected_malicious_fraction",
    "mean_attacked_accuracy",
)


def run_selection_experiment(
    *, output: Path, datasets: tuple[str, ...], seeds: tuple[int, ...],
    partitions: tuple[str, ...], alphas: tuple[float, ...],
    malicious_counts: tuple[int, ...], privacy_modes: tuple[str, ...],
    compliance: tuple[str, ...], rounds: int = 20, attack: str = "sign_flip",
) -> dict:
    if not all((datasets, seeds, partitions, malicious_counts, privacy_modes, compliance)):
        raise ValueError("experiment parameters must be nonempty")
    if attack not in {"sign_flip", "alie_oracle", "label_flip"}:
        raise ValueError("unsupported attack")
    if any(mode not in {"clip_only", "dp_0.5", "dp_1", "dp_2", "dp_4"} for mode in privacy_modes):
        raise ValueError("unsupported privacy mode")
    choices = [(kind, alpha) for kind in partitions
               for alpha in ((0.3,) if kind == "iid" else alphas)]
    if not choices:
        raise ValueError("specify at least one valid partition and alpha")
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    for dataset, seed, (partition, alpha), malicious, mode, policy in itertools.product(
        datasets, seeds, choices, malicious_counts, privacy_modes, compliance
    ):
        cfg = Config(
            partition=partition, alpha=alpha, malicious_clients=malicious,
            multi_krum_k=min(5, 15 - malicious - 2),
            attacker_compliance=policy, rounds=rounds,
        )
        record = run_case(
            dataset, seed, "multi_krum", mode, attack, cfg,
            include_selection_diagnostics=True,
        )
        rows.append({
            "dataset":dataset, "seed":seed, "partition":partition,
            "alpha":alpha if partition == "dirichlet" else "",
            "malicious_clients":malicious, "privacy_mode":mode,
            "attacker_compliance":policy, "attack":attack,
            "selected_malicious_fraction":record["selected_malicious_fraction"],
            "selected_counts_per_round_json":record["selected_malicious_count_per_round_json"],
            "attacked_accuracy":record["final_accuracy"],
        })
    with (output / "selection_runs.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    summary = defaultdict(list)
    for record in rows:
        key = tuple(record[field] for field in SUMMARY_FIELDS[:7])
        summary[key].append(record)
    summary_rows = []
    for key, items in sorted(summary.items()):
        fractions = [item["selected_malicious_fraction"] for item in items]
        summary_rows.append(dict(zip(SUMMARY_FIELDS[:7], key)) | {
            "runs":len(items),
            "mean_selected_malicious_fraction":float(np.mean(fractions)),
            "std_selected_malicious_fraction":float(np.std(fractions, ddof=1)) if len(items) > 1 else 0.0,
            "mean_attacked_accuracy":float(np.mean([item["attacked_accuracy"] for item in items])),
        })
    with (output / "selection_summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(summary_rows)
    manifest = {
        "kind":"exploratory Multi-Krum malicious-admission measurement",
        "assumption":"oracle knows actual malicious-client IDs; CKKS hides plaintext in deployed setting",
        "runs":len(rows), "rounds_per_run":rounds, "total_rounds":len(rows) * rounds,
        "datasets":datasets, "seeds":seeds, "partitions":partitions,
        "alphas":alphas, "malicious_counts":malicious_counts,
        "privacy_modes":privacy_modes, "attacker_compliance":compliance, "attack":attack,
        "warning":"Admission frequency is NOT detection precision, a privacy guarantee, or proof of a novel defense.",
        "run_sha256":hashlib.sha256((output/"selection_runs.csv").read_bytes()).hexdigest(),
        "source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (output/"selection_manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,default=Path("artifacts/cyse_01608_selection"))
    parser.add_argument("--datasets",nargs="+",default=["breast_cancer","digits"])
    parser.add_argument("--seeds",nargs="+",type=int,default=list(range(5)))
    parser.add_argument("--partitions",nargs="+",choices=("iid","dirichlet"),default=["iid","dirichlet"])
    parser.add_argument("--alphas",nargs="+",type=float,default=[0.3])
    parser.add_argument("--malicious-clients",nargs="+",type=int,default=[3,6])
    parser.add_argument("--privacy-modes",nargs="+",default=["clip_only","dp_1"])
    parser.add_argument("--attacker-compliance",nargs="+",choices=("compliant","bypass"),default=["compliant","bypass"])
    parser.add_argument("--attack",choices=("sign_flip","label_flip","alie_oracle"),default="sign_flip")
    parser.add_argument("--rounds",type=int,default=20)
    args=parser.parse_args()
    m=run_selection_experiment(
        output=args.output,datasets=tuple(args.datasets),seeds=tuple(args.seeds),
        partitions=tuple(args.partitions),alphas=tuple(args.alphas),
        malicious_counts=tuple(args.malicious_clients),
        privacy_modes=tuple(args.privacy_modes),
        compliance=tuple(args.attacker_compliance),
        rounds=args.rounds,attack=args.attack)
    print(json.dumps({"runs":m["runs"],"total_rounds":m["total_rounds"],"sha256":m["run_sha256"]},indent=2))


if __name__ == "__main__":
    main()
