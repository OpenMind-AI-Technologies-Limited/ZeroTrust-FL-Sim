"""Exploratory, paired Multi-Krum malicious-admission inference.

Uses ground-truth Byzantine labels available to the simulator. Reported
selection frequency must NOT be described as an attack detector's precision.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import wilcoxon

from security_analysis import holm_adjust, stratified_bootstrap_ci

PAIRED_ID = (
    "dataset", "seed", "partition", "alpha", "malicious_clients",
    "privacy_mode", "attack",
)
GROUP = ("partition", "alpha", "malicious_clients", "privacy_mode", "attack")
COLUMNS = GROUP + (
    "dataset_seed_pairs", "mean_compliant_admission", "mean_bypass_admission",
    "mean_bypass_minus_compliant_admission", "admission_ci_low",
    "admission_ci_high", "mean_bypass_minus_compliant_accuracy",
    "wilcoxon_p", "holm_adjusted_p",
)


def analyze(rows: list[dict]) -> list[dict]:
    paired = defaultdict(dict)
    for row in rows:
        key = tuple(str(row[k]) for k in PAIRED_ID)
        policy = row["attacker_compliance"]
        if policy not in {"compliant", "bypass"}:
            raise ValueError("unknown compliance policy")
        if policy in paired[key]:
            raise ValueError("duplicate matched condition")
        admitted = float(row["selected_malicious_fraction"])
        accuracy = float(row["attacked_accuracy"])
        if not 0 <= admitted <= 1 or not 0 <= accuracy <= 1:
            raise ValueError("admission/accuracy values outside [0,1]")
        paired[key][policy] = (admitted, accuracy)

    by_group = defaultdict(list)
    for key, conditions in paired.items():
        if set(conditions) != {"compliant", "bypass"}:
            raise ValueError("missing matching compliant/bypass condition")
        group = tuple(key[PAIRED_ID.index(k)] for k in GROUP)
        by_group[group].append((key[0], key[1], conditions["compliant"], conditions["bypass"]))

    results = []
    for group, matches in sorted(by_group.items()):
        if len(set((d,s) for d,s,*_ in matches)) != len(matches):
            raise ValueError("duplicate dataset-seed pairs")
        differences = []
        acc_effects = []
        by_dataset = defaultdict(list)
        for dataset, seed, compliant, bypass in matches:
            delta = bypass[0]-compliant[0]
            differences.append(delta)
            acc_effects.append(bypass[1]-compliant[1])
            by_dataset[dataset].append(delta)
        if len(by_dataset) < 2:
            raise ValueError("pooled analysis needs at least two datasets")
        lo, hi = stratified_bootstrap_ci(by_dataset, draws=5000)
        arr = np.asarray(differences)
        p = 1.0 if np.all(arr == 0) else float(wilcoxon(arr).pvalue)
        results.append(dict(zip(GROUP,group)) | {
            "dataset_seed_pairs":len(matches),
            "mean_compliant_admission":float(np.mean([i[2][0] for i in matches])),
            "mean_bypass_admission":float(np.mean([i[3][0] for i in matches])),
            "mean_bypass_minus_compliant_admission":float(np.mean(arr)),
            "admission_ci_low":lo, "admission_ci_high":hi,
            "mean_bypass_minus_compliant_accuracy":float(np.mean(acc_effects)),
            "wilcoxon_p":p, "holm_adjusted_p":0.0,
        })
    if not results:
        raise ValueError("empty selection study")
    corrected = holm_adjust([record["wilcoxon_p"] for record in results])
    for row, adj in zip(results, corrected):
        row["holm_adjusted_p"] = adj
    return results


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    with args.input.open(newline="",encoding="utf-8") as stream:
        rows=analyze(list(csv.DictReader(stream)))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("w",newline="",encoding="utf-8") as stream:
        writer=csv.DictWriter(stream,fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps({"contrasts":len(rows),"file":str(args.output)},indent=2))


if __name__ == "__main__":
    main()
