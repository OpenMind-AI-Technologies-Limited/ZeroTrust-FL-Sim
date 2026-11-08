"""Matched exploratory inference for privacy/Byzantine sensitivity experiments.

The units are dataset-seed pairs, NOT client updates or dependent FL rounds.
This is not a cryptographic proof or a generalizable causal conclusion.
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

KEYS = (
    "dataset", "seed", "partition", "alpha", "malicious_clients",
    "aggregator", "privacy_mode", "threat",
)
GROUP = ("partition", "alpha", "malicious_clients", "aggregator", "privacy_mode", "threat")
COLUMNS = GROUP + (
    "observations", "datasets", "mean_compliant_drop_pp",
    "mean_bypass_drop_pp", "mean_excess_degradation_pp",
    "stratified_bootstrap_ci_low", "stratified_bootstrap_ci_high",
    "wilcoxon_p", "holm_adjusted_p",
)


def read_rows(paths: tuple[Path, ...]) -> list[dict]:
    rows = []
    for path in paths:
        with path.open(newline="", encoding="utf-8") as stream:
            rows.extend(csv.DictReader(stream))
    return rows


def analyze(rows: list[dict]) -> list[dict]:
    paired = {}
    for row in rows:
        if row["attacker_compliance"] not in {"compliant", "bypass"}:
            raise ValueError("unknown attacker compliance condition")
        key = tuple(str(row[k]) for k in KEYS)
        paired.setdefault(key, {})
        policy = row["attacker_compliance"]
        if policy in paired[key]:
            raise ValueError("duplicate matched experimental case")
        paired[key][policy] = float(row["accuracy_drop_pp"])

    grouped = defaultdict(list)
    for key, conditions in paired.items():
        if set(conditions) != {"compliant", "bypass"}:
            raise ValueError(f"missing paired compliance case: {key}")
        group = tuple(key[KEYS.index(k)] for k in GROUP)
        grouped[group].append((
            key[0], key[1], conditions["compliant"], conditions["bypass"]
        ))
    findings = []
    for condition, observations in sorted(grouped.items()):
        ids = {(dataset, seed) for dataset, seed, _, _ in observations}
        if len(ids) != len(observations):
            raise ValueError("duplicate dataset-seed units")
        by_dataset = defaultdict(list)
        deltas = []
        for dataset, seed, compliant, bypass in observations:
            effect = bypass - compliant
            by_dataset[dataset].append(effect)
            deltas.append(effect)
        if len(by_dataset) < 2:
            raise ValueError("pooled inference requires at least two datasets")
        differences = np.asarray(deltas, dtype=np.float64)
        if not np.isfinite(differences).all():
            raise ValueError("non-finite paired effect")
        low, high = stratified_bootstrap_ci(by_dataset, draws=5000)
        p = 1.0 if np.all(differences == 0) else float(wilcoxon(differences).pvalue)
        findings.append(dict(zip(GROUP, condition)) | {
            "observations": len(observations), "datasets": len(by_dataset),
            "mean_compliant_drop_pp": float(np.mean([o[2] for o in observations])),
            "mean_bypass_drop_pp": float(np.mean([o[3] for o in observations])),
            "mean_excess_degradation_pp": float(np.mean(differences)),
            "stratified_bootstrap_ci_low": low,
            "stratified_bootstrap_ci_high": high,
            "wilcoxon_p": p, "holm_adjusted_p": 0.0,
        })
    if not findings:
        raise ValueError("no comparisons")
    adjusted = holm_adjust([row["wilcoxon_p"] for row in findings])
    for result, value in zip(findings, adjusted):
        result["holm_adjusted_p"] = value
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", nargs="+", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    rows = analyze(read_rows(tuple(args.inputs)))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps({"comparisons": len(rows), "output": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
