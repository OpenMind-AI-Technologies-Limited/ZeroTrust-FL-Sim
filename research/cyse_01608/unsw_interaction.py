"""Pre-specified privacy x attacker-compliance x aggregator interaction.

This is a descriptive, within-dataset, paired-seed analysis of UNSW-NB15,
not a randomized clinical/causal estimand or independent dataset replication.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

import numpy as np
from scipy.stats import wilcoxon

from security_analysis import holm_adjust

METHODS = ("mean", "multi_krum")
PRIVACY = ("clip_only", "dp_1")
COMPLIANCE = ("compliant", "bypass")
METRICS = ("accuracy_drop_pp", "macro_f1_drop_pp", "balanced_accuracy_drop_pp")
COLUMNS = ("metric", "contrast", "seeds", "mean_interaction_pp",
           "seed_bootstrap_95_low", "seed_bootstrap_95_high",
           "wilcoxon_p", "holm_adjusted_p", "individual_seed_interactions_json")


def analyze(rows: list[dict], *, draws: int = 10000, bootstrap_seed: int = 2026) -> list[dict]:
    if draws < 100 or not rows:
        raise ValueError("at least 100 bootstrap draws and nonempty paired data are required")
    lookup = {}
    for row in rows:
        if row["dataset"] != "UNSW-NB15" or row["threat"] != "sign_flip":
            raise ValueError("this pre-specified contrast uses only UNSW-NB15 sign-flip conditions")
        key = (int(row["seed"]), row["aggregator"], row["privacy_mode"],
               row["attacker_compliance"])
        if key in lookup:
            raise ValueError("duplicate paired condition")
        lookup[key] = row
    seeds = sorted({key[0] for key in lookup})
    if len(seeds) < 2:
        raise ValueError("at least two independent study seeds are needed for an interval")
    for seed in seeds:
        for method in METHODS:
            for privacy in PRIVACY:
                for policy in COMPLIANCE:
                    if (seed, method, privacy, policy) not in lookup:
                        raise ValueError("missing complete matched privacy/compliance factors")

    results = []
    for metric in METRICS:
        effects = {}
        for method in METHODS:
            interactions = []
            for seed in seeds:
                def drop(privacy, compliance):
                    value = float(lookup[seed, method, privacy, compliance][metric])
                    if not np.isfinite(value):
                        raise ValueError("non-finite endpoint")
                    return value
                dp_excess = drop("dp_1", "bypass") - drop("dp_1", "compliant")
                clip_excess = drop("clip_only", "bypass") - drop("clip_only", "compliant")
                interactions.append(dp_excess - clip_excess)
            effects[method] = np.asarray(interactions, dtype=float)
        effects["multi_krum_minus_mean"] = effects["multi_krum"] - effects["mean"]

        for method, values in effects.items():
            rng = np.random.default_rng(bootstrap_seed)
            sampled = rng.choice(values, size=(draws, len(values)), replace=True).mean(axis=1)
            lo, hi = (float(v) for v in np.percentile(sampled, [2.5, 97.5]))
            p = 1.0 if np.all(values == 0.0) else float(wilcoxon(values).pvalue)
            results.append({
                "metric": metric, "contrast": method, "seeds": len(seeds),
                "mean_interaction_pp": float(np.mean(values)),
                "seed_bootstrap_95_low": lo, "seed_bootstrap_95_high": hi,
                "wilcoxon_p": p, "holm_adjusted_p": 0.,
                "individual_seed_interactions_json": json.dumps(values.tolist()),
            })
    adjusted = holm_adjust([row["wilcoxon_p"] for row in results])
    for row, p in zip(results, adjusted):
        row["holm_adjusted_p"] = p
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--draws", type=int, default=10000)
    args = parser.parse_args()
    with args.input.open(newline="", encoding="utf-8") as f:
        findings = analyze(list(csv.DictReader(f)), draws=args.draws)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(findings)
    manifest = {
        "study": "UNSW-NB15 privacy/compliance/aggregator interaction",
        "status": "exploratory, five seeds from only one externally sourced dataset",
        "primary_contrast": "accuracy_drop_pp / multi_krum_minus_mean",
        "comparisons": len(findings),
        "seed_bootstrap_draws": args.draws,
        "input_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(),
        "output_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "limitations": [
            "Seed-bootstrap intervals capture within-dataset seed variation, not dataset or deployment generalization.",
            "Two-sided Wilcoxon p-values use only five pairs and receive Holm adjustment across nine exploratory tests.",
            "No cryptographic Byzantine input-validation mechanism is proposed or established.",
            "These are seeded utility experiments and not operational differential privacy."
        ],
    }
    (args.output.parent / "unsw_interaction_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "comparisons": len(findings),
        "primary": next(r for r in findings
                        if r["metric"] == "accuracy_drop_pp"
                        and r["contrast"] == "multi_krum_minus_mean")
    }, indent=2))


if __name__ == "__main__":
    main()
