"""Fail-closed, paired-seed audit of supplementary IDS attack sensitivity.

Separate from CYSE-D-26-01608 original 720-run historical evidence.
This analysis is exploratory and conditional on the sampled datasets/seeds.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
from pathlib import Path

import numpy as np


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _same(a: float, b: float) -> bool:
    return math.isclose(a, b, rel_tol=1e-10, abs_tol=1e-8)


def _fraction(value: str, field: str) -> float:
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError("invalid " + field)
    return number


def _drop(value: str, field: str) -> float:
    number = float(value)
    if not math.isfinite(number) or not -100.0 <= number <= 100.0:
        raise ValueError("invalid " + field)
    return number


def _pvalue(deltas: np.ndarray) -> float:
    """Two-sided, exhaustive paired sign-flip randomization; n <= 16."""
    if len(deltas) > 16:
        raise ValueError("exact test restricted to at most 16 paired seeds")
    observed = abs(float(np.mean(deltas)))
    extreme = 0
    count = 0
    for signs in itertools.product((-1, 1), repeat=len(deltas)):
        test = abs(float(np.mean(deltas * np.asarray(signs))))
        extreme += test >= observed - 1e-12
        count += 1
    return extreme / count


def _holm(pvalues: list[float]) -> list[float]:
    rank = sorted(range(len(pvalues)), key=lambda i: pvalues[i])
    result = [0.] * len(pvalues)
    previous = 0.
    for position, i in enumerate(rank):
        previous = max(previous, (len(pvalues) - position) * pvalues[i])
        result[i] = min(1., previous)
    return result


def audit(input_dir: Path, output_dir: Path, *, draws: int = 4000) -> dict:
    if draws < 100:
        raise ValueError("bootstrap draws must be >= 100")
    raw = input_dir / "baseline_runs.csv"
    paired = input_dir / "baseline_pairs.csv"
    manifest_file = input_dir / "baseline_manifest.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if manifest.get("not_original_720_runs") is not True:
        raise ValueError("supplementary-study provenance flag missing")
    if _sha(raw) != manifest.get("raw_csv_sha256"):
        raise ValueError("raw experiment hash mismatch")
    if _sha(paired) != manifest.get("paired_csv_sha256"):
        raise ValueError("paired experiment hash mismatch")
    seeds = list(manifest["seeds"])
    methods = list(manifest["methods"])
    privacy = list(manifest["privacy"])
    policies = list(manifest["policies"])
    attacks = list(manifest["attacks"])
    if any(len(x) != len(set(x)) or not x for x in
           (seeds, methods, privacy, policies, attacks)):
        raise ValueError("empty or duplicated experimental factors")
    if set(policies) != {"compliant", "bypass"}:
        raise ValueError("matched compliant/bypass policies required")
    if "benign" in attacks:
        raise ValueError("benign must not be listed as an attack")
    runs = _rows(raw)
    pairs = _rows(paired)
    expected = set(itertools.product(
        seeds, methods, privacy, policies, ["benign", *attacks]
    ))
    indexed = {}
    for row in runs:
        key = (int(row["seed"]), row["aggregator"], row["privacy_mode"],
               row["attacker_compliance"], row["threat"])
        if key in indexed or key not in expected:
            raise ValueError("duplicate or unexpected experimental condition")
        if row["dataset"] != manifest["dataset"]:
            raise ValueError("dataset label mismatch")
        if (int(row["malicious_clients"]) != int(manifest["malicious_clients"]) or
                int(row["rounds"]) != int(manifest["rounds"]) or
                not _same(float(row["alpha"]), float(manifest["alpha"]))):
            raise ValueError("factor/metadata mismatch")
        for field in ("final_accuracy", "macro_f1", "balanced_accuracy"):
            _fraction(row[field], field)
        if not math.isfinite(float(row["final_loss"])):
            raise ValueError("nonfinite cross-entropy")
        indexed[key] = row
    if set(indexed) != expected or len(runs) != manifest["executions"]:
        raise ValueError("missing or wrong experimental grid")
    expected_pairs = set(itertools.product(seeds, methods, privacy, policies, attacks))
    paired_index = {}
    for row in pairs:
        key = (int(row["seed"]), row["aggregator"], row["privacy_mode"],
               row["attacker_compliance"], row["threat"])
        if key in paired_index or key not in expected_pairs:
            raise ValueError("duplicate or unexpected matched condition")
        benign = indexed[key[:-1] + ("benign",)]
        attacked = indexed[key]
        for source, target, field in (
            ("final_accuracy", "accuracy_drop_pp", "clean_accuracy"),
            ("macro_f1", "macro_f1_drop_pp", None),
            ("balanced_accuracy", "balanced_accuracy_drop_pp", None),
        ):
            calculated = 100. * (
                float(benign[source]) - float(attacked[source])
            )
            if not _same(calculated, _drop(row[target], target)):
                raise ValueError("paired metric disagrees with raw values: " + target)
            if field and (not _same(float(benign[source]), float(row[field])) or
                          not _same(float(attacked[source]), float(row["attacked_accuracy"]))):
                raise ValueError("matched accuracy inconsistent")
        paired_index[key] = row
    if set(paired_index) != expected_pairs:
        raise ValueError("incomplete paired-comparison grid")

    # A seed is a paired observation, NOT one independent observation per run.
    effects = {}
    per_seed = []
    for seed, method, mode, attack in itertools.product(
        seeds, methods, privacy, attacks
    ):
        prefix = (seed, method, mode)
        compliant = paired_index[prefix + ("compliant", attack)]
        bypass = paired_index[prefix + ("bypass", attack)]
        value = (_drop(bypass["accuracy_drop_pp"], "accuracy_drop_pp") -
                 _drop(compliant["accuracy_drop_pp"], "accuracy_drop_pp"))
        effects[(seed, method, mode, attack)] = value
        per_seed.append(dict(
            dataset=manifest["dataset"], seed=seed, aggregator=method,
            privacy_mode=mode, threat=attack,
            malicious_clients=manifest["malicious_clients"],
            dirichlet_alpha=manifest["alpha"],
            excess_bypass_accuracy_drop_pp=value,
            compliant_accuracy_drop_pp=compliant["accuracy_drop_pp"],
            bypass_accuracy_drop_pp=bypass["accuracy_drop_pp"],
        ))

    contrasts = []
    for method, mode, attack in itertools.product(methods, privacy, attacks):
        contrasts.append(("bypass_minus_compliant", method, mode, attack,
                          [effects[(seed, method, mode, attack)] for seed in seeds]))
    if set(("clip_only", "dp_1")).issubset(privacy):
        for method, attack in itertools.product(methods, attacks):
            contrasts.append(("privacy_x_bypass", method, "dp_1-minus-clip_only",
                              attack, [effects[(seed, method, "dp_1", attack)] -
                                       effects[(seed, method, "clip_only", attack)]
                                       for seed in seeds]))
        if {"mean", "multi_krum"}.issubset(methods):
            for attack in attacks:
                contrasts.append(("aggregator_x_privacy_x_bypass",
                                  "multi_krum-minus-mean", "dp_1-minus-clip_only",
                                  attack, [
                                    (effects[(seed, "multi_krum", "dp_1", attack)] -
                                     effects[(seed, "multi_krum", "clip_only", attack)]) -
                                    (effects[(seed, "mean", "dp_1", attack)] -
                                     effects[(seed, "mean", "clip_only", attack)])
                                    for seed in seeds]))

    rng = np.random.default_rng(140927)
    summary = []
    for kind, method, mode, attack, values in contrasts:
        sample = np.asarray(values, dtype=float)
        if not np.isfinite(sample).all():
            raise ValueError("nonfinite seed contrasts")
        resampled = sample[rng.integers(0, len(sample), size=(draws, len(sample)))].mean(axis=1)
        lo, hi = np.quantile(resampled, [0.025, 0.975])
        summary.append(dict(
            dataset=manifest["dataset"], contrast=kind, aggregator=method,
            privacy_mode=mode, threat=attack,
            malicious_clients=manifest["malicious_clients"],
            dirichlet_alpha=manifest["alpha"], n_paired_seeds=len(seeds),
            mean_contrast_pp=float(sample.mean()),
            seed_sd_pp=float(sample.std(ddof=1)) if len(sample) > 1 else 0.0,
            bootstrap_95_lo_pp=float(lo), bootstrap_95_hi_pp=float(hi),
            exact_sign_flip_p=_pvalue(sample),
        ))
    adjusted = _holm([float(x["exact_sign_flip_p"]) for x in summary])
    for row, p in zip(summary, adjusted):
        row["holm_within_job_p"] = p

    output_dir.mkdir(parents=True, exist_ok=True)
    for name, records in (("seed_effects.csv", per_seed),
                          ("exploratory_contrasts.csv", summary)):
        with (output_dir / name).open("w", newline="", encoding="utf-8") as out:
            writer = csv.DictWriter(out, fieldnames=list(records[0]))
            writer.writeheader()
            writer.writerows(records)
    result = dict(
        study="supplementary Byzantine attack sensitivity; exploratory",
        not_original_720_runs=True, data_source=manifest["dataset"],
        original_run_manifest_sha256=_sha(manifest_file),
        original_run_csv_sha256=_sha(raw),
        original_paired_csv_sha256=_sha(paired),
        paired_observation_unit="dataset/seed within a fixed scenario",
        baseline_executions=len(runs), federated_rounds=manifest["federated_rounds"],
        per_seed_effects=len(per_seed), contrasts=len(summary),
        bootstrap_draws=draws,
        seed_effects_sha256=_sha(output_dir / "seed_effects.csv"),
        contrasts_sha256=_sha(output_dir / "exploratory_contrasts.csv"),
        limitations=[
            "Five deterministic seeds are not independent cybersecurity datasets or deployable DP.",
            "ALIE uses an idealized honest-update statistics oracle, not a demonstrated network attacker.",
            "Bootstrap intervals and exact tests are conditional on these seeds and fixed historical sources.",
            "Holm adjustment is within this job only, not across the full sensitivity family.",
            "No CKKS-valid Byzantine filtering or novel defense is evaluated.",
            "Historical original-author 720-run provenance is not authenticated.",
        ],
    )
    (output_dir / "audit_manifest.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--draws", type=int, default=4000)
    args = parser.parse_args()
    result = audit(args.input_dir, args.output_dir, draws=args.draws)
    print(json.dumps({"data_source": result["data_source"],
                      "executions": result["baseline_executions"],
                      "paired_seed_effects": result["per_seed_effects"],
                      "contrasts": result["contrasts"]}, indent=2))


if __name__ == "__main__":
    main()
