"""Cross-benchmark descriptive comparison for the CYSE privacy/bypass interaction.

Five seeds on each of TWO DIFFERENT historical datasets do not imply ten
independent real-world populations or universal validity. Do not report a
pooled population p-value from these limited experimental units.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import numpy as np

FACTORS = ("mean", "multi_krum"), ("clip_only", "dp_1"), ("compliant", "bypass")
METRICS = ("accuracy_drop_pp", "macro_f1_drop_pp", "balanced_accuracy_drop_pp")
ROW_FIELDS = (
    "dataset", "seed", "metric", "mean_interaction_pp",
    "multi_krum_interaction_pp", "triple_interaction_pp",
)
SUMMARY_FIELDS = (
    "dataset", "metric", "study_seeds", "mean_triple_interaction_pp",
    "bootstrap_seed_ci_low", "bootstrap_seed_ci_high",
    "positive_seed_fraction", "source_type",
)


def load_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def _values(rows: list[dict], expected_dataset: str) -> dict:
    by_key = {}
    for row in rows:
        if row["dataset"] != expected_dataset:
            raise ValueError(f"dataset mismatch, wanted {expected_dataset}")
        if row["threat"] != "sign_flip":
            raise ValueError("only sign-flip conditions are supported here")
        key = (
            int(row["seed"]), row["aggregator"], row["privacy_mode"],
            row["attacker_compliance"],
        )
        if key in by_key:
            raise ValueError("duplicate seed/aggregator/privacy/compliance case")
        if any(key[i+1] not in FACTORS[i] for i in range(3)):
            raise ValueError("unsupported experimental factor")
        if not all(np.isfinite(float(row[name])) for name in METRICS):
            raise ValueError("non-finite paired experiment endpoint")
        by_key[key] = row
    return by_key


def compare(
    unsw_rows: list[dict], nsl_rows: list[dict],
    *, bootstrap_seed: int = 2026, draws: int = 10000
) -> tuple[list[dict], list[dict]]:
    if draws < 100:
        raise ValueError("at least 100 bootstrap resamples required")
    benchmarks = {
        "UNSW-NB15": _values(unsw_rows, "UNSW-NB15"),
        "NSL-KDD": _values(nsl_rows, "NSL-KDD"),
    }
    expected_seed_set = None
    effects = []
    for dataset, indexed in benchmarks.items():
        seeds = sorted({key[0] for key in indexed})
        if len(seeds) < 2:
            raise ValueError("at least two independent seeds per dataset required")
        if expected_seed_set is not None and seeds != expected_seed_set:
            raise ValueError("dataset seed grids are not aligned")
        expected_seed_set = seeds
        expected_size = len(seeds)*2*2*2
        if len(indexed) != expected_size:
            raise ValueError(f"missing or extra matched cases in {dataset}")
        for seed in seeds:
            for method in FACTORS[0]:
                for privacy in FACTORS[1]:
                    for compliance in FACTORS[2]:
                        if (seed,method,privacy,compliance) not in indexed:
                            raise ValueError(f"missing paired experimental case in {dataset}")
            for metric in METRICS:
                by_method = {}
                for method in FACTORS[0]:
                    def effect(mode: str) -> float:
                        b = float(indexed[seed, method, mode, "bypass"][metric])
                        c = float(indexed[seed, method, mode, "compliant"][metric])
                        return b - c
                    by_method[method] = effect("dp_1") - effect("clip_only")
                effects.append({
                    "dataset": dataset, "seed": seed, "metric": metric,
                    "mean_interaction_pp": by_method["mean"],
                    "multi_krum_interaction_pp": by_method["multi_krum"],
                    "triple_interaction_pp": by_method["multi_krum"]-by_method["mean"],
                })
    summary = []
    rng = np.random.default_rng(bootstrap_seed)
    for metric in METRICS:
        blocks = []
        for dataset in benchmarks:
            chosen = [e for e in effects if e["dataset"]==dataset and e["metric"]==metric]
            values = np.asarray([e["triple_interaction_pp"] for e in chosen])
            if len(values) != len(expected_seed_set):
                raise AssertionError("lost paired experimental seeds")
            draws_matrix = rng.choice(values, size=(draws,len(values)), replace=True).mean(axis=1)
            lower, upper = (float(v) for v in np.percentile(draws_matrix,[2.5,97.5]))
            summary.append({
                "dataset":dataset,"metric":metric,"study_seeds":len(values),
                "mean_triple_interaction_pp":float(np.mean(values)),
                "bootstrap_seed_ci_low":lower,"bootstrap_seed_ci_high":upper,
                "positive_seed_fraction":float(np.mean(values>0)),
                "source_type":"within-dataset seed-conditional; NOT population CI",
            })
            blocks.append(values)
        # Equal weight per data source, not per row or client update.
        a, b = blocks
        simulated = (
            rng.choice(a,size=(draws,len(a)),replace=True).mean(axis=1) +
            rng.choice(b,size=(draws,len(b)),replace=True).mean(axis=1)
        ) / 2
        low, high = (float(v) for v in np.percentile(simulated,[2.5,97.5]))
        summary.append({
            "dataset":"EQUAL_WEIGHT_TWO_DATASETS","metric":metric,
            "study_seeds":len(a)+len(b),
            "mean_triple_interaction_pp":float((np.mean(a)+np.mean(b))/2),
            "bootstrap_seed_ci_low":low,"bootstrap_seed_ci_high":high,
            "positive_seed_fraction":float(np.mean(np.concatenate([a,b])>0)),
            "source_type":"descriptive equal-weight pooled estimate; two historical datasets only",
        })
    return effects, summary


def write_rows(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def execute(unsw: Path, nsl: Path, output: Path, *, draws: int = 10000) -> dict:
    effects, summary = compare(load_csv(unsw),load_csv(nsl),draws=draws)
    output.mkdir(parents=True,exist_ok=True)
    write_rows(output/"cross_seed_effects.csv",effects,ROW_FIELDS)
    write_rows(output/"cross_summary.csv",summary,SUMMARY_FIELDS)
    manifest = {
        "kind":"cross-dataset comparison of two independent historical intrusion benchmarks",
        "scope":"exploratory, post-hoc, 2 datasets x 5 seeds. No population-level inference.",
        "unsw_pair_sha256":hashlib.sha256(unsw.read_bytes()).hexdigest(),
        "nsl_pair_sha256":hashlib.sha256(nsl.read_bytes()).hexdigest(),
        "source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "effect_csv_sha256":hashlib.sha256((output/"cross_seed_effects.csv").read_bytes()).hexdigest(),
        "summary_csv_sha256":hashlib.sha256((output/"cross_summary.csv").read_bytes()).hexdigest(),
        "seed_effects":len(effects),
        "summary_rows":len(summary),
        "bootstrap_draws":draws,
        "limitations":[
            "UNSW-NB15 and NSL-KDD have different source distributions and historical vintages.",
            "Two datasets cannot support a broad claim about current cybersecurity networks.",
            "Matching integer seeds across independent datasets does not imply paired observations across datasets.",
            "Five-seed bootstrap intervals only reflect conditional seeded variability.",
            "The privacy/noise/bypass method interaction has been explored repeatedly; these comparisons are not confirmatory preregistered tests.",
            "No new encrypted Byzantine filtering mechanism or operational differential privacy guarantee is implemented.",
        ],
    }
    (output/"cross_manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    return manifest


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--unsw-paired",required=True,type=Path)
    p.add_argument("--nsl-paired",required=True,type=Path)
    p.add_argument("--output",type=Path,default=Path("artifacts/cyse_01608_cross_dataset"))
    p.add_argument("--draws",type=int,default=10000)
    a=p.parse_args()
    m=execute(a.unsw_paired,a.nsl_paired,a.output,draws=a.draws)
    print(json.dumps({"effects":m["seed_effects"],"summary":m["summary_rows"],"output":str(a.output)},indent=2))


if __name__=="__main__":
    main()
