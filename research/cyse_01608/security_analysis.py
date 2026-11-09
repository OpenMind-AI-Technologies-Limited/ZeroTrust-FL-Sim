"""Paired protocol-deviation analysis; not evidence of scientific novelty by itself."""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import wilcoxon

KEYS = ('dataset', 'seed', 'aggregator', 'privacy_mode', 'threat')
FIELDS = ('privacy_mode', 'aggregator', 'dataset_seed_pairs',
          'compliant_drop_pp', 'bypass_drop_pp', 'bypass_minus_compliant_pp',
          'bootstrap_ci_low', 'bootstrap_ci_high', 'wilcoxon_p', 'holm_p')


def read_csv(path: Path) -> list[dict]:
    with path.open(newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def holm_adjust(p_values: list[float]) -> list[float]:
    """Holm step-down adjusted p-values, monotonic in sorted raw p."""
    if not p_values:
        return []
    order = sorted(range(len(p_values)), key=lambda k: p_values[k])
    corrected = [0.] * len(p_values)
    maximum = 0.
    for rank, index in enumerate(order):
        maximum = max(maximum, min(1., (len(p_values) - rank) * p_values[index]))
        corrected[index] = maximum
    return corrected


def stratified_bootstrap_ci(values_by_dataset: dict[str, list[float]],
                            *, seed: int = 2026, draws: int = 10000) -> tuple[float, float]:
    """Resample study seeds within datasets, not FL rounds as independent samples."""
    if not values_by_dataset or any(not values for values in values_by_dataset.values()):
        raise ValueError('each dataset must have matched observations')
    rng = np.random.default_rng(seed)
    samples = []
    for _ in range(draws):
        block_means = []
        for label in sorted(values_by_dataset):
            values = np.asarray(values_by_dataset[label], dtype=float)
            idx = rng.integers(0, len(values), size=len(values))
            block_means.append(float(np.mean(values[idx])))
        samples.append(float(np.mean(block_means)))
    return tuple(float(v) for v in np.percentile(samples, [2.5, 97.5]))


def compare(compliant: list[dict], bypass: list[dict]) -> list[dict]:
    """Join same dataset/seed/attack/method and compare adversarial bypass."""
    baseline = {tuple(row[k] for k in KEYS): row for row in compliant
                if row['threat'] == 'sign_flip'}
    direct = {tuple(row[k] for k in KEYS): row for row in bypass
              if row['threat'] == 'sign_flip'}
    if not baseline or not direct:
        raise ValueError('both inputs must contain matched sign_flip conditions')
    if len(baseline) != sum(r['threat'] == 'sign_flip' for r in compliant):
        raise ValueError('duplicate compliant keys')
    if len(direct) != sum(r['threat'] == 'sign_flip' for r in bypass):
        raise ValueError('duplicate bypass keys')
    groups = defaultdict(list)
    for key, row in direct.items():
        if key not in baseline:
            raise ValueError(f'no compliant match for {key}')
        original = baseline[key]
        group = (row['privacy_mode'], row['aggregator'])
        clean = float(original['accuracy_drop_pp'])
        attacked = float(row['accuracy_drop_pp'])
        groups[group].append((row['dataset'], row['seed'], clean, attacked))
    result = []
    for (privacy_mode, aggregator), matched in sorted(groups.items()):
        pairs = {(x[0], x[1]) for x in matched}
        if len(pairs) != len(matched):
            raise ValueError('duplicate dataset-seed units')
        if len({d for d, *_ in matched}) < 2:
            raise ValueError('two independent datasets are required for this pooled analysis')
        deltas = np.array([attack - clean for _, _, clean, attack in matched])
        if not np.isfinite(deltas).all():
            raise ValueError('non-finite accuracy differences')
        stratified = defaultdict(list)
        for dataset, seed, clean, attacked in matched:
            stratified[dataset].append(attacked - clean)
        low, high = stratified_bootstrap_ci(stratified)
        p = 1. if np.all(deltas == 0) else float(wilcoxon(deltas).pvalue)
        result.append(dict(privacy_mode=privacy_mode, aggregator=aggregator,
                           dataset_seed_pairs=len(matched),
                           compliant_drop_pp=float(np.mean([v[2] for v in matched])),
                           bypass_drop_pp=float(np.mean([v[3] for v in matched])),
                           bypass_minus_compliant_pp=float(np.mean(deltas)),
                           bootstrap_ci_low=low, bootstrap_ci_high=high,
                           wilcoxon_p=p, holm_p=0.))
    adjusted = holm_adjust([r['wilcoxon_p'] for r in result])
    for row, value in zip(result, adjusted):
        row['holm_p'] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compliant', required=True, type=Path)
    parser.add_argument('--bypass', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    rows = compare(read_csv(args.compliant), read_csv(args.bypass))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(rows, indent=2))


if __name__ == '__main__':
    main()
