"""Rudimentary oracle-labeled Byzantine admission diagnostics tests."""
import csv
import json
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reproduce import Config, FIELDS, multi_krum_selected_clients, run_case
from selection_experiment import run_selection_experiment


def test_krum_admission_excludes_obvious_large_outliers():
    cfg = Config()
    updates = np.concatenate([np.zeros((12, 4)), 1000*np.ones((3, 4))])
    indices = multi_krum_selected_clients(updates, cfg)
    assert len(indices) == cfg.multi_krum_k
    assert set(indices).isdisjoint({12, 13, 14})


def test_krum_diagnostics_do_not_change_original_metrics():
    cfg = Config(rounds=3)
    args = ("breast_cancer", 0, "multi_krum", "dp_1", "sign_flip", cfg)
    baseline = run_case(*args)
    instrumented = run_case(*args, include_selection_diagnostics=True)
    assert {key:instrumented[key] for key in FIELDS} == baseline
    assert 0 <= instrumented["selected_malicious_fraction"] <= 1
    assert len(json.loads(instrumented["selected_malicious_count_per_round_json"])) == 3
    with pytest.raises(ValueError, match="Multi-Krum"):
        run_case("breast_cancer",0,"mean","none","sign_flip",cfg,
                 include_selection_diagnostics=True)


def test_selection_grid_reproducible_smoke(tmp_path):
    manifest = run_selection_experiment(
        output=tmp_path, datasets=("breast_cancer", "digits"), seeds=(0,),
        partitions=("iid",), alphas=(.3,), malicious_counts=(3,),
        privacy_modes=("clip_only", "dp_1"), compliance=("compliant","bypass"),
        rounds=3,
    )
    assert manifest["runs"] == 8
    assert manifest["total_rounds"] == 24
    with (tmp_path/"selection_runs.csv").open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 8
    assert all(len(json.loads(r["selected_counts_per_round_json"])) == 3 for r in rows)
    assert all(0 <= float(r["selected_malicious_fraction"]) <= 1 for r in rows)
    assert (tmp_path/"selection_summary.csv").exists()
    assert (tmp_path/"selection_manifest.json").exists()
