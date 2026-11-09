"""Tests use synthetic CSV fixtures ONLY; they do not claim UNSW results."""
import csv
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from unsw_data import prepare_unsw, verify_file
from unsw_experiment import experiment


def fixture_pair(tmp_path):
    rng = np.random.default_rng(403)
    train, test = tmp_path / "fake_training.csv", tmp_path / "fake_testing.csv"
    for filename, n, test_mode in [(train, 600, False), (test, 250, True)]:
        y = np.arange(n) % 2
        frame = pd.DataFrame({
            "id": np.arange(n) + (100000 if test_mode else 0),
            "dur": rng.normal(size=n) + 2*y + (50 if test_mode else 0),
            "sbytes": rng.normal(size=n) + 2*y,
            "proto": ["new-proto" if test_mode and i == 0 else "tcp" if i % 2 else "udp"
                      for i in range(n)],
            "service": ["dns" if i % 3 else "http" for i in range(n)],
            "state": ["INT" if i % 4 else "FIN" for i in range(n)],
            "attack_cat": ["FakeAttack" if v else "Normal" for v in y],
            "label": y,
        })
        frame.loc[5, "dur"] = np.nan
        frame.to_csv(filename, index=False)
    return train, test


def test_pinned_blob_validation(tmp_path):
    train, test = fixture_pair(tmp_path)
    fp = verify_file(train, expected_git_blob=None)
    assert len(fp["sha256"]) == 64
    assert len(fp["git_blob_sha1"]) == 40
    assert fp["size_bytes"] == train.stat().st_size
    verify_file(train, expected_git_blob=fp["git_blob_sha1"])
    with pytest.raises(ValueError, match="SHA mismatch"):
        verify_file(test, expected_git_blob=fp["git_blob_sha1"])


def test_holdout_and_train_only_preprocessing(tmp_path):
    train, test = fixture_pair(tmp_path)
    data, info = prepare_unsw(
        train, test, seed=0, train_limit=300, test_limit=100,
        expected_train_blob=None, expected_test_blob=None,
        require_official_row_counts=False,
    )
    xtr, ytr, xte, yte, classes = data
    assert classes == 2 and xtr.shape[0] == 300 and xte.shape[0] == 100
    assert xtr.shape[1] == xte.shape[1]
    assert info["encoded_feature_count"] == xtr.shape[1] - 1
    assert info["excluded_label_leakage"] == ["id", "attack_cat"]
    assert len(np.unique(ytr)) == 2 and len(np.unique(yte)) == 2
    assert np.isfinite(xtr).all() and np.isfinite(xte).all()
    # The large shifted held-out 'dur' values are NOT used to fit train scaling.
    assert xte[:, 0].mean() > 15.0
    assert abs(xtr[:, 0].mean()) < 1e-10
    assert (xtr[:, -1] == 1).all() and (xte[:, -1] == 1).all()
    assert info["train_binary_class_counts"] == [150, 150]


def test_real_benchmark_interface_with_synthetic_fixture(tmp_path):
    train, test = fixture_pair(tmp_path)
    out = tmp_path / "out"
    manifest = experiment(
        train, test, out, seeds=(0,),
        aggregators=("mean", "multi_krum"), privacy_modes=("dp_1",),
        policies=("compliant", "bypass"), attacks=("sign_flip",),
        rounds=2, partition="iid", train_limit=300, test_limit=100,
        check_blobs=False, strict_official_count=False,
    )
    assert manifest["not_original_manuscript_data"]
    assert manifest["federated_executions"] == 8
    assert manifest["federated_rounds"] == 16
    assert manifest["dataset_manifests"][0]["sampled_train"] == 300
    assert manifest["dataset_manifests"][0]["sampled_test"] == 100
    with (out / "unsw_runs.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    with (out / "unsw_paired.csv").open(newline="") as handle:
        paired = list(csv.DictReader(handle))
    assert len(rows) == 8 and len(paired) == 4
    assert all(0 <= float(row["macro_f1"]) <= 1 for row in rows)
    assert all(0 <= float(row["balanced_accuracy"]) <= 1 for row in rows)
    assert all(len(json.loads(row["confusion_matrix_json"])) == 2 for row in rows)
    assert all("macro_f1_drop_pp" in row for row in paired)
