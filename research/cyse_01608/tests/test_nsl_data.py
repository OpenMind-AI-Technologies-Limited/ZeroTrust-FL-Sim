"""Synthetic NSL-style fixtures only. No historical dataset values are fabricated."""
import csv
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nsl_data import prepare_nsl, verify_file
from nsl_experiment import experiment


def fixture_pair(folder: Path) -> tuple[Path, Path]:
    rng = np.random.default_rng(2026)
    train = folder / "fixture_train.txt"
    test = folder / "fixture_test.txt"
    for path, size, heldout in ((train, 600, False), (test, 250, True)):
        rows = []
        for i in range(size):
            malicious = i % 2 == 0
            row = [float(rng.normal()) for _ in range(41)]
            row[0] = float(rng.normal() + 2 * malicious + (45 if heldout else 0))
            row[1] = "tcp" if i % 2 else "udp"
            row[2] = "unseen_service" if heldout and i == 2 else "http"
            row[3] = "SF" if i % 3 else "REJ"
            # The final feature pair 41,42 is label and difficulty. Neither
            # is allowed to enter the model features.
            row.append("neptune" if malicious else "normal")
            row.append(21 if malicious else 1)
            rows.append(row)
        pd.DataFrame(rows).to_csv(path, index=False, header=False)
    return train, test


def test_blob_verification_rejects_unpinned_content(tmp_path):
    train, test = fixture_pair(tmp_path)
    meta = verify_file(train, None)
    assert len(meta["sha256"]) == 64
    verify_file(train, meta["git_blob_sha1"])
    with pytest.raises(ValueError, match="SHA mismatch"):
        verify_file(test, meta["git_blob_sha1"])


def test_split_holdout_difficulty_exclusion_and_category_unknown(tmp_path):
    train, test = fixture_pair(tmp_path)
    task, metadata = prepare_nsl(
        train, test, seed=1, train_limit=300, test_limit=100,
        expected_train_blob=None, expected_test_blob=None,
        require_standard_counts=False,
    )
    xtr, ytr, xte, yte, nclass = task
    assert nclass == 2 and xtr.shape[0] == 300 and xte.shape[0] == 100
    assert xtr.shape[1] == xte.shape[1]
    assert metadata["numeric_feature_count"] == 38
    assert metadata["encoded_feature_count"] == xtr.shape[1] - 1
    assert metadata["excluded_fields"] == ["attack_label", "difficulty"]
    assert metadata["train_class_counts"] == [150, 150]
    assert np.isfinite(xtr).all() and np.isfinite(xte).all()
    assert abs(float(np.mean(xtr[:, 0]))) < 1e-10
    assert np.mean(xte[:, 0]) > 15
    assert np.all(xtr[:, -1] == 1) and np.all(xte[:, -1] == 1)
    assert set(ytr) == {0, 1} and set(yte) == {0, 1}


def test_nsl_end_to_end_smoke_on_synthetic_fixture(tmp_path):
    train, test = fixture_pair(tmp_path)
    folder = tmp_path / "study"
    manifest = experiment(
        train, test, folder, seeds=(0,), aggregators=("mean", "multi_krum"),
        privacy_modes=("dp_1",), policies=("compliant", "bypass"),
        attacks=("sign_flip",), rounds=2, partition="dirichlet", alpha=0.3,
        train_limit=300, test_limit=100, check_blobs=False,
        strict_official_count=False,
    )
    assert manifest["federated_executions"] == 8
    assert manifest["federated_rounds"] == 16
    with (folder / "nsl_runs.csv").open(newline="") as f:
        runs = list(csv.DictReader(f))
    with (folder / "nsl_paired.csv").open(newline="") as f:
        paired = list(csv.DictReader(f))
    assert len(runs) == 8 and len(paired) == 4
    assert all(0 <= float(x["macro_f1"]) <= 1 for x in runs)
    assert all(0 <= float(x["balanced_accuracy"]) <= 1 for x in runs)
    assert all("macro_f1_drop_pp" in x for x in paired)
