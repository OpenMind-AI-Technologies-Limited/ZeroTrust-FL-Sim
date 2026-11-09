import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_data import prepare_csv


def make_csv(tmp_path):
    rng = np.random.default_rng(33)
    count = 400
    frame = pd.DataFrame({
        "group": [f"device{i // 20}" for i in range(count)],
        "flow_id": [f"flow{i}" for i in range(count)],
        "f1": rng.normal(size=count),
        "f2": rng.normal(size=count),
        "target": ["benign" if i % 2 else "attack" for i in range(count)],
    })
    frame.loc[4, "f1"] = np.nan
    path = tmp_path / "mock_flows.csv"
    frame.to_csv(path, index=False)
    return path


def test_group_heldout_dataset_no_leakage(tmp_path):
    path = make_csv(tmp_path)
    result = prepare_csv(
        path, label_column="target", group_column="group",
        exclude_columns=("flow_id",), seed=17
    )
    xtr, ytr, xte, yte, classes = result.data
    assert len(ytr) + len(yte) == 400
    assert classes == 2
    assert xtr.shape[1] == 3
    assert result.metadata["numeric_features"] == ["f1", "f2"]
    assert result.metadata["split_type"] == "group"
    assert result.metadata["dataset_sha256"]
    assert np.isfinite(xtr).all() and np.isfinite(xte).all()
    assert np.all(xtr[:, -1] == 1) and np.all(xte[:, -1] == 1)
    assert np.allclose(xtr[:, :-1].mean(axis=0), 0, atol=1e-10)


def test_missing_label_and_unexcluded_identifiers_rejected(tmp_path):
    path = make_csv(tmp_path)
    with pytest.raises(ValueError, match="missing label"):
        prepare_csv(path, label_column="unknown", seed=0)
    with pytest.raises(ValueError, match="non-numeric"):
        prepare_csv(path, label_column="target", group_column="group", seed=0)
