import csv
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_experiment import run_csv_benchmark


def test_real_csv_interface_smoke_with_synthetic_fixture(tmp_path):
    rng = np.random.default_rng(11)
    n = 600
    frame = pd.DataFrame({
        "sensor": rng.normal(size=n),
        "flow_identifier": np.arange(n),
        "label": ["normal" if i % 2 else "attack" for i in range(n)],
    })
    path = tmp_path / "synthetic_fixture_only.csv"
    frame.to_csv(path, index=False)
    result = run_csv_benchmark(
        csv_path=path, label="label", group=None,
        exclude=("flow_identifier",), output=tmp_path / "out",
        seeds=(0,), aggregators=("mean",), privacy_modes=("dp_1",),
        threats=("sign_flip",), compliance=("compliant", "bypass"),
        rounds=2, partition="iid", alpha=0.3
    )
    assert result["runs"] == 4
    assert result["paired_attacks"] == 2
    assert result["dataset_sha256"]
    assert (tmp_path / "out" / "cyber_runs.csv").exists()
    assert (tmp_path / "out" / "cyber_manifest.json").exists()
    with (tmp_path / "out" / "cyber_metrics.csv").open(newline="") as stream:
        metrics = list(csv.DictReader(stream))
    assert len(metrics) == 4
    for row in metrics:
        assert 0 <= float(row["macro_f1"]) <= 1
        assert 0 <= float(row["balanced_accuracy"]) <= 1
        confusion = json.loads(row["confusion_matrix_json"])
        assert len(confusion) == 2 and len(confusion[0]) == 2
        assert sum(sum(v) for v in confusion) == 150
        assert len(json.loads(row["per_class_recall_json"])) == 2
