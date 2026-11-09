"""End-to-end baseline experiment tests use clearly marked synthetic fixtures."""
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from defense_benchmark import evaluate
from test_unsw_data import fixture_pair as unsw_fixture
from test_nsl_data import fixture_pair as nsl_fixture


def test_paired_plaintext_robust_baselines_unsw(tmp_path):
    train, test = unsw_fixture(tmp_path)
    output = tmp_path / "results"
    m = evaluate(
        dataset="UNSW-NB15", train=train, test=test,
        output=output, seeds=(0,), methods=(
            "mean", "multi_krum", "rfa", "server_clipped_rfa"
        ), privacy_modes=("clip_only", "dp_1"),
        policies=("compliant", "bypass"),
        attacks=("sign_flip",), rounds=2, train_limit=300,
        test_limit=100, verify_sources=False,
    )
    assert m["executions"] == 32
    assert m["federated_rounds"] == 64
    assert m["not_original_720_runs"]
    with (output / "baseline_runs.csv").open(newline="") as file:
        records=list(csv.DictReader(file))
    with (output / "baseline_pairs.csv").open(newline="") as file:
        pairs=list(csv.DictReader(file))
    with (output / "baseline_summary.csv").open(newline="") as file:
        summary=list(csv.DictReader(file))
    assert len(records)==32 and len(pairs)==16 and len(summary)==16
    assert {r["aggregator"] for r in records} == {
        "mean", "multi_krum", "rfa", "server_clipped_rfa"
    }
    assert all(0 <= float(r["macro_f1"]) <= 1 for r in records)
    assert json.loads((output/"baseline_manifest.json").read_text())["raw_csv_sha256"]


def test_nsl_kdd_baseline_runner_independent_source_path(tmp_path):
    train, test = nsl_fixture(tmp_path)
    m = evaluate(
        dataset="NSL-KDD", train=train, test=test,
        output=tmp_path / "nsl_result",
        seeds=(0,), methods=("server_clipped_mean", "server_clipped_multi_krum"),
        privacy_modes=("dp_1",), policies=("bypass",),
        attacks=("sign_flip",), rounds=2,
        train_limit=300, test_limit=100, verify_sources=False
    )
    assert m["executions"]==4
    assert m["federated_rounds"]==8
    assert m["dataset_split_manifests"][0]["sampled_test"]==100
