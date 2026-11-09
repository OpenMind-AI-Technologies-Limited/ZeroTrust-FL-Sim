"""Controlled synthetic fixtures; never described as real IDS evidence."""
import csv
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attack_sensitivity_validation import audit
from defense_benchmark import evaluate
from test_unsw_data import fixture_pair


@pytest.fixture()
def sensitivity(tmp_path):
    train, test = fixture_pair(tmp_path)
    source = tmp_path / "input"
    experiment = evaluate(
        dataset="UNSW-NB15", train=train, test=test, output=source,
        seeds=(0, 1), methods=("mean", "multi_krum"),
        privacy_modes=("clip_only", "dp_1"),
        policies=("compliant", "bypass"),
        attacks=("sign_flip", "alie_oracle"),
        rounds=2, malicious_clients=3, train_limit=300,
        test_limit=100, verify_sources=False,
    )
    assert experiment["executions"] == 48
    return source, tmp_path / "audit"


def test_complete_grid_and_conditional_inference(sensitivity):
    source, target = sensitivity
    report = audit(source, target, draws=300)
    assert report["baseline_executions"] == 48
    assert report["per_seed_effects"] == 16
    assert report["contrasts"] == 14
    assert report["not_original_720_runs"]
    with (target / "exploratory_contrasts.csv").open(newline="") as handle:
        contrasts = list(csv.DictReader(handle))
    assert len(contrasts) == 14
    assert {r["contrast"] for r in contrasts} == {
        "bypass_minus_compliant", "privacy_x_bypass",
        "aggregator_x_privacy_x_bypass",
    }
    assert all(0 <= float(r["holm_within_job_p"]) <= 1 for r in contrasts)


def test_rejects_tampered_experiment_file(sensitivity):
    source, target = sensitivity
    with (source / "baseline_runs.csv").open("a", encoding="utf-8") as out:
        out.write("tampered\n")
    with pytest.raises(ValueError, match="hash mismatch"):
        audit(source, target, draws=100)


def test_rejects_missing_paired_condition_even_when_hash_rewritten(sensitivity):
    source, target = sensitivity
    path = source / "baseline_pairs.csv"
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    header = list(rows[0])
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows[1:])
    manifest_path = source / "baseline_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["paired_csv_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="incomplete paired-comparison grid"):
        audit(source, target, draws=100)
