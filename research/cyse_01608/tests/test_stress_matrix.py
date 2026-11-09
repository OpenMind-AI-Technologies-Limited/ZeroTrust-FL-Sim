"""Regression checks for the exploratory security stress grid."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stress_matrix import sweep


def test_stress_matrix_creates_paired_records(tmp_path):
    manifest = sweep(
        output=tmp_path, datasets=("breast_cancer",), seeds=(0,),
        partitions=("iid", "dirichlet"), alphas=(0.3,),
        malicious_counts=(1, 3), aggregators=("mean",),
        modes=("dp_1",), threats=("sign_flip",),
        compliance=("compliant", "bypass"), rounds=2,
    )
    assert manifest["scenarios"] == 8
    assert manifest["executed_runs"] == 16
    assert manifest["total_rounds"] == 32
    assert len((tmp_path / "stress_pairs.csv").read_text().splitlines()) == 9
    assert (tmp_path / "stress_summary.csv").is_file()
    assert (tmp_path / "stress_manifest.json").is_file()


def test_threshold_requires_positive_value(tmp_path):
    with pytest.raises(ValueError, match="threshold"):
        sweep(
            output=tmp_path, datasets=("digits",), seeds=(0,),
            partitions=("iid",), alphas=(0.3,),
            malicious_counts=(1,), aggregators=("mean",),
            modes=("clip_only",), threats=("sign_flip",),
            compliance=("bypass",), rounds=1,
            failure_threshold_pp=0,
        )


def test_krum_invalid_fault_bound_fails_closed(tmp_path):
    with pytest.raises(ValueError, match="Krum requires"):
        sweep(
            output=tmp_path, datasets=("breast_cancer",), seeds=(0,),
            partitions=("iid",), alphas=(0.3,),
            malicious_counts=(7,), aggregators=("multi_krum",),
            modes=("clip_only",), threats=("sign_flip",),
            compliance=("bypass",), rounds=1,
        )
