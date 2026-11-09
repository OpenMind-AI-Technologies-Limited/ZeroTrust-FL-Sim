import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stress_inference import analyze


def test_matched_stress_inference():
    cases = []
    for dataset in ("a", "b"):
        for seed in range(3):
            for compliance, degradation in (("compliant", 5.0), ("bypass", 20.0 + seed)):
                cases.append(dict(
                    dataset=dataset, seed=seed, partition="iid",
                    alpha="", malicious_clients=3, aggregator="mean",
                    privacy_mode="dp_1", threat="sign_flip",
                    attacker_compliance=compliance, accuracy_drop_pp=degradation,
                ))
    results = analyze(cases)
    assert len(results) == 1
    assert results[0]["observations"] == 6
    assert results[0]["mean_excess_degradation_pp"] == pytest.approx(16.0)
    assert results[0]["stratified_bootstrap_ci_low"] <= 16 <= results[0]["stratified_bootstrap_ci_high"]


def test_missing_paired_case_rejected():
    with pytest.raises(ValueError, match="missing paired"):
        analyze([dict(
            dataset="a", seed=0, partition="iid", alpha="",
            malicious_clients=3, aggregator="mean", privacy_mode="dp_1",
            threat="sign_flip", attacker_compliance="bypass",
            accuracy_drop_pp=15.0,
        )])
