"""Synthetic contrast tests, NOT UNSW-NB15 experimental findings."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from unsw_interaction import analyze


def study_rows():
    rows = []
    for seed in range(5):
        for method in ("mean", "multi_krum"):
            for privacy in ("clip_only", "dp_1"):
                for policy in ("compliant", "bypass"):
                    excess = 0.
                    if policy == "bypass":
                        if method == "mean":
                            excess = 10. + seed
                        elif privacy == "dp_1":
                            excess = 30. + seed
                    rows.append({
                        "dataset": "UNSW-NB15", "seed": seed,
                        "aggregator": method, "privacy_mode": privacy,
                        "attacker_compliance": policy, "threat": "sign_flip",
                        "accuracy_drop_pp": excess,
                        "macro_f1_drop_pp": excess,
                        "balanced_accuracy_drop_pp": excess,
                    })
    return rows


def test_triple_interaction_detects_extra_dp_robustness_loss():
    results = analyze(study_rows(), draws=300)
    assert len(results) == 9
    estimates = {r["contrast"]: r for r in results if r["metric"] == "accuracy_drop_pp"}
    assert estimates["mean"]["mean_interaction_pp"] == pytest.approx(0.)
    assert estimates["multi_krum"]["mean_interaction_pp"] == pytest.approx(32.)
    assert estimates["multi_krum_minus_mean"]["mean_interaction_pp"] == pytest.approx(32.)
    for row in results:
        assert 0 <= row["holm_adjusted_p"] <= 1
        assert row["seed_bootstrap_95_low"] <= row["mean_interaction_pp"] <= row["seed_bootstrap_95_high"]


def test_triple_interaction_requires_complete_matched_grid():
    rows = study_rows()
    rows.pop()
    with pytest.raises(ValueError, match="missing complete"):
        analyze(rows, draws=100)


def test_triple_interaction_rejects_duplicate_conditions():
    rows = study_rows()
    rows.append(dict(rows[0]))
    with pytest.raises(ValueError, match="duplicate paired"):
        analyze(rows, draws=100)
