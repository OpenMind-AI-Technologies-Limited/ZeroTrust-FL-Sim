"""Cross-study inference tests use fabricated fixtures, not experimental results."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cross_dataset_compare import compare


def mock(dataset: str, multi_privacy_excess: float):
    rows=[]
    for seed in range(5):
        for agg in ("mean","multi_krum"):
            for mode in ("clip_only","dp_1"):
                for policy in ("compliant","bypass"):
                    value=5.0
                    if policy=="bypass":
                        value=10.0
                        if agg=="multi_krum" and mode=="dp_1":
                            value+=multi_privacy_excess
                    rows.append({
                        "dataset":dataset,"seed":seed,"aggregator":agg,
                        "privacy_mode":mode,"attacker_compliance":policy,
                        "threat":"sign_flip",
                        "accuracy_drop_pp":value,
                        "macro_f1_drop_pp":value,
                        "balanced_accuracy_drop_pp":value,
                    })
    return rows


def test_paired_two_dataset_interaction_and_equal_weight():
    effects,summary=compare(
        mock("UNSW-NB15",10),mock("NSL-KDD",20),draws=300
    )
    assert len(effects)==30 and len(summary)==9
    found={r["dataset"]:r for r in summary if r["metric"]=="accuracy_drop_pp"}
    assert found["UNSW-NB15"]["mean_triple_interaction_pp"]==pytest.approx(10)
    assert found["NSL-KDD"]["mean_triple_interaction_pp"]==pytest.approx(20)
    assert found["EQUAL_WEIGHT_TWO_DATASETS"]["mean_triple_interaction_pp"]==pytest.approx(15)
    assert all(r["positive_seed_fraction"]==1. for r in found.values())


def test_missing_cases_cannot_be_silently_dropped():
    x=mock("UNSW-NB15",10)
    x.pop()
    with pytest.raises(ValueError,match="missing or extra"):
        compare(x,mock("NSL-KDD",20),draws=100)


def test_mismatched_seeds_rejected():
    x=mock("UNSW-NB15",10)
    y=mock("NSL-KDD",20)
    for row in y:
        if row["seed"]==4: row["seed"]=9
    with pytest.raises(ValueError,match="not aligned"):
        compare(x,y,draws=100)
