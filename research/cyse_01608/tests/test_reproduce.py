"""Regression checks for the independent CYSE-01608 study design."""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reproduce import (AGGREGATORS, DATASETS, PRIVACY_MODES, THREATS, Config,
                       aggregate, epsilon_gaussian, generate, load_task,
                       partition_indices, run_case)


def test_matrix_is_exactly_720():
    assert len(DATASETS)*5*len(AGGREGATORS)*len(PRIVACY_MODES)*len(THREATS)==720
    assert 720*20 == 14400


@pytest.mark.parametrize("sigma,expected", [(0.5,83.03),(1,31.51),(2,13.26),(4,6.00)])
def test_rdp_published_accounting_numbers(sigma, expected):
    assert epsilon_gaussian(sigma, 20, 1e-5) == pytest.approx(expected, abs=.006)


def test_aggregate_ignores_malicious_large_outliers():
    config=Config()
    honest=np.zeros((12, 4))
    malicious=np.ones((3, 4))*10000
    values=np.vstack([honest,malicious])
    assert aggregate(values, "mean", config).max()>0
    for method in ("median", "trimmed_mean", "multi_krum"):
        np.testing.assert_allclose(aggregate(values, method, config), 0)


def test_disjoint_stratified_partition():
    cfg=Config()
    _,y,_,_,_=load_task("digits", 1, cfg)
    p=partition_indices(y, 1, cfg)
    assert len(p)==15 and all(len(i)>0 for i in p)
    assert sorted(np.concatenate(p).tolist())==list(range(len(y)))


def test_non_iid_is_valid_disjoint_and_seeded():
    cfg=Config(partition="dirichlet", alpha=.3)
    _,y,_,_,_=load_task("digits", 1, cfg)
    a=partition_indices(y, 1, cfg)
    b=partition_indices(y, 1, cfg)
    assert all(np.array_equal(x,y) for x,y in zip(a,b))
    assert sorted(np.concatenate(a).tolist())==list(range(len(y)))


def test_paired_noise_and_bypass_are_distinct():
    config=Config(rounds=3)
    args=("breast_cancer", 0, "mean", "dp_1", "sign_flip")
    first=run_case(*args,config)
    again=run_case(*args,config)
    bypass=run_case(*args,Config(rounds=3, attacker_compliance="bypass"))
    assert first == again
    assert first["attacker_compliance"]=="compliant"
    assert bypass["attacker_compliance"]=="bypass"
    assert first["final_accuracy"] != bypass["final_accuracy"]


def test_smoke_creates_matched_and_hashed_artifacts(tmp_path):
    cfg=Config(rounds=2)
    m=generate(tmp_path,("breast_cancer",),(0,), ("mean",),
               ("none","dp_1"),("benign","sign_flip"),cfg)
    assert m["run_count"]==4 and m["total_rounds"]==8
    assert len((tmp_path/"runs.csv").read_text().splitlines())==5
    assert len((tmp_path/"paired.csv").read_text().splitlines())==3
    assert (tmp_path/"manifest.json").is_file()


def test_holm_adjust_monotone_and_bounded():
    from security_analysis import holm_adjust
    p = holm_adjust([0.04, 0.001, 0.1])
    assert p == pytest.approx([0.08, 0.003, 0.1])


def test_stratified_bootstrap_handles_degenerate_results():
    from security_analysis import stratified_bootstrap_ci
    assert stratified_bootstrap_ci({'a':[0.,0.], 'b':[0.,0.]}, draws=50) == (0.,0.)



def test_oracle_alie_baseline_is_not_part_of_original_threat_grid():
    from reproduce import EXTENSION_THREATS, THREATS, alie_oracle_update

    assert "alie_oracle" not in THREATS
    assert "alie_oracle" in EXTENSION_THREATS
    honest = np.array([[1.0, 0.0], [3.0, 4.0]])
    np.testing.assert_allclose(
        alie_oracle_update(honest, factor=1.5), [0.5, -1.0]
    )
    with pytest.raises(ValueError):
        alie_oracle_update(honest, factor=-1.0)
    cfg = Config(rounds=3)
    baseline = run_case("breast_cancer", 0, "mean", "dp_1", "benign", cfg)
    attacked = run_case("breast_cancer", 0, "mean", "dp_1", "alie_oracle", cfg)
    assert 0 <= baseline["final_accuracy"] <= 1
    assert 0 <= attacked["final_accuracy"] <= 1
    assert attacked["threat"] == "alie_oracle"
