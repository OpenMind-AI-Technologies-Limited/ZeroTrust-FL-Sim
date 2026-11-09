"""Regression tests for publicly known plaintext Byzantine baselines."""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from robust_baselines import (
    EXTENSION_AGGREGATORS, aggregate_extended, geometric_median, project_l2,
)
from reproduce import AGGREGATORS, Config, run_case


def test_geometric_median_is_translation_equivariant():
    vectors = np.asarray(
        [[-1., 0.], [0., 1.], [1., 0.], [0., -1.], [1e3, 1e3]]
    )
    median = geometric_median(vectors)
    shifted = geometric_median(vectors + [17., -23.])
    np.testing.assert_allclose(shifted, median + [17., -23.], atol=1e-5)
    assert np.linalg.norm(median) < 2.0


def test_server_norm_cap_handles_enormous_finite_attacker_vectors():
    updates = np.asarray([[1e300, -1e300], [0.03, 0.04], [0., 0.]])
    bounded = project_l2(updates, cap=0.1)
    assert np.isfinite(bounded).all()
    assert max(np.linalg.norm(bounded, axis=1)) <= .1*(1+1e-12)
    np.testing.assert_allclose(bounded[1], updates[1])
    np.testing.assert_allclose(bounded[2], [0, 0])


@pytest.mark.parametrize("bad", [
    np.array([[1., 2.], [np.inf, 0.]]),
    np.array([[0.], [np.nan]]),
    np.ones((3, 2, 1)),
    np.ones((1, 3)),
])
def test_untrusted_client_payload_fails_closed(bad):
    with pytest.raises(ValueError):
        project_l2(bad, .1)


def test_server_clip_enforces_bounded_aggregation():
    updates = np.vstack([np.ones((12, 4))*.01, np.ones((3, 4))*1000])
    cfg = Config()
    for method in ("server_clipped_mean", "server_clipped_rfa", "server_clipped_multi_krum"):
        merged = aggregate_extended(
            updates, method, cap=.1,
            multi_krum_callback=lambda x: x[:cfg.multi_krum_k].mean(axis=0)
        )
        assert np.linalg.norm(merged) <= .1*(1+1e-10)


def test_no_implicit_encrypted_filtering_claim_or_fallback():
    vectors = np.ones((15, 3))
    with pytest.raises(ValueError, match="unknown"):
        aggregate_extended(vectors, "ckks_secure_multi_krum", cap=.1)
    with pytest.raises(ValueError, match="explicitly provided"):
        aggregate_extended(vectors, "server_clipped_multi_krum", cap=.1)
    with pytest.raises(ValueError, match="positive"):
        project_l2(vectors, 0.)


def test_extension_is_separate_from_original_720_run_aggregators():
    assert len(AGGREGATORS) == 4
    assert "server_clipped_rfa" in EXTENSION_AGGREGATORS
    assert not set(AGGREGATORS) & set(EXTENSION_AGGREGATORS)
    cfg = Config(rounds=3, partition="iid")
    for method in EXTENSION_AGGREGATORS:
        result = run_case(
            "breast_cancer", 1, method, "dp_1", "sign_flip",
            cfg, include_classification_metrics=True
        )
        assert 0 <= result["final_accuracy"] <= 1
        assert 0 <= result["macro_f1"] <= 1
        assert np.isfinite(result["final_loss"])


def test_known_reference_grid_unchanged_by_adding_optional_baselines():
    from reproduce import aggregate, FIELDS
    cfg = Config(rounds=2)
    base = run_case("breast_cancer", 0, "multi_krum", "dp_1", "sign_flip", cfg)
    assert set(base) == set(FIELDS)
    np.testing.assert_allclose(aggregate(np.zeros((15, 3)), "multi_krum", cfg), 0)



def test_server_bounded_mean_adversarial_influence_lemma():
    """With f replaced clients, projected mean differs by at most 2*f*C/n."""
    n, f, cap = 15, 3, .1
    honest = np.zeros((n-f, 4))
    adversary_one = np.zeros((f, 4))
    adversary_two = np.zeros((f, 4))
    adversary_one[:, 0] = 1e8
    adversary_two[:, 0] = -1e8
    first = aggregate_extended(
        np.concatenate([honest, adversary_one]), "server_clipped_mean", cap=cap
    )
    second = aggregate_extended(
        np.concatenate([honest, adversary_two]), "server_clipped_mean", cap=cap
    )
    observed = np.linalg.norm(first-second)
    assert observed <= 2.*f*cap/n + 1e-12
    assert observed == pytest.approx(2.*f*cap/n, abs=1e-12)
