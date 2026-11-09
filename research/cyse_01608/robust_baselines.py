"""Additional *plaintext* Byzantine aggregation baselines for CYSE-01608.

- RFA geometric median approximated by smoothed Weiszfeld (known prior art).
- Server-enforced norm projection after receiving client update bytes.
- This module is deliberately NOT a CKKS-encrypted Byzantine filter.
- Enforcement on post-local-DP releases is postprocessing but requires the
  server to see the plaintext/noisy vector and authentic client identity.
"""
from __future__ import annotations

import math
import numpy as np

EXTENSION_AGGREGATORS = (
    "rfa",
    "server_clipped_mean",
    "server_clipped_rfa",
    "server_clipped_multi_krum",
)


def _validate(updates: np.ndarray) -> np.ndarray:
    data = np.asarray(updates, dtype=np.float64)
    if data.ndim != 2 or data.shape[0] < 2 or data.shape[1] < 1:
        raise ValueError("expected [at least two clients, nonempty vector]")
    if not np.isfinite(data).all():
        raise ValueError("untrusted updates must contain only finite numbers")
    return data


def project_l2(updates: np.ndarray, cap: float) -> np.ndarray:
    """Enforce a SERVER-SIDE L2 cap on every update, including Byzantine clients.

    Only protects the *magnitude* of observed plaintext update vectors.
    It does not verify that an attacker followed client-side Gaussian DP,
    and it is not usable on semantically opaque CKKS ciphertext vectors.
    """
    if not math.isfinite(cap) or cap <= 0:
        raise ValueError("cap must be positive and finite")
    data = _validate(updates)
    # Normalize each row before computing Euclidean norm to avoid squaring
    # arbitrary large attacker-controlled finite floats.
    maxima = np.max(np.abs(data), axis=1, keepdims=True)
    safe_max = np.where(maxima == 0, 1., maxima)
    units = data / safe_max
    unit_norms = np.linalg.norm(units, axis=1, keepdims=True)
    norms = maxima * unit_norms
    # When the mathematical norm overflows float64, unit directions are still
    # known. Divide the unit row by its norm, then scale to cap.
    protected = np.empty_like(data)
    clipped = (norms > cap) | ~np.isfinite(norms)
    np.copyto(protected, data)
    idx = clipped[:, 0]
    if np.any(idx):
        protected[idx] = cap * (units[idx] / unit_norms[idx])
    # Tolerate only round-off, not arbitrary cap violations.
    if np.any(np.linalg.norm(protected, axis=1) > cap*(1+1e-12)):
        raise AssertionError("server clipping failed to enforce update norm cap")
    return protected


def geometric_median(
    updates: np.ndarray, *, max_iterations: int = 80,
    tolerance: float = 1e-9, smoothing: float = 1e-7,
) -> np.ndarray:
    """RFA-style, unweighted smoothed Weiszfeld geometric median approximation.

    The returned vector is a convex combination of the received points.
    It is a known robust-estimation baseline, not a new contribution.
    """
    data = _validate(updates)
    if max_iterations < 1:
        raise ValueError("max_iterations must be positive")
    if (not math.isfinite(tolerance) or tolerance <= 0 or
            not math.isfinite(smoothing) or smoothing <= 0):
        raise ValueError("smoothing and tolerance must be finite and positive")
    current = data.mean(axis=0)
    for _ in range(max_iterations):
        # Center first and normalize distances for numerical robustness.
        dist = np.linalg.norm(data - current, axis=1)
        if not np.isfinite(dist).all():
            raise ValueError("distances overflowed; apply server clipping first")
        inv_dist = 1.0 / np.maximum(dist, smoothing)
        new = np.average(data, axis=0, weights=inv_dist)
        if np.linalg.norm(new - current) <= tolerance*(1+np.linalg.norm(current)):
            return new
        current = new
    return current


def aggregate_extended(
    updates: np.ndarray, method: str, *, cap: float,
    multi_krum_callback=None,
) -> np.ndarray:
    """Select an explicit transparent baseline. No hidden fallback."""
    if method not in EXTENSION_AGGREGATORS:
        raise ValueError("unknown robust extension method")
    vectors = _validate(updates)
    if method.startswith("server_clipped_"):
        vectors = project_l2(vectors, cap)
    if method in ("rfa", "server_clipped_rfa"):
        return geometric_median(vectors)
    if method == "server_clipped_mean":
        return vectors.mean(axis=0)
    if method == "server_clipped_multi_krum":
        if multi_krum_callback is None:
            raise ValueError("Multi-Krum callback must be explicitly provided")
        return multi_krum_callback(vectors)
    raise AssertionError("unreachable aggregator state")
