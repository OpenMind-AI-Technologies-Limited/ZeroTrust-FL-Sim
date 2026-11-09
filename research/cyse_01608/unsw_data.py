"""Prepare the official UNSW-NB15 train/test split without train/test leakage.

The official dataset is copyright UNSW and is free for academic research.
This module never redistributes records. Use a pinned dataset mirror and
verify Git blob SHA-1 before assigning provenance to a downloaded file.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler

MIRROR_COMMIT = "44bbd02b9e70f74dd915218d5eb702f125341ffc"
EXPECTED_GIT_BLOBS = {
    "train": "c8226c710f99228ee3ac60d3ef5a610677e3c36d",
    "test": "5a120da5e21fa6b0f90ad54ab22027f29c8ad2df",
}
CATEGORICAL = ("proto", "service", "state")
DROP = ("id", "attack_cat", "label")


def verify_file(path: Path, expected_git_blob: str | None) -> dict:
    """Check a Git content blob SHA-1 and record SHA-256 for audit.

    A Git SHA-1 validates the exact blob against the pinned Git commit; it is
    not a claim of collision-resistant security against an active adversary.
    The stronger SHA-256 digest is recorded independently in the manifest.
    """
    path = Path(path)
    size = path.stat().st_size
    git_hash = hashlib.sha1(b"blob " + str(size).encode("ascii") + b"\0")
    sha256 = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            git_hash.update(chunk)
            sha256.update(chunk)
    actual = git_hash.hexdigest()
    if expected_git_blob is not None and actual != expected_git_blob:
        raise ValueError(f"Git blob SHA mismatch for {path.name}: {actual}")
    return {
        "filename": path.name,
        "size_bytes": size,
        "git_blob_sha1": actual,
        "sha256": sha256.hexdigest(),
    }


def _sample(frame: pd.DataFrame, limit: int | None, seed: int) -> pd.DataFrame:
    if limit is None:
        return frame
    if limit < 2:
        raise ValueError("sample limit must be at least 2")
    if limit >= len(frame):
        return frame
    selected, _ = train_test_split(
        np.arange(len(frame)), train_size=limit,
        random_state=seed, stratify=frame["label"].to_numpy()
    )
    return frame.iloc[np.sort(selected)].copy()


def prepare_unsw(
    train_csv: Path,
    test_csv: Path,
    *,
    seed: int,
    train_limit: int | None = None,
    test_limit: int | None = None,
    expected_train_blob: str | None = EXPECTED_GIT_BLOBS["train"],
    expected_test_blob: str | None = EXPECTED_GIT_BLOBS["test"],
    require_official_row_counts: bool = True,
) -> tuple[tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, int], dict]:
    """Use the publisher's held-out test set, never re-split it into training."""
    provenance = {
        "train": verify_file(train_csv, expected_train_blob),
        "test": verify_file(test_csv, expected_test_blob),
    }
    raw_train, raw_test = pd.read_csv(train_csv), pd.read_csv(test_csv)
    if require_official_row_counts and (len(raw_train), len(raw_test)) != (175341, 82332):
        raise ValueError("unexpected official UNSW-NB15 train/test row counts")
    if set(raw_train.columns) != set(raw_test.columns):
        raise ValueError("train/test column schemas differ")
    if not {"id", "attack_cat", "label", *CATEGORICAL}.issubset(raw_train.columns):
        raise ValueError("missing required UNSW-NB15 features or target")
    numeric_names = [c for c in raw_train.columns if c not in {*DROP, *CATEGORICAL}]
    if not numeric_names:
        raise ValueError("no numerical input features remain")

    # Sampling, if requested for resource-limited experiments, happens within
    # each official split. The held-out rows never enter the training pipeline.
    train = _sample(raw_train, train_limit, seed)
    test = _sample(raw_test, test_limit, seed + 1741)
    ytr = pd.to_numeric(train["label"], errors="raise").to_numpy(dtype=np.int64)
    yte = pd.to_numeric(test["label"], errors="raise").to_numpy(dtype=np.int64)
    if set(np.unique(ytr)) != {0, 1} or set(np.unique(yte)) != {0, 1}:
        raise ValueError("both official splits must contain benign (0) and attack (1) labels")

    def numeric(frame: pd.DataFrame) -> np.ndarray:
        return frame[numeric_names].apply(
            pd.to_numeric, errors="raise"
        ).replace([np.inf, -np.inf], np.nan).to_numpy(dtype=np.float64)

    train_numeric, test_numeric = numeric(train), numeric(test)
    if np.isnan(train_numeric).all(axis=0).any():
        raise ValueError("training sample includes an entirely missing numeric feature")
    imputer = SimpleImputer(strategy="median")
    train_numeric = imputer.fit_transform(train_numeric)
    test_numeric = imputer.transform(test_numeric)
    scaler = StandardScaler()
    train_scaled = scaler.fit_transform(train_numeric)
    test_scaled = scaler.transform(test_numeric)

    train_cat = train[list(CATEGORICAL)].fillna("__MISSING__").astype(str)
    test_cat = test[list(CATEGORICAL)].fillna("__MISSING__").astype(str)
    encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False, dtype=np.float64)
    train_encoded = encoder.fit_transform(train_cat)
    test_encoded = encoder.transform(test_cat)
    xtr = np.column_stack([train_scaled, train_encoded, np.ones(len(train))])
    xte = np.column_stack([test_scaled, test_encoded, np.ones(len(test))])
    if not np.isfinite(xtr).all() or not np.isfinite(xte).all():
        raise ValueError("non-finite model features after preprocessing")

    source_names = numeric_names + encoder.get_feature_names_out(CATEGORICAL).tolist()
    metadata = {
        "dataset": "UNSW-NB15 official publisher train/test split",
        "source": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "mirror_commit": MIRROR_COMMIT,
        "files": provenance,
        "seed": seed,
        "sampled_train": len(train),
        "sampled_test": len(test),
        "train_limit": train_limit,
        "test_limit": test_limit,
        "train_binary_class_counts": np.bincount(ytr, minlength=2).tolist(),
        "test_binary_class_counts": np.bincount(yte, minlength=2).tolist(),
        "heldout_protocol": "official training-set versus testing-set, no random resplit",
        "excluded_label_leakage": ["id", "attack_cat"],
        "categorical_features": list(CATEGORICAL),
        "numeric_features": numeric_names,
        "encoded_feature_count": len(source_names),
        "preprocessing": "train-only median imputation, standard scaling and one-hot vocabulary",
        "caveat": "Academic-use dataset; sampled evaluation is not full-dataset SOTA comparison. Cross-split duplication and environment shift require separate audits.",
    }
    return (xtr, ytr, xte, yte, 2), metadata
