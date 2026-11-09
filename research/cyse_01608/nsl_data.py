"""NSL-KDD legacy intrusion benchmark: isolated publisher train/test preprocessing.

The UNB/ISCX original dataset is no longer downloadable from its original
hosting page. A mirrored source is pinned to an exact Git commit / blob hashes.
Never claim this 2009-era dataset represents modern network traffic.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from unsw_data import verify_file

MIRROR_REPOSITORY = "Jehuty4949/NSL_KDD"
MIRROR_COMMIT = "27bbbdf5c5cccf9970b8b6037a0f19dc09c5a0a9"
EXPECTED_GIT_BLOBS = {
    "train": "20002897492adc110190a10509aa694f26f7f308",
    "test": "b30e89605285a5ccd8cf8fd38dba72906c20d3dd",
}
TRAIN_ROWS = 125973
TEST_ROWS = 22544
NUM_FIELDS = 43
CATEGORICAL_POSITIONS = (1, 2, 3)
LABEL_POSITION = 41
DIFFICULTY_POSITION = 42


def _read(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path, header=None, low_memory=False)
    if frame.shape[1] != NUM_FIELDS:
        raise ValueError(f"NSL-KDD expected 43 fields; got {frame.shape[1]}")
    if frame.empty or frame.isna().all(axis=1).any():
        raise ValueError("NSL-KDD has empty rows")
    return frame


def _sample(frame: pd.DataFrame, labels: np.ndarray,
            maximum: int | None, seed: int) -> tuple[pd.DataFrame, np.ndarray]:
    if maximum is None or maximum >= len(frame):
        return frame, labels
    if maximum < 2:
        raise ValueError("sample size must be >=2")
    picks, _ = train_test_split(
        np.arange(len(frame)), train_size=maximum,
        stratify=labels, random_state=seed,
    )
    picks = np.sort(picks)
    return frame.iloc[picks], labels[picks]


def prepare_nsl(
    train_path: Path, test_path: Path, *, seed: int,
    train_limit: int | None = 6000, test_limit: int | None = 3000,
    expected_train_blob: str | None = EXPECTED_GIT_BLOBS["train"],
    expected_test_blob: str | None = EXPECTED_GIT_BLOBS["test"],
    require_standard_counts: bool = True,
) -> tuple[tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, int], dict]:
    fingerprints = {
        "train": verify_file(train_path, expected_train_blob),
        "test": verify_file(test_path, expected_test_blob),
    }
    raw_train = _read(train_path)
    raw_test = _read(test_path)
    if require_standard_counts and (len(raw_train), len(raw_test)) != (TRAIN_ROWS, TEST_ROWS):
        raise ValueError("unexpected NSL-KDD publisher train/test row counts")

    def encode_label(frame: pd.DataFrame) -> np.ndarray:
        series = frame[LABEL_POSITION]
        if series.isna().any():
            raise ValueError("NSL-KDD has missing attack labels")
        names = series.astype(str).str.strip().str.lower()
        return (names != "normal").to_numpy(dtype=np.int64)

    labels_train = encode_label(raw_train)
    labels_test = encode_label(raw_test)
    train, y_train = _sample(raw_train, labels_train, train_limit, seed)
    test, y_test = _sample(raw_test, labels_test, test_limit, seed + 7511)

    if set(np.unique(y_train)) != {0, 1} or set(np.unique(y_test)) != {0, 1}:
        raise ValueError("both split samples must contain normal and attack classes")
    numeric_positions = [i for i in range(41) if i not in CATEGORICAL_POSITIONS]
    numeric_train = train[numeric_positions].apply(
        pd.to_numeric, errors="raise"
    ).replace([np.inf, -np.inf], np.nan).to_numpy(dtype=np.float64)
    numeric_test = test[numeric_positions].apply(
        pd.to_numeric, errors="raise"
    ).replace([np.inf, -np.inf], np.nan).to_numpy(dtype=np.float64)
    if np.isnan(numeric_train).all(axis=0).any():
        raise ValueError("all-missing numeric training feature")

    imputer = SimpleImputer(strategy="median")
    numeric_train = imputer.fit_transform(numeric_train)
    numeric_test = imputer.transform(numeric_test)
    scaler = StandardScaler()
    train_numeric = scaler.fit_transform(numeric_train)
    test_numeric = scaler.transform(numeric_test)

    def cat(frame: pd.DataFrame) -> pd.DataFrame:
        return frame[list(CATEGORICAL_POSITIONS)].fillna("__MISSING__").astype(str)

    one_hot = OneHotEncoder(handle_unknown="ignore", sparse_output=False, dtype=np.float64)
    train_cat = one_hot.fit_transform(cat(train))
    test_cat = one_hot.transform(cat(test))
    x_train = np.column_stack([train_numeric, train_cat, np.ones(len(train))])
    x_test = np.column_stack([test_numeric, test_cat, np.ones(len(test))])
    if not np.isfinite(x_train).all() or not np.isfinite(x_test).all():
        raise ValueError("non-finite transformed features")

    original_train_attack_types = set(
        raw_train[LABEL_POSITION].astype(str).str.strip().str.lower().unique()
    )
    original_test_attack_types = set(
        raw_test[LABEL_POSITION].astype(str).str.strip().str.lower().unique()
    )
    metadata = {
        "dataset": "NSL-KDD publisher train KDDTrain+ and test KDDTest+ (legacy 2009-era traffic)",
        "publisher_status": "original University of New Brunswick source no longer downloadable",
        "original_publisher_page": "https://www.unb.ca/cic/datasets/nsl.html",
        "mirror": f"https://github.com/{MIRROR_REPOSITORY}/tree/{MIRROR_COMMIT}",
        "mirror_commit": MIRROR_COMMIT,
        "source_files": fingerprints,
        "seed": seed,
        "published_train_rows": len(raw_train),
        "published_test_rows": len(raw_test),
        "sampled_train": len(train),
        "sampled_test": len(test),
        "train_class_counts": np.bincount(y_train, minlength=2).tolist(),
        "test_class_counts": np.bincount(y_test, minlength=2).tolist(),
        "train_limit": train_limit, "test_limit": test_limit,
        "numeric_feature_count": len(numeric_positions),
        "categorical_feature_positions": list(CATEGORICAL_POSITIONS),
        "encoded_feature_count": int(x_train.shape[1] - 1),
        "excluded_fields": ["attack_label", "difficulty"],
        "test_attack_types_unseen_in_train": sorted(
            original_test_attack_types - original_train_attack_types
        ),
        "protocol": "fixed original KDDTrain+ / KDDTest+ split, no test-to-train transfer",
        "preprocessing": "train-only numeric median imputation, standard scaling and categorical OHE",
        "limitations": [
            "NSL-KDD is old and does not represent present-day operational network telemetry.",
            "NSL-KDD has no host/device group identifier; possible flow or identity overlap requires separate auditing.",
            "The mirror is non-authoritative; source identity is pinned and checked but publisher originals are offline.",
            "Test contains some attack types absent from train. The benchmark tests binary attack presence, not attribution.",
        ],
    }
    return (x_train, y_train, x_test, y_test, 2), metadata
