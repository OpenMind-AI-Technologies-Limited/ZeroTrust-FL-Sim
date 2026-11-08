"""CSV cybersecurity benchmark loader with train/test isolation and provenance.

No datasets are downloaded or synthesized here. The caller provides an actual
CSV file and declares its target, group and intentionally excluded columns.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler


@dataclass(frozen=True)
class PreparedTask:
    data: tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, int]
    metadata: dict


def _sha256_stream(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_csv(
    path: Path, *, label_column: str, seed: int,
    group_column: str | None = None,
    exclude_columns: tuple[str, ...] = (),
    test_fraction: float = 0.25,
) -> PreparedTask:
    """Fit imputation and scaling ONLY on train rows; exclude labels and groups."""
    path = Path(path)
    if not 0.0 < test_fraction < 1.0:
        raise ValueError("test_fraction must be in (0, 1)")
    frame = pd.read_csv(path, low_memory=False)
    if frame.empty:
        raise ValueError("dataset is empty")
    if label_column not in frame.columns:
        raise ValueError(f"missing label column: {label_column}")
    if group_column and group_column not in frame.columns:
        raise ValueError(f"missing group column: {group_column}")
    if frame[label_column].isna().any():
        raise ValueError("missing labels are not allowed")

    encoder = LabelEncoder()
    y = encoder.fit_transform(frame[label_column].astype(str).to_numpy()).astype(np.int64)
    if len(encoder.classes_) < 2:
        raise ValueError("classification benchmark needs at least two classes")
    dropped = {label_column, *exclude_columns}
    if group_column:
        dropped.add(group_column)
    unknown = set(exclude_columns) - set(frame.columns)
    if unknown:
        raise ValueError(f"unknown excluded columns: {sorted(unknown)}")
    features = [name for name in frame.columns if name not in dropped]
    if not features:
        raise ValueError("no input feature columns remain")
    try:
        numerical = frame[features].apply(pd.to_numeric, errors="raise")
    except ValueError as exc:
        raise ValueError(
            "non-numeric input feature: explicitly exclude identifiers and categorical text"
        ) from exc
    numerical = numerical.replace([np.inf, -np.inf], np.nan)
    if numerical.isna().all(axis=0).any():
        raise ValueError("a feature is entirely missing after numeric conversion")

    row_indices = np.arange(len(frame))
    if group_column:
        if frame[group_column].isna().any():
            raise ValueError("missing group IDs are not allowed")
        groups = frame[group_column].astype(str).to_numpy()
        if len(set(groups)) < 2:
            raise ValueError("need at least two distinct groups for held-out split")
        splitter = GroupShuffleSplit(
            n_splits=1, test_size=test_fraction, random_state=seed
        )
        train_idx, test_idx = next(splitter.split(row_indices, y, groups))
        if set(groups[train_idx]) & set(groups[test_idx]):
            raise AssertionError("group leakage across train/test boundary")
    else:
        train_idx, test_idx = train_test_split(
            row_indices, test_size=test_fraction, stratify=y, random_state=seed
        )
    observed_classes = set(np.unique(y))
    if set(y[train_idx]) != observed_classes or set(y[test_idx]) != observed_classes:
        raise ValueError(
            "train/test split is missing a class; use more groups/rows or change seed"
        )
    imputer = SimpleImputer(strategy="median")
    train_features = imputer.fit_transform(
        numerical.iloc[train_idx].to_numpy(dtype=np.float64)
    )
    test_features = imputer.transform(
        numerical.iloc[test_idx].to_numpy(dtype=np.float64)
    )
    scaler = StandardScaler().fit(train_features)
    xtr = scaler.transform(train_features)
    xte = scaler.transform(test_features)
    if not np.isfinite(xtr).all() or not np.isfinite(xte).all():
        raise ValueError("preprocessed features contain non-finite values")
    xtr = np.column_stack([xtr, np.ones(len(xtr))])
    xte = np.column_stack([xte, np.ones(len(xte))])
    return PreparedTask(
        data=(xtr, y[train_idx], xte, y[test_idx], len(encoder.classes_)),
        metadata={
            "dataset_file_name": path.name,
            "dataset_sha256": _sha256_stream(path),
            "label_column": label_column,
            "group_column": group_column,
            "excluded_columns": list(exclude_columns),
            "numeric_features": features,
            "class_names": encoder.classes_.tolist(),
            "train_rows": len(train_idx),
            "test_rows": len(test_idx),
            "split_seed": seed,
            "split_type": "group" if group_column else "stratified_random",
            "test_fraction": test_fraction,
            "warning": (
                "train/test preprocessing isolated; dataset provenance "
                "and label leakage require independent review"
            ),
        },
    )
