"""Tests deliberately fabricate structural rows, never manuscript evidence."""
import csv
import hashlib
import itertools
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from original_evidence_gate import audit
from reproduce import AGGREGATORS, DATASETS, FIELDS, PRIVACY_MODES, THREATS


def source_fixture(path: Path):
    raw=path/"FAKE_NOT_ORIGINAL.csv"
    with raw.open("w",newline="",encoding="utf-8") as stream:
        writer=csv.DictWriter(stream,fieldnames=FIELDS)
        writer.writeheader()
        for dataset,seed,method,privacy,threat in itertools.product(
            DATASETS,range(5),AGGREGATORS,PRIVACY_MODES,THREATS
        ):
            row=dict(dataset=dataset,seed=seed,aggregator=method,
                     privacy_mode=privacy,threat=threat,attacker_compliance="compliant",
                     rounds=20,n_clients=15,malicious_clients=3,
                     final_accuracy=.55,final_loss=.7)
            writer.writerow(row)
    meta=path/"FAKE_DECLARATIONS.json"
    meta.write_text(json.dumps({
        "manuscript_id":"CYSE-D-26-01608",
        "declared_original_author_run":True,
        "source_commit":"a"*40,
        "run_timestamp_utc":"2026-07-03T07:00:00Z",
        "dataset_versions":{k:"mock-dataset" for k in DATASETS},
        "raw_runs_sha256":hashlib.sha256(raw.read_bytes()).hexdigest(),
        "experiment_script_sha256":"b"*64,
    }),encoding="utf-8")
    return raw,meta


def test_only_structural_consistency_not_historical_attestation(tmp_path):
    raw,manifest=source_fixture(tmp_path)
    result=audit(raw,manifest)
    assert result["rows"]==720
    assert result["not_historical_authentication"] is True
    assert result["data_provenance_asserted_not_independently_verified"] is True


def test_missing_source_is_not_reconstructed(tmp_path):
    with pytest.raises(FileNotFoundError,match="NOT a substitute"):
        audit(tmp_path/"nonexistent.csv",tmp_path/"missing.json")


def test_checksum_changes_fail_before_any_result_validation(tmp_path):
    raw,manifest=source_fixture(tmp_path)
    with raw.open("a",encoding="utf-8") as stream:
        stream.write("edited\n")
    with pytest.raises(ValueError,match="SHA-256 mismatch"):
        audit(raw,manifest)


def test_disallow_unsubstantiated_historical_declaration(tmp_path):
    raw,manifest=source_fixture(tmp_path)
    content=json.loads(manifest.read_text())
    content["declared_original_author_run"]=False
    manifest.write_text(json.dumps(content))
    with pytest.raises(ValueError,match="original author run"):
        audit(raw,manifest)


def test_incomplete_factorial_grid_is_explicitly_rejected(tmp_path):
    raw,manifest=source_fixture(tmp_path)
    lines=raw.read_text().splitlines()
    raw.write_text("\n".join(lines[:-1])+"\n")
    info=json.loads(manifest.read_text())
    info["raw_runs_sha256"]=hashlib.sha256(raw.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(info))
    with pytest.raises(ValueError,match="incomplete factorial"):
        audit(raw,manifest)
