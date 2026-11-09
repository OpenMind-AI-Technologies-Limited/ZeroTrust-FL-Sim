"""Fail-closed structural/provenance gate for CYSE-D-26-01608 original raw runs.

This tool NEVER reconstructs or substitutes missing original author data.
User-supplied provenance declarations are checked but NOT independently attested;
checking a manifest is not proof of the historical run's authenticity.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
import re
from pathlib import Path

from reproduce import AGGREGATORS, DATASETS, FIELDS, PRIVACY_MODES, THREATS

EXPECTED = set(itertools.product(DATASETS, range(5), AGGREGATORS, PRIVACY_MODES, THREATS))
IDENTITY_FIELDS = ("dataset", "seed", "aggregator", "privacy_mode", "threat")
REQUIRED_PROVENANCE = (
    "manuscript_id", "declared_original_author_run",
    "source_commit", "run_timestamp_utc", "dataset_versions",
    "raw_runs_sha256", "experiment_script_sha256",
)


def sha256(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024*1024), b""):
            digest.update(block)
    return digest.hexdigest()


def audit(raw: Path, provenance: Path, *,
          comparison: Path | None = None) -> dict:
    if not raw.is_file() or not provenance.is_file():
        raise FileNotFoundError(
            "Original author-run CSV and historical provenance manifest "
            "are required. An independent rerun is NOT a substitute."
        )
    meta=json.loads(provenance.read_text(encoding="utf-8"))
    missing=[name for name in REQUIRED_PROVENANCE if name not in meta]
    if missing:
        raise ValueError(f"missing historical provenance declarations: {missing}")
    if meta["manuscript_id"]!="CYSE-D-26-01608" or meta["declared_original_author_run"] is not True:
        raise ValueError("manifest must explicitly identify the original author run")
    if not re.fullmatch(r"[0-9a-f]{40}",str(meta["source_commit"])):
        raise ValueError("source_commit must be a full 40-character source commit SHA")
    if not re.fullmatch(r"[0-9a-f]{64}",str(meta["experiment_script_sha256"])):
        raise ValueError("experiment_script_sha256 must be a full 64-character checksum")
    if not isinstance(meta["dataset_versions"],dict) or set(meta["dataset_versions"])!=set(DATASETS):
        raise ValueError("dataset version metadata must cover both original tasks")
    if not isinstance(meta["run_timestamp_utc"],str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",meta["run_timestamp_utc"]
    ):
        raise ValueError("original run timestamp must be UTC YYYY-MM-DDTHH:MM:SSZ")
    digest=sha256(raw)
    if digest!=meta["raw_runs_sha256"]:
        raise ValueError("original raw-run SHA-256 mismatch")
    with raw.open(newline="",encoding="utf-8") as stream:
        reader=csv.DictReader(stream)
        if not set(FIELDS).issubset(reader.fieldnames or []):
            raise ValueError("original CSV lacks mandatory result and condition fields")
        actual={}
        for row in reader:
            identity=(row["dataset"],int(row["seed"]),row["aggregator"],
                      row["privacy_mode"],row["threat"])
            if identity not in EXPECTED:
                raise ValueError(f"unexpected original experiment condition {identity}")
            if identity in actual:
                raise ValueError(f"duplicate original experiment condition {identity}")
            if row["attacker_compliance"]!="compliant" or int(row["n_clients"])!=15:
                raise ValueError("row does not match submitted compliant 15-client design")
            if int(row["rounds"])!=20 or int(row["malicious_clients"])!=3:
                raise ValueError("original round/adversarial count differs from submitted design")
            accuracy=float(row["final_accuracy"])
            loss=float(row["final_loss"])
            if not (math.isfinite(accuracy) and 0<=accuracy<=1
                    and math.isfinite(loss) and loss>=0):
                raise ValueError("nonfinite or out-of-range outcome")
            actual[identity]={"accuracy":accuracy,"loss":loss}
    if set(actual)!=EXPECTED:
        raise ValueError(f"incomplete factorial grid: expected 720, found {len(actual)}")

    report={
        "status":"STRUCTURE_MATCHES_DECLARED_ORIGINAL_DESIGN",
        "not_historical_authentication":True,
        "raw_sha256":digest,
        "rows":len(actual),
        "declared_source_commit":meta["source_commit"],
        "declared_run_timestamp_utc":meta["run_timestamp_utc"],
        "data_provenance_asserted_not_independently_verified":True,
        "warning":"No software can prove a historical experiment occurred solely from a self-declared manifest. Reconcile with independently held original raw files and submission history."
    }
    if comparison is not None:
        if not comparison.is_file():
            raise FileNotFoundError("independent comparison CSV not supplied")
        ref={}
        with comparison.open(newline="",encoding="utf-8") as f:
            for row in csv.DictReader(f):
                key=(row["dataset"],int(row["seed"]),row["aggregator"],
                     row["privacy_mode"],row["threat"])
                if key in ref:
                    raise ValueError("duplicate reconstruction condition")
                ref[key]=float(row["final_accuracy"])
        if set(ref)!=EXPECTED:
            raise ValueError("comparison CSV must have all 720 original-design cases")
        differences={str(k):abs(v["accuracy"]-ref[k]) for k,v in actual.items()}
        report["comparison_sha256"]=sha256(comparison)
        report["comparison_mean_abs_accuracy_pp"]=100*sum(differences.values())/len(differences)
        report["comparison_max_abs_accuracy_pp"]=100*max(differences.values())
        report["comparison_exact_equal_count"]=sum(val==0 for val in differences.values())
        report["note"]="Comparison is diagnostic; an independent reproduction cannot authenticate the submitted original runs."
    return report


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--original-runs",required=True,type=Path)
    p.add_argument("--original-provenance",required=True,type=Path)
    p.add_argument("--compare-independent",type=Path)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    report=audit(a.original_runs,a.original_provenance,
                 comparison=a.compare_independent)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report,indent=2))


if __name__=="__main__":
    main()
