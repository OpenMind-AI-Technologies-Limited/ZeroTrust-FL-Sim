"""Measure real native CKKS additive aggregation, without implying Byzantine security.

Requires the repository C++ extension built with ZTFL_ENABLE_CKKS=ON.
Never generates benchmark numbers when native CKKS support is missing.
"""
from __future__ import annotations

import argparse
import hashlib
import platform
import csv
import json
import statistics
import sys
import time
from pathlib import Path

import numpy as np

FIELDS = ('trial', 'dimension', 'clients', 'key_generation_ms',
          'encrypt_ms', 'aggregate_ms', 'decrypt_ms',
          'serialized_ciphertext_bytes', 'chunks_per_update',
          'max_abs_error', 'mean_abs_error', 'weights_authenticated', 'byzantine_robust')


def benchmark(trials: int, clients: int, dimension: int, seed: int) -> list[dict]:
    if trials <= 0 or clients <= 0 or dimension <= 0:
        raise ValueError('trials, clients and dimension must be positive')
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'fl'))
    from zerotrust_fl.privacy import (CKKSConfig, CKKSKeyMaterial,
        CKKSClientEncryptor, CKKSServerAggregator, CKKSDecryptor,
        native_ckks_available)
    if not native_ckks_available():
        raise RuntimeError('Native CKKS unavailable: build SEAL extension with ZTFL_ENABLE_CKKS=ON')
    results = []
    for trial in range(trials):
        rng = np.random.default_rng(np.random.SeedSequence([seed, trial, 903]))
        vectors = [rng.normal(0., .1, dimension) for _ in range(clients)]
        weights = rng.uniform(.5, 2., size=clients)
        start = time.perf_counter_ns()
        material = CKKSKeyMaterial.generate(CKKSConfig())
        keygen = (time.perf_counter_ns() - start)/1e6
        encryptor = CKKSClientEncryptor(material.public_bundle())
        server = CKKSServerAggregator(material.parameters)
        decryptor = CKKSDecryptor(material)
        start = time.perf_counter_ns()
        payloads = [encryptor.encrypt(v, weight=float(w))
                    for v,w in zip(vectors, weights)]
        encrypt_ms = (time.perf_counter_ns()-start)/1e6
        start = time.perf_counter_ns()
        aggregated = server.aggregate(payloads, expected_weights=weights)
        aggregate_ms = (time.perf_counter_ns()-start)/1e6
        start = time.perf_counter_ns()
        recovered = decryptor.decrypt_weighted_mean(aggregated)
        decrypt_ms = (time.perf_counter_ns()-start)/1e6
        expected = np.average(np.stack(vectors), axis=0, weights=weights)
        error = np.abs(recovered-expected)
        if not np.allclose(recovered,expected,rtol=1e-5,atol=1e-5):
            raise AssertionError(f'CKKS correctness failed: maximum absolute error={error.max()}')
        results.append(dict(trial=trial, dimension=dimension, clients=clients,
            key_generation_ms=keygen, encrypt_ms=encrypt_ms,
            aggregate_ms=aggregate_ms, decrypt_ms=decrypt_ms,
            serialized_ciphertext_bytes=sum(len(chunk) for p in payloads for chunk in p.chunks),
            chunks_per_update=len(payloads[0].chunks),
            max_abs_error=float(error.max()), mean_abs_error=float(error.mean()),
            weights_authenticated=False, byzantine_robust=False))
    return results


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trials',type=int,default=10)
    parser.add_argument('--clients',type=int,default=15)
    parser.add_argument('--dimension',type=int,default=10000)
    parser.add_argument('--seed',type=int,default=42)
    parser.add_argument('--output',type=Path,default=Path('artifacts/cyse_01608/ckks_benchmark.csv'))
    args=parser.parse_args()
    rows=benchmark(args.trials,args.clients,args.dimension,args.seed)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('w',newline='',encoding='utf-8') as handle:
        writer=csv.DictWriter(handle,fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    summary={'trials':len(rows),'dimension':args.dimension,'clients':args.clients,
      'median_encrypt_ms':statistics.median(r['encrypt_ms'] for r in rows),
      'median_aggregate_ms':statistics.median(r['aggregate_ms'] for r in rows),
      'median_decrypt_ms':statistics.median(r['decrypt_ms'] for r in rows),
      'max_abs_error':max(r['max_abs_error'] for r in rows),
      'security_warning':'Encrypted addition only; not Byzantine filtering, metadata authenticated=False.'}
    manifest = {
      "kind": "native Microsoft SEAL CKKS additive aggregation correctness and overhead",
      "status": "measurement only, no cryptographic Byzantine filtering",
      "summary": summary,
      "cpu": platform.processor(),
      "platform": platform.platform(),
      "python": platform.python_version(),
      "numpy": np.__version__,
      "output_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
      "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
      "configuration": {
        "trials": args.trials, "clients": args.clients, "dimension": args.dimension,
        "seed": args.seed, "poly_modulus_degree": 8192,
        "coeff_modulus_bits": [60, 40, 40, 60], "scale_bits": 40,
      },
      "limitation": "Server expected-weight metadata validation is not a proof of encrypted plaintext correctness or Byzantine update validity.",
    }
    (args.output.parent / "ckks_manifest.json").write_text(
      json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary,indent=2))


if __name__=='__main__':
    main()
