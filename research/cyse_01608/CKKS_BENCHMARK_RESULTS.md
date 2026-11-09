# Real native Microsoft SEAL CKKS: correctness, latency and ciphertext overhead

Measured with CKKS enabled in the C++20 native extension. Independent from the original 720-run FL matrix.

GitHub Actions execution: https://github.com/smshagor-dev/ZeroTrust-FL-Sim/actions/runs/42538602110, artifact cyse-01608-native-ckks-42538602110 (ckks_benchmark.csv and ckks_manifest.json).

## Configuration and observations
- 15 weighted client updates, each 4096 real-valued coordinates; three trials on an Ubuntu Azure GitHub Actions x86_64 runner; Python 3.12.16; NumPy 2.5.4.
- CKKS polynomial modulus degree 8192; coefficient modulus bits 60, 40, 40, 60; scale bits 40.
- Median CKKS key generation: approximately 42.90 ms.
- Median encryption of all 15 client updates sequentially: **646.97 ms**.
- Median ciphertext addition: **41.87 ms**.
- Median weighted-sum decryption: **41.86 ms**.
- Total serialized client ciphertext payload: **5,899,935 bytes**, or ~5.63 MiB, per run.
- Maximum absolute numerical error against the plaintext weighted mean: **1.67e-9**.
- CSV SHA-256: 9614b46d4e894c770e8044579ca527631ca55354fdfcf5eff954ad01815b7738.

## Claim boundaries
This is an honest-input additive CKKS correctness/overhead benchmark, not encrypted Krum, Multi-Krum, trimming, proof of update-range, proof of correct noise, end-to-end deployment latency, key-compromise study or real-world Byzantine-tolerant encrypted model training. Expected-weight metadata checks are not cryptographic binding to the encrypted plaintext. These security claims remain UNSUPPORTED.

Run instructions: Python native dependencies, build the extension with ZTFL_ENABLE_CKKS=ON, then execute research/cyse_01608/ckks_benchmark.py with 15 clients, 4096 dimensions and 3 trials.
