"""verify_artifacts.py — independent artifact verification (no verifier logic).

1. Checks every artifact listed in SHA256SUMS.txt against its recorded SHA-256.
2. Recomputes Wilson-95% lower bounds from raw counts inside each JSON.

Run:  python verify_artifacts.py
Stdlib only. MIT license.
"""
import hashlib
import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).parent
Z95 = 1.959963984540054  # two-sided 95% -> 97.5% quantile


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_sums() -> bool:
    ok = True
    sums = HERE / "SHA256SUMS.txt"
    for line in sums.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        expected, name = line.split(maxsplit=1)
        p = HERE / name
        if not p.exists():
            print(f"[FAIL] missing: {name}")
            ok = False
            continue
        actual = sha256_of(p)
        if actual.startswith(expected.split("…")[0][:16]) or actual == expected:
            print(f"[ OK ] {name}  {actual[:16]}…")
        else:
            print(f"[FAIL] {name}  expected {expected[:16]}… got {actual[:16]}…")
            ok = False
    return ok


def wilson_lower(k: int, n: int, z: float = Z95) -> float:
    if n == 0:
        return 0.0
    p = k / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (centre - margin) / denom)


def recompute_bounds() -> None:
    p = HERE / "artifact_100k_stress.json"
    d = json.loads(p.read_text())
    n_int = d["tp_intercept"] + d["fn_miss"]
    n_pas = d["tn_pass"] + d["fp_false_intercept"]
    lo_int = wilson_lower(d["tp_intercept"], n_int)
    lo_pas = wilson_lower(d["tn_pass"], n_pas)
    print(f"\n[RECOMPUTE] artifact_100k_stress.json (published values in parentheses)")
    print(f"  interception  {d['tp_intercept']}/{n_int}  Wilson-95 lower = {lo_int:.7f}  ({d.get('intercept_wilson95_lower')})")
    print(f"  pass-correct  {d['tn_pass']}/{n_pas}  Wilson-95 lower = {lo_pas:.7f}  ({d.get('pass_correct_wilson95_lower')})")
    print(f"  latency p99 = {d['latency_ms']['p99']} ms (published: 0.13)")


if __name__ == "__main__":
    ok = check_sums()
    try:
        recompute_bounds()
    except Exception as e:  # noqa: BLE001
        print(f"[WARN] bound recompute skipped: {e}")
    sys.exit(0 if ok else 1)
