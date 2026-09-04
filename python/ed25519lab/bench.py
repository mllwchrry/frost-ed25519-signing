"""Timing for every ed25519lab primitive.

    python3 bench.py            # everything
    python3 bench.py decode     # only rows whose name contains "decode"

Numbers are medians of repeated runs, in milliseconds. This is a reference
implementation over Python bigints: the absolute values are only useful for
comparing operations against each other and for sizing a protocol session.
"""

import statistics
import sys
import time
from pathlib import Path
from random import randint, seed

# Run from a fresh clone without installing, same as test/__init__.py.
sys.path.insert(0, str(Path(__file__).parent / "src/"))

from ed25519lab.ecdh import ecdh_ed25519
from ed25519lab.ed25519 import FE, GE, B, Scalar, _mul_int, _recover_x
from ed25519lab.internal_sig import internal_sign, internal_verify
from ed25519lab.keys import pubkey_gen
from ed25519lab.util import tagged_hash

L = Scalar.SIZE
P = FE.SIZE

ROWS: list[tuple[str, str, float]] = []


def bench(group: str, name: str, fn, reps: int | None = None) -> float:
    """Time fn, auto-scaling the repeat count so each measurement takes ~50 ms."""
    if reps is None:
        t0 = time.perf_counter()
        fn()
        single = time.perf_counter() - t0
        reps = max(3, min(20000, int(0.05 / max(single, 1e-9))))
    samples = []
    for _ in range(5):
        t0 = time.perf_counter()
        for _ in range(reps):
            fn()
        samples.append((time.perf_counter() - t0) / reps * 1000)
    ms = statistics.median(samples)
    ROWS.append((group, name, ms))
    return ms


def main() -> None:
    filt = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    seed(20260818)

    a = Scalar(randint(1, L - 1))
    b = Scalar(randint(1, L - 1))
    fa = FE(randint(1, P - 1))
    fb = FE(randint(1, P - 1))
    pt = a * B
    enc = pt.to_bytes()
    y_only = FE(int(pt.y))
    wide = bytes(randint(0, 255) for _ in range(64))

    # --- field ---
    bench("field", "FE mul", lambda: fa * fb)
    bench("field", "FE add", lambda: fa + fb)
    bench("field", "FE int() (forces inversion)", lambda: int(FE(fa._num, fb._num)))
    bench("field", "FE sqrt", lambda: (fa * fa).sqrt())

    # --- scalar ---
    bench("scalar", "Scalar mul", lambda: a * b)
    bench("scalar", "Scalar add", lambda: a + b)
    bench("scalar", "Scalar inverse", lambda: Scalar(1) / a)
    bench("scalar", "from_bytes_checked", lambda: Scalar.from_bytes_checked(a.to_bytes()))
    bench("scalar", "from_bytes_wide", lambda: Scalar.from_bytes_wide(wide))
    bench("scalar", "to_bytes", lambda: a.to_bytes())

    # --- group ---
    bench("group", "GE add", lambda: pt + pt)
    bench("group", "GE neg", lambda: -pt)
    bench("group", "GE eq", lambda: pt == pt)  # noqa: PLR0124 - measuring __eq__
    bench("group", "GE scalar mul (252-bit)", lambda: a * B)
    bench("group", "GE scalar mul (8-bit)", lambda: Scalar(200) * B)
    bench("group", "GE.sum of 10", lambda: GE.sum(*([pt] * 10)))
    bench("group", "GE.batch_mul of 10", lambda: GE.batch_mul(*([(a, pt)] * 10)))

    # --- codec, broken down ---
    bench("codec", "to_bytes", lambda: pt.to_bytes())
    bench("codec", "  _recover_x only", lambda: _recover_x(y_only, 0))
    bench("codec", "  subgroup check [L]P only", lambda: _mul_int(pt, GE.ORDER).is_identity)
    bench("codec", "from_bytes (full)", lambda: GE.from_bytes(enc))

    # --- protocol-level ---
    bench("protocol", "pubkey_gen", lambda: pubkey_gen(a.to_bytes()))
    bench("protocol", "tagged_hash of 32 B", lambda: tagged_hash("bench", b"\x00" * 32))
    sk = a.to_bytes()
    pk = pubkey_gen(sk)
    sig = internal_sign(b"msg", sk)
    bench("protocol", "internal_sign", lambda: internal_sign(b"msg", sk))
    bench("protocol", "internal_verify", lambda: internal_verify(b"msg", pk, sig))
    bench("protocol", "ecdh_ed25519", lambda: ecdh_ed25519(sk, pk, b"ctx", sending=True))

    # --- session sizing ---
    decode = next(ms for g, n, ms in ROWS if n == "from_bytes (full)")
    sub = next(ms for g, n, ms in ROWS if "subgroup check" in n)

    width = max(len(n) for _, n, _ in ROWS) + 2
    last_group = None
    for group, name, ms in ROWS:
        if filt and filt not in name.lower() and filt not in group.lower():
            continue
        if group != last_group:
            print(f"\n{group}")
            last_group = group
        per_sec = 1000 / ms if ms else float("inf")
        print(f"  {name:<{width}}{ms:9.4f} ms{per_sec:12.0f}/s")

    if not filt:
        print("\nsession sizing (strict decodes only: n*t VSS commitment points + n host pubkeys)")
        print(f"  {'':<12}{'decodes':>9}{'total':>12}{'spent in [L]P':>16}")
        for n, t in ((3, 2), (5, 3), (10, 7), (20, 13)):
            count = n * t + n
            print(
                f"  n={n:<3} t={t:<4}{count:>9}"
                f"{count * decode / 1000:>10.2f} s"
                f"{count * sub / 1000:>14.2f} s"
            )
        print(
            f"\n  The subgroup check is {sub / decode * 100:.0f}% of decode cost. It runs per "
            "received point,\n  not per session; that is deliberate (see the spec's pitfall 7)."
        )


if __name__ == "__main__":
    main()
