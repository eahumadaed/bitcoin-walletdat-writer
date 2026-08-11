#!/usr/bin/env python3
"""
walletdat-forge - build a Bitcoin Core-compatible wallet.dat (SQLite,
descriptor format, v25+) directly from a list of WIF private keys, without
ever running bitcoind.

    python3 walletdat_forge.py --in wifs.txt --out wallet.dat

Each WIF is imported as a combo() descriptor (BIP 380/384) covering
p2pk / p2pkh / p2wpkh / p2sh-wrapped-p2wpkh in one entry, matching what
`bitcoin-cli importdescriptors` would produce for the same key - but
written directly as SQLite rows instead of going through a running node.

===============================================================================
DISCLAIMER - READ BEFORE USING WITH REAL FUNDS

This is a research / educational tool, reverse-engineered by comparing
byte-for-byte output against real wallets created by Bitcoin Core
(v28.1.0 and v31.1). It is NOT part of Bitcoin Core, is NOT officially
supported, and has NOT been audited.

USE AT YOUR OWN RISK. Always:
  - test with disposable/throwaway keys first (see samples/fake_wifs.txt)
  - verify the resulting wallet.dat by loading it into a real bitcoind
    and checking `getaddressinfo` / balances BEFORE trusting it with funds
  - keep a backup of your original key material regardless of what this
    tool produces
  - review the code yourself; do not trust it blindly with real money

The authors take no responsibility for lost or corrupted funds resulting
from the use of this software. See LICENSE (MIT) - provided "AS IS",
without warranty of any kind.
===============================================================================

See README.md for the full write-up of how each byte of the format was
verified, and vendor/ for the (lightly patched) copy of Bitcoin Core's own
test-framework secp256k1 implementation this script uses to derive public
keys, so the whole pipeline never depends on bitcoind or any third-party
crypto library.
"""
import argparse
import functools
import hashlib
import itertools
import multiprocessing as mp
import os
import struct
import sqlite3
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))
from key import ECKey  # noqa: E402  (vendor/key.py, from bitcoin/bitcoin test framework)

# ---------------------------------------------------------------------------
# base58check (WIF decoding) - no external dependencies
# ---------------------------------------------------------------------------
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode_check(s):
    num = 0
    for c in s:
        num = num * 58 + B58_ALPHABET.index(c)
    combined = num.to_bytes((num.bit_length() + 7) // 8, "big")
    n_leading = len(s) - len(s.lstrip("1"))
    combined = b"\x00" * n_leading + combined
    payload, checksum = combined[:-4], combined[-4:]
    calc = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if calc != checksum:
        raise ValueError(f"invalid WIF checksum: {s!r}")
    return payload


def wif_to_privkey(wif):
    """Decode a mainnet WIF into (32-byte privkey, is_compressed)."""
    payload = b58decode_check(wif)
    version, rest = payload[0], payload[1:]
    if version != 0x80:
        raise ValueError(f"not a mainnet WIF (version byte {version:#x})")
    if len(rest) == 33 and rest[-1] == 0x01:
        return rest[:32], True
    elif len(rest) == 32:
        return rest, False
    raise ValueError(f"unexpected WIF payload length: {len(rest)}")


# ---------------------------------------------------------------------------
# BIP-380 descriptor checksum
# Verified against Bitcoin Core's own `getdescriptorinfo` RPC output.
# ---------------------------------------------------------------------------
INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]


def descsum_polymod(symbols):
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7FFFFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk


def descsum_expand(s):
    groups, symbols = [], []
    for c in s:
        v = INPUT_CHARSET.find(c)
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols


def descsum_create(s):
    symbols = descsum_expand(s) + [0, 0, 0, 0, 0, 0, 0, 0]
    checksum = descsum_polymod(symbols) ^ 1
    return s + "#" + "".join(CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))


# ---------------------------------------------------------------------------
# wallet.dat record construction
# Every field below was verified byte-for-byte against wallets produced by
# real bitcoind instances (v28.1.0 and v31.1) - see README.md "How this was
# verified" for the full methodology.
# ---------------------------------------------------------------------------

def chash256(data):
    """Bitcoin's CHash256: double SHA-256."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact_size(n):
    if n < 0xFD:
        return bytes([n])
    elif n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def ser_string(b):
    """Bitcoin Core's generic variable-length serialization: compactsize(len) + bytes."""
    return compact_size(len(b)) + b


def db_key(name, *fixed_width_parts):
    """
    wallet.dat DB keys are: compactsize(name) + name + extra parts.
    uint256 fields (like desc_id) are fixed-width and carry no length
    prefix; variable-length fields (like a CPubKey) must be pre-wrapped
    with ser_string() by the caller before being passed in here.
    """
    out = ser_string(name.encode())
    for part in fixed_width_parts:
        out += part
    return out


# SEC1 ECPrivateKey DER templates (RFC 5915 / SEC1 sec 3, explicit secp256k1
# curve parameters). Each blob is IDENTICAL for every key of the same
# compression type except two spots: the 32-byte private scalar and the
# public key point (33 bytes compressed / 65 bytes uncompressed) -
# confirmed by diffing the DER output for multiple different real keys of
# each type. The uncompressed variant is bigger only because DER's
# explicit-curve-parameters section embeds the generator point G in the
# same compression as the key's own public key, plus the outer SEQUENCE
# length prefix grows from short-form (1 byte) to long-form (2 bytes)
# once the total exceeds 255 bytes.
DER_HEADER_COMPRESSED = bytes.fromhex("3081d30201010420")
DER_MIDDLE_COMPRESSED = bytes.fromhex(
    "a08185308182020101302c06072a8648ce3d0101022100"
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    "300604010004010704210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641410201"
    "01a124032200"
)

DER_HEADER_UNCOMPRESSED = bytes.fromhex("308201130201010420")
DER_MIDDLE_UNCOMPRESSED = bytes.fromhex(
    "a081a53081a2020101302c06072a8648ce3d0101022100"
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    "3006040100040107044104"
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    "022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101"
    "a1440342"
    "00"
)


def build_der(privkey32, pubkey, compressed):
    if compressed:
        assert len(pubkey) == 33
        return DER_HEADER_COMPRESSED + privkey32 + DER_MIDDLE_COMPRESSED + pubkey
    else:
        assert len(pubkey) == 65
        return DER_HEADER_UNCOMPRESSED + privkey32 + DER_MIDDLE_UNCOMPRESSED + pubkey


# "Blank wallet" scaffolding records. These are identical across every
# fresh descriptor wallet we inspected (private keys enabled, nothing
# scanned yet) - so they're safe to hardcode rather than recompute.
CONST_RECORDS = {
    "flags": bytes.fromhex("0000000004000000"),       # WALLET_FLAG_DESCRIPTORS
    "version": bytes.fromhex("24460400"),              # last client version, int32 LE
    "minversion": bytes.fromhex("ac970200"),            # wallet min version, int32 LE
    "bestblock": bytes.fromhex("8011010000"),           # genesis block locator
}

# SQLite `application_id` pragma Bitcoin Core stamps on every wallet file.
# It's a SIGNED 32-bit int in the SQLite header; Core reports it unsigned
# (4190024921) via `file wallet.dat`, but PRAGMA application_id wants (and
# returns) the signed representation.
SQLITE_APPLICATION_ID = -104942375


def build_combo_records(wif, timestamp=1):
    """Build the (walletdescriptor, walletdescriptorkey) row pair for one WIF.

    Handles both compressed (33-byte pubkey) and uncompressed (65-byte
    pubkey) WIFs - common in older/legacy wallets, where WIFs starting
    with '5' are uncompressed and 'K'/'L' are compressed. combo() only
    expands to pk()/pkh() for an uncompressed key (wpkh()/sh(wpkh())
    require a compressed pubkey per consensus rules), which Core handles
    on its own - this tool doesn't need to know or care about that.
    """
    privkey32, compressed = wif_to_privkey(wif)

    key = ECKey()
    key.set(privkey32, compressed=compressed)
    pubkey = key.get_pubkey().get_bytes()

    desc_plain = f"combo({pubkey.hex()})"
    desc_full = descsum_create(desc_plain)
    desc_id = hashlib.sha256(desc_full.encode()).digest()

    der = build_der(privkey32, pubkey, compressed)
    key_value = compact_size(len(der)) + der + chash256(pubkey + der)

    desc_value = (
        ser_string(desc_full.encode())
        + struct.pack("<Q", timestamp)  # creation_time (Core clamps 0 -> 1)
        + struct.pack("<i", 0)          # range_start (unused, not a ranged descriptor)
        + struct.pack("<i", 0)          # range_end
        + struct.pack("<i", 1)          # next_index (unused, not a ranged descriptor)
    )

    return [
        (db_key("walletdescriptor", desc_id), desc_value),
        # CPubKey serializes as compactsize(len)+bytes, unlike the fixed-width
        # uint256 desc_id - this asymmetry is a common trap, see README.
        (db_key("walletdescriptorkey", desc_id, ser_string(pubkey)), key_value),
    ], desc_full


# ---------------------------------------------------------------------------
# streaming, parallel wallet construction
#
# Pubkey derivation (pure-Python secp256k1 point multiplication, see
# vendor/) is the actual bottleneck here, not SQLite - measured at ~135
# keys/s on a single core. Two things keep this practical at scale:
#
#   1. multiprocessing spreads derivation across all CPU cores. Only the
#      derivation happens in worker processes; SQLite writes stay on a
#      single connection in the main process (SQLite doesn't want
#      concurrent writers anyway, and this isn't the slow part).
#   2. WIFs are read lazily and processed in fixed-size chunks, each
#      chunk's rows get INSERTed and committed, then dropped - so memory
#      use stays bounded by (chunk_size * a few in-flight chunks), not by
#      the total input size. Without this, building one Python list with
#      every row for a very large input can use far more RAM than the
#      resulting SQLite file itself.
# ---------------------------------------------------------------------------

def _process_chunk(wifs_chunk, timestamp):
    """Runs in a worker process: derive pubkeys/records for one chunk of WIFs."""
    rows, errors = [], []
    for wif in wifs_chunk:
        try:
            recs, _desc = build_combo_records(wif, timestamp=timestamp)
            rows.extend(recs)
        except Exception as e:
            errors.append((wif, str(e)))
    return rows, errors


def chunked(iterable, size):
    it = iter(iterable)
    while True:
        chunk = list(itertools.islice(it, size))
        if not chunk:
            return
        yield chunk


def default_chunk_size(total, workers):
    """Aim for enough chunks that progress logs update steadily (~20 per
    worker over the whole run) without going so small that per-chunk
    overhead (pickling to a worker, a SQLite commit) starts to matter."""
    if not total:
        return 100_000
    target_chunks = max(workers * 20, 20)
    size = total // target_chunks
    return max(500, min(size, 100_000))


def format_hms(seconds):
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m{s:02d}s" if h else f"{m}m{s:02d}s"


def write_wallet(out_path, wifs_iter, timestamp=1, chunk_size=100_000, workers=None,
                  unsafe_fast=False, append=False, total=None):
    """
    wifs_iter: an iterable (generator is fine and recommended) of WIF strings.
    workers: number of worker processes for pubkey derivation. 1 disables
             multiprocessing entirely (useful for debugging). Defaults to
             all available CPU cores.
    total: total number of WIFs in wifs_iter, if known - enables a percent-
           complete and ETA in the progress log. Pass None to skip counting
           ahead of time (e.g. for a WIF source that isn't a plain file) and
           get plain running totals instead.
    unsafe_fast: relax SQLite's durability guarantees (WAL + synchronous=OFF)
             for maximum write throughput. Fine for a disposable stress test;
             do NOT use this for a wallet.dat you intend to keep - a crash
             or power loss mid-write can leave it corrupted.
    append: add keys to an EXISTING wallet.dat (forge-built or Core-built -
             the schema is the same either way) instead of creating a fresh
             one. The scaffolding/constant records are skipped (they should
             already be there). Useful for resuming an interrupted run, or
             for topping up a wallet that was originally built by a
             different tool/path.
             NOTE: the target file must not be open elsewhere (e.g. loaded
             in a running bitcoind) - SQLite's exclusive locking will
             reject concurrent access either way.
    """
    # Always OR IGNORE, append or not: the same WIF can legitimately appear
    # more than once in one input file (duplicate exports, overlapping
    # sources), which produces the same key/value pair twice - a plain
    # INSERT would crash on the second copy with a UNIQUE constraint error
    # instead of just skipping a harmless, byte-identical duplicate.
    insert_sql = "INSERT OR IGNORE INTO main(key, value) VALUES (?, ?)"

    if append:
        if not os.path.exists(out_path):
            raise FileNotFoundError(f"--append requires an existing file: {out_path}")
        con = sqlite3.connect(out_path)
    else:
        if os.path.exists(out_path):
            os.remove(out_path)
        con = sqlite3.connect(out_path)
        con.execute("CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)")
        con.execute(f"PRAGMA application_id = {SQLITE_APPLICATION_ID}")
        con.execute("PRAGMA user_version = 0")
        const_rows = [(db_key(name), val) for name, val in CONST_RECORDS.items()]
        con.executemany(insert_sql, const_rows)
        con.commit()

    if unsafe_fast:
        con.execute("PRAGMA journal_mode = WAL")
        con.execute("PRAGMA synchronous = OFF")

    workers = workers or os.cpu_count() or 1
    worker_fn = functools.partial(_process_chunk, timestamp=timestamp)
    chunk_iter = chunked(wifs_iter, chunk_size)

    total_ok, total_err = 0, 0
    error_log = []
    t0 = time.time()

    pool = mp.Pool(workers) if workers > 1 else None
    results_iter = pool.imap(worker_fn, chunk_iter) if pool else map(worker_fn, chunk_iter)

    try:
        for rows, errors in results_iter:
            if rows:
                con.executemany(insert_sql, rows)
                con.commit()
            # 2 DB rows per successfully-processed key
            total_ok += len(rows) // 2
            total_err += len(errors)
            error_log.extend(errors)
            elapsed = time.time() - t0
            done = total_ok + total_err
            rate = done / elapsed if elapsed > 0 else 0
            if total:
                pct = 100 * done / total
                remaining = max(0, total - done)
                eta = format_hms(remaining / rate) if rate > 0 else "?"
                print(f"  {done}/{total} ({pct:.1f}%)  {total_ok} written, {total_err} errors  "
                      f"| {rate:.0f} keys/s | elapsed {format_hms(elapsed)} | ETA {eta}")
            else:
                print(f"  {total_ok} keys written, {total_err} errors  "
                      f"| {rate:.0f} keys/s | elapsed {format_hms(elapsed)}")
    finally:
        if pool:
            pool.close()
            pool.join()

    con.close()
    return total_ok, error_log


def read_wifs(path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


def main():
    ap = argparse.ArgumentParser(
        description="Build a Bitcoin Core-compatible wallet.dat from a list of WIFs, without bitcoind."
    )
    ap.add_argument("--in", dest="infile", required=True, help="text file, one WIF per line")
    ap.add_argument("--out", dest="outfile", required=True,
                     help="output path. By default this is the wallet.dat file itself. "
                          "With --as-dir, it's treated as a wallet name/directory instead.")
    ap.add_argument(
        "--as-dir", action="store_true",
        help="treat --out as a wallet directory name rather than a literal wallet.dat "
             "path: creates <out>/ (if it doesn't exist yet) and writes <out>/wallet.dat "
             "inside it - the same layout Bitcoin Core itself uses for a wallet, so the "
             "result can be copied straight into <datadir>/wallets/ and loaded by name.",
    )
    ap.add_argument(
        "--timestamp", type=int, default=1,
        help="descriptor creation_time (unix epoch). Default 1 = 'unknown origin', "
             "so a later `rescanblockchain` on a real node will search from the "
             "beginning of the chain. Use a real epoch value if you know these "
             "keys have no history and want to skip scanning for it.",
    )
    ap.add_argument(
        "--workers", type=int, default=None,
        help="number of worker processes for pubkey derivation (default: all CPU cores). "
             "Pass 1 to disable multiprocessing.",
    )
    ap.add_argument(
        "--chunk-size", type=int, default=None,
        help="how many keys to derive and write per batch. Controls the memory/"
             "throughput trade-off, AND how often a progress line is printed - each "
             "chunk is written to SQLite (and a progress line logged) before the next "
             "one starts. Default: auto-picked from the input size and worker count so "
             "you get a steady stream of updates instead of one line at the very end "
             "(capped at 100000). Set this explicitly to override that.",
    )
    ap.add_argument(
        "--unsafe-fast", action="store_true",
        help="relax SQLite durability (WAL + synchronous=OFF) for max throughput on "
             "disposable stress tests. Do NOT use for a wallet.dat you intend to keep.",
    )
    ap.add_argument(
        "--append", action="store_true",
        help="add keys to an EXISTING wallet.dat instead of creating a fresh one. "
             "Already-present keys are silently skipped (safe to resume/re-run). "
             "The target file must not be loaded in a running bitcoind.",
    )
    ap.add_argument(
        "--no-count", action="store_true",
        help="skip the upfront pass that counts total WIFs in the input file (used for "
             "the percent-complete/ETA in progress logs). Only useful if --in isn't a "
             "plain file the tool can cheaply scan twice.",
    )
    args = ap.parse_args()

    # Line-buffer stdout so progress lines show up as they're printed instead
    # of sitting in a buffer until the process exits (only matters when
    # stdout is redirected to a file/pipe, e.g. `> run.log &` - a TTY is
    # already line-buffered by default).
    sys.stdout.reconfigure(line_buffering=True)

    outfile = args.outfile
    if args.as_dir:
        os.makedirs(outfile, exist_ok=True)
        outfile = os.path.join(outfile, "wallet.dat")

    total = None
    if not args.no_count:
        print(f"counting {args.infile}...")
        total = sum(1 for _ in read_wifs(args.infile))
        print(f"{total} WIFs to process")

    workers_effective = args.workers or os.cpu_count() or 1
    chunk_size = args.chunk_size or default_chunk_size(total, workers_effective)
    print(f"using chunk-size={chunk_size}, workers={workers_effective}")

    ok, errors = write_wallet(
        outfile,
        read_wifs(args.infile),
        timestamp=args.timestamp,
        chunk_size=chunk_size,
        workers=args.workers,
        unsafe_fast=args.unsafe_fast,
        append=args.append,
        total=total,
    )
    print(f"=== {outfile}: {ok} keys written, {len(errors)} errors ===")
    if errors:
        err_path = args.infile + ".errors.txt"
        with open(err_path, "w") as f:
            for wif, err in errors:
                f.write(f"{wif}\t{err}\n")
        print(f"error detail written to: {err_path}")
        sys.exit(1)


if __name__ == "__main__":
    main()
