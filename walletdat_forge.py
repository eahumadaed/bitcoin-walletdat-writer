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
import hashlib
import os
import struct
import sqlite3
import sys

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


# SEC1 ECPrivateKey DER template (RFC 5915 / SEC1 sec 3, explicit secp256k1
# curve parameters). This blob is IDENTICAL for every key except two spots:
# the 32-byte private scalar and the 33-byte compressed public key point -
# confirmed by diffing the DER output for two different real keys.
DER_HEADER = bytes.fromhex("3081d30201010420")
DER_MIDDLE = bytes.fromhex(
    "a08185308182020101302c06072a8648ce3d0101022100"
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    "300604010004010704210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641410201"
    "01a124032200"
)


def build_der(privkey32, pubkey33):
    return DER_HEADER + privkey32 + DER_MIDDLE + pubkey33


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
    """Build the (walletdescriptor, walletdescriptorkey) row pair for one WIF."""
    privkey32, compressed = wif_to_privkey(wif)
    if not compressed:
        raise ValueError("only compressed WIFs are supported")

    key = ECKey()
    key.set(privkey32, compressed=True)
    pubkey33 = key.get_pubkey().get_bytes()

    desc_plain = f"combo({pubkey33.hex()})"
    desc_full = descsum_create(desc_plain)
    desc_id = hashlib.sha256(desc_full.encode()).digest()

    der = build_der(privkey32, pubkey33)
    key_value = compact_size(len(der)) + der + chash256(pubkey33 + der)

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
        (db_key("walletdescriptorkey", desc_id, ser_string(pubkey33)), key_value),
    ], desc_full


def write_wallet(out_path, wifs, timestamp=1):
    if os.path.exists(out_path):
        os.remove(out_path)
    con = sqlite3.connect(out_path)
    con.execute("CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)")
    con.execute(f"PRAGMA application_id = {SQLITE_APPLICATION_ID}")
    con.execute("PRAGMA user_version = 0")

    rows = [(db_key(name), val) for name, val in CONST_RECORDS.items()]

    ok, errors = 0, []
    for wif in wifs:
        try:
            recs, _desc = build_combo_records(wif, timestamp=timestamp)
            rows.extend(recs)
            ok += 1
        except Exception as e:
            errors.append((wif, str(e)))

    con.executemany("INSERT INTO main(key, value) VALUES (?, ?)", rows)
    con.commit()
    con.close()
    return ok, errors


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
    ap.add_argument("--out", dest="outfile", required=True, help="output wallet.dat path")
    ap.add_argument(
        "--timestamp", type=int, default=1,
        help="descriptor creation_time (unix epoch). Default 1 = 'unknown origin', "
             "so a later `rescanblockchain` on a real node will search from the "
             "beginning of the chain. Use a real epoch value if you know these "
             "keys have no history and want to skip scanning for it.",
    )
    args = ap.parse_args()

    wifs = list(read_wifs(args.infile))
    ok, errors = write_wallet(args.outfile, wifs, timestamp=args.timestamp)
    print(f"=== {args.outfile}: {ok}/{len(wifs)} keys written ===")
    for wif, err in errors:
        print(f"  error on {wif[:10]}...: {err}")
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
