#!/usr/bin/env python3
"""
wif_combo_import_via_rpc.py --in wifs.txt --out my_wallet

"Method B": the safe, RPC-based way to bulk-import WIFs into a Bitcoin Core
descriptor wallet - useful as a reference implementation, and as a way to
cross-check whatever walletdat_forge.py (the offline writer in this repo)
produces.

Reads a text file with one WIF per line, builds a combo() descriptor for
each one (covers p2pk/p2pkh/p2wpkh/p2sh-wrapped-p2wpkh without having to
know in advance which script type a given key was used with), and imports
them into the target wallet via `importdescriptors`, in batches.

Creates the destination wallet if it doesn't exist yet (as a blank
descriptor wallet - no auto-generated HD seed, only what you import ends
up in it). Loads it if it exists on disk but isn't currently loaded.

Requires pure Python 3 (no external dependencies) and a bitcoind running
with `server=1`, using cookie-file authentication.
"""
import argparse
import base64
import http.client
import json
import sys
import time

# ---- BIP-380 descriptor checksum (Core's own reference implementation,
# test/functional/test_framework/descriptors.py, verified against v31.1) ----
INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]


def descsum_polymod(symbols):
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7ffffffff) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk


def descsum_expand(s):
    groups = []
    symbols = []
    for c in s:
        if c not in INPUT_CHARSET:
            raise ValueError(f"invalid character in descriptor: {c!r}")
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
    return s + '#' + ''.join(CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))


def build_combo_descriptor(wif):
    return descsum_create(f"combo({wif})")


# ---- minimal JSON-RPC client (cookie auth, no external dependencies) ----
class RPCError(Exception):
    pass


class RPC:
    def __init__(self, host, port, cookie_path, wallet=None, timeout=300):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.wallet = wallet
        with open(cookie_path) as f:
            user, password = f.read().strip().split(':', 1)
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
        }

    def call(self, method, params=None, wallet=None):
        w = wallet if wallet is not None else self.wallet
        path = f"/wallet/{w}" if w else "/"
        payload = json.dumps({"jsonrpc": "1.0", "id": "wif_combo_import", "method": method, "params": params or []})
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            conn.request("POST", path, payload, self.headers)
            resp = conn.getresponse()
            body = resp.read()
        finally:
            conn.close()
        data = json.loads(body)
        if data.get("error"):
            raise RPCError(data["error"])
        return data["result"]


def ensure_wallet_loaded(rpc, wallet_name):
    wallets = rpc.call("listwallets")
    if wallet_name in wallets:
        print(f"[{wallet_name}] already loaded.")
        return
    listed = rpc.call("listwalletdir")
    on_disk = {w["name"] for w in listed["wallets"]}
    if wallet_name in on_disk:
        print(f"[{wallet_name}] exists on disk but isn't loaded, loading...")
        rpc.call("loadwallet", [wallet_name])
    else:
        print(f"[{wallet_name}] doesn't exist, creating a blank descriptor wallet...")
        # [name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors, load_on_startup]
        # blank=True: no auto-generated HD seed / active descriptors - only
        # what you explicitly import via importdescriptors ends up in it.
        rpc.call("createwallet", [wallet_name, False, True, "", False, True])


def read_wifs(path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                yield line


def main():
    ap = argparse.ArgumentParser(description="Bulk-import WIFs as combo() descriptors, in batches.")
    ap.add_argument("--in", dest="infile", required=True, help="file with one WIF per line")
    ap.add_argument("--out", dest="wallet", required=True, help="destination wallet name")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8332, help="RPC port (default: mainnet, 8332)")
    ap.add_argument("--cookie", default=None,
                     help="path to bitcoind's .cookie file (default: <datadir>/.cookie next to "
                          "the default OS datadir - pass explicitly if you use a custom -datadir)")
    ap.add_argument("--batch-size", type=int, default=2000, help="descriptors per importdescriptors call")
    ap.add_argument("--internal", action="store_true", help="mark entries as change addresses (default: no)")
    ap.add_argument("--label", default=None, help="optional label applied to every imported entry")
    ap.add_argument("--dry-run", action="store_true", help="only build/validate descriptors, import nothing")
    ap.add_argument(
        "--timestamp", default="0",
        help="'0' (default) = unknown origin; a later `rescanblockchain` on a fully-synced "
             "node will search from genesis (use this if these keys might have real "
             "on-chain history you want recovered). "
             "'now' = current wall-clock time (skips scanning for history; only use this "
             "if you know the keys are unused). "
             "Or pass an explicit unix timestamp. "
             "NOTE: the literal string 'now' accepted by importdescriptors itself means "
             "'the synced chain tip time of the node processing the import', NOT wall-clock "
             "time - on an isolated/offline node stuck at height 0 that resolves to the "
             "genesis block (2009), the worst possible value. This script resolves 'now' "
             "to real wall-clock time itself instead, to avoid that trap.",
    )
    args = ap.parse_args()

    cookie_path = args.cookie or "~/.bitcoin/.cookie"
    import os
    cookie_path = os.path.expanduser(cookie_path)

    rpc = RPC(args.host, args.port, cookie_path, wallet=args.wallet)

    if not args.dry_run:
        ensure_wallet_loaded(rpc, args.wallet)

    if args.timestamp == "now":
        import_timestamp = int(time.time())
    else:
        import_timestamp = int(args.timestamp)

    batch = []
    total = 0
    imported_ok = 0
    errors = []

    def flush():
        nonlocal batch, imported_ok
        if not batch:
            return
        if args.dry_run:
            imported_ok += len(batch)
            batch = []
            return
        result = rpc.call("importdescriptors", [batch])
        for item, req in zip(result, batch):
            if item.get("success"):
                imported_ok += 1
            else:
                errors.append((req["desc"], item.get("error")))
        batch = []

    t0 = time.time()
    for wif in read_wifs(args.infile):
        total += 1
        try:
            desc = build_combo_descriptor(wif)
        except Exception as e:
            errors.append((wif, str(e)))
            continue
        entry = {
            "desc": desc,
            "timestamp": import_timestamp,
            "internal": args.internal,
        }
        if args.label:
            entry["label"] = args.label
        batch.append(entry)
        if len(batch) >= args.batch_size:
            flush()
            elapsed = time.time() - t0
            rate = total / elapsed if elapsed > 0 else 0
            print(f"  {total} processed, {imported_ok} ok, {len(errors)} errors  ({rate:.0f}/s)")
    flush()

    elapsed = time.time() - t0
    print(f"\n=== done: {total} WIFs read, {imported_ok} imported ok, {len(errors)} errors ({elapsed:.1f}s) ===")
    if errors:
        err_path = args.infile + ".errors.txt"
        with open(err_path, "w") as f:
            for desc, err in errors:
                f.write(f"{desc}\t{err}\n")
        print(f"error detail written to: {err_path}")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
