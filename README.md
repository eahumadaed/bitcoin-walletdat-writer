# walletdat-forge

Build a Bitcoin Core-compatible `wallet.dat` (SQLite, descriptor format,
Core v25+) directly from a list of WIF private keys — **without ever
running `bitcoind`** to write it. Load the result into a real node and
it works exactly like a wallet Core created itself.

```
python3 walletdat_forge.py --in wifs.txt --out wallet.dat
```

## ⚠️ Disclaimer — use at your own risk

This is a research / educational tool, reverse-engineered by comparing
byte-for-byte output against real wallets created by Bitcoin Core
(tested against v28.1.0 and v31.1). It is **not part of Bitcoin Core**,
is **not officially supported**, and has **not been security-audited**.

**Use this at your own risk.** In particular:

- Test with the disposable keys in [`samples/fake_wifs.txt`](samples/fake_wifs.txt) first.
- Always verify the resulting `wallet.dat` by loading it into a real
  `bitcoind` and checking `getaddressinfo` / balances **before**
  trusting it with real funds.
- Keep a backup of your original key material regardless of what this
  tool produces.
- Read the code yourself. Don't trust it blindly with real money.

The author(s) take no responsibility for lost or corrupted funds
resulting from the use of this software. Provided **as is**, without
warranty of any kind — see [LICENSE](LICENSE).

## Why this exists

While consolidating a pile of old wallets (millions of individually
generated legacy keys, most from one-off "just in case" addresses), the
usual path — recreate them in Core, `dumpwallet`/`importwallet`, then
`migratewallet` to the modern descriptor format — worked, but was slow:
converting ~2.7M legacy BDB keys to individual descriptors took Core
several hours on a single wallet.

That raised an obvious question: BDB legacy wallets are (deliberately)
hard to leave behind, but the *destination* format — the SQLite
descriptor wallet Core has used since v25 — is just a plain SQLite
database with a documented, MIT-licensed reference implementation for
almost every piece involved (the descriptor language, the checksum
algorithm, the secp256k1 math). What if we wrote that database directly?

Turns out you can. This repo is the result: every byte of the format
below was reverse-engineered and then verified against real Core output,
not guessed.

## What it produces

Each WIF becomes a [`combo()`](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)
descriptor — the same thing you'd get from `bitcoin-cli importdescriptors`
with a `combo(<key>)` entry. `combo()` expands to `pk()` / `pkh()` /
`wpkh()` / `sh(wpkh())` all at once, so you don't need to know in advance
which script type a given key was actually used with.

The output wallet has private keys enabled, is unencrypted, and is
otherwise "blank" (no auto-generated HD seed, no active
address-generating descriptors) — it only contains exactly what you fed
in.

## Two tools, two trade-offs

| | `walletdat_forge.py` | `wif_combo_import_via_rpc.py` |
|---|---|---|
| Needs a running `bitcoind`? | No, only to load/verify the result | Yes, the whole time |
| Speed at scale | Fast — direct batched SQLite inserts | Bounded by Core deriving/validating each descriptor over RPC |
| Trust model | Vendored crypto code + a lot of byte-level verification (see below) | Core validates everything server-side |
| Good for | Bulk/offline generation, air-gapped workflows | Smaller batches, or when you want Core's own validation on the way in |

Use whichever trade-off you're more comfortable with. Cross-checking one
against the other on the same input is a good way to build confidence.

## Requirements

Python 3.8+, standard library only. No `pip install` needed —
`vendor/key.py` and `vendor/secp256k1.py` are a lightly patched copy of
Bitcoin Core's own test-framework secp256k1 implementation (MIT
licensed, see file headers), vendored in so pubkey derivation never
depends on `bitcoind`, OpenSSL, or any third-party crypto library.

## Usage

### `walletdat_forge.py` — offline, no bitcoind needed to write

```bash
python3 walletdat_forge.py --in wifs.txt --out wallet.dat
```

`wifs.txt`: one compressed mainnet WIF per line, blank lines and `#`
comments ignored (see [`samples/fake_wifs.txt`](samples/fake_wifs.txt)).

Then, to actually use it, drop the file into a real node's wallet
directory and load it:

```bash
mkdir -p ~/.bitcoin/wallets/my_wallet
cp wallet.dat ~/.bitcoin/wallets/my_wallet/wallet.dat
bitcoin-cli loadwallet my_wallet
bitcoin-cli -rpcwallet=my_wallet rescanblockchain   # if you need on-chain history
```

By default every descriptor is stamped with `creation_time = 1`
("unknown origin") so a later `rescanblockchain` searches from the very
start of the chain — appropriate if these keys might have real history
you want recovered. Pass `--timestamp <unix_time>` if you know better
(e.g. these keys were never used, so there's nothing to scan for).

### `wif_combo_import_via_rpc.py` — via a running node

```bash
bitcoind -server -daemon
python3 wif_combo_import_via_rpc.py --in wifs.txt --out my_wallet \
    --cookie ~/.bitcoin/.cookie
```

Creates the destination wallet (blank, descriptors-enabled) if it
doesn't exist, loads it if it's on disk but unloaded, and imports in
configurable batches (`--batch-size`, default 2000) via
`importdescriptors`.

## How this was verified

Every record type below was checked byte-for-byte against wallets
produced by real `bitcoind` (v28.1.0 and v31.1), not inferred from
documentation alone — the internal wallet database format is explicitly
**not** a stable public contract in Bitcoin Core, so guessing from docs
wasn't good enough.

- **Descriptor checksum** (BIP 380): implemented from Core's own
  `test/functional/test_framework/descriptors.py`, cross-checked against
  `bitcoin-cli getdescriptorinfo`.
- **Descriptor ID** (the hash used as the primary DB key for a
  descriptor's records): found in
  [`src/script/descriptor.cpp`](https://github.com/bitcoin/bitcoin/blob/master/src/script/descriptor.cpp)
  — `SHA256(descriptor.ToString(compat_format=true))`. The non-obvious
  part: the string that gets hashed is the **canonical pubkey-hex form**
  of the descriptor (with its own checksum), not the WIF form you import
  — matches what `getdescriptorinfo` normalizes to. Verified by
  computing the hash independently and diffing it against the real
  stored key byte-for-byte.
- **`walletdescriptorkey` value**: `compactsize(len) + DER-encoded
  SEC1 private key + CHash256(pubkey ‖ DER)`, per
  `WalletBatch::WriteDescriptorKey` in
  [`src/wallet/walletdb.cpp`](https://github.com/bitcoin/bitcoin/blob/master/src/wallet/walletdb.cpp).
  `Hash(pubkey, privkey)` in `src/hash.h` turned out to be plain
  `CHash256` (double SHA-256) over the raw byte concatenation.
- **DER template**: the SEC1 `ECPrivateKey` blob is identical across
  every key except two spots — the 32-byte private scalar and the
  33-byte compressed public key. Confirmed by diffing the DER output for
  two different real keys; the curve parameters (explicit secp256k1
  prime, `a`, `b`, generator point, order, cofactor) never change.
- **`walletdescriptor` value fields**: `descriptor_string +
  creation_time(u64) + range_start(i32) + range_end(i32) +
  next_index(i32)`, matching the `WalletDescriptor` struct field order in
  `src/wallet/walletutil.h`. Note Core clamps a requested
  `creation_time=0` to `1` internally — this tool does the same by
  default.
- **`walletdescriptorcache` isn't needed**: it only applies to ranged
  (HD) descriptors, for caching derived child pubkeys. `combo()` isn't
  ranged, so this whole record type is out of scope here.
- **SQLite pragmas**: `application_id` is written by Core as the
  *unsigned* value `4190024921` (what `file wallet.dat` reports) but
  must be set via `PRAGMA application_id = ...` as its *signed* 32-bit
  equivalent, `-104942375` — an easy off-by-sign bug (SQLite silently
  drops the pragma if the value doesn't fit `int32`, no error).
- **`CPubKey` inside a DB key needs a length prefix**: unlike a fixed 32-byte
  `uint256` (like the descriptor ID, no prefix), `CPubKey` serializes as
  `compactsize(len) + bytes`. Missing this produced a wallet that Core
  rejected with `"descriptor unencrypted key CPubKey corrupt"` — a clean
  failure, not silent corruption, but still worth calling out as the
  most likely mistake to reproduce.

Three real bugs were found and fixed this way during development — all
three failed loudly (SQLite silently ignoring an out-of-range pragma,
or Core's own consistency checks rejecting a malformed key), never
silently. That loud-failure property was a hard requirement before this
tool was written this way at all — anything that could *quietly*
produce a wallet with the wrong keys/addresses wasn't worth the
speed-up.

## Compatibility

Verified end-to-end against `bitcoind` v28.1.0 (wallet writer +
loader) and v31.1 (loader). Should work on any Core version supporting
descriptor/SQLite wallets (v25+), but if you're on a very different
version, verify against your own build before trusting it.

## License

MIT — see [LICENSE](LICENSE). `vendor/key.py` and `vendor/secp256k1.py`
are copyright the Bitcoin Core developers / Pieter Wuille, also MIT
licensed (see their file headers) — see the notes at the top of each
file for what, if anything, was changed from upstream.
