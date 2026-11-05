#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 APlane Project LLC
"""Regenerates internal/crypto/wotsc/testdata/vectors.json.

This is a second implementation of the construction in plain Python, sharing
no code with the Go package. WOTS+C has no published test vectors, and both
were written from the same design by the same author: agreement catches coding
slips, not design mistakes. It isn't an independent oracle in the sense of
tools/xmssoracle, which checks against a separate RFC 8391 implementation.

    python3 tools/wotscoracle/oracle.py internal/crypto/wotsc/testdata/vectors.json
"""
import hashlib
import json
import struct
import sys

N, W, LEN, TARGET_SUM, HEIGHT, GRIND_LIMIT = 16, 16, 32, 240, 6, 8192
WOTS_HASH, WOTS_PK, TREE, WOTS_PRF = 0, 1, 2, 5


def sha256(data):
    return hashlib.sha256(data).digest()


def adrs(kind, keypair=0, chain=0, index=0):
    return bytes(9) + bytes([kind]) + struct.pack(">III", keypair, chain, index)


class Key:
    def __init__(self, sk_seed, sk_prf, pk_seed):
        self.sk_seed, self.sk_prf, self.pk_seed = sk_seed, sk_prf, pk_seed
        self.block = pk_seed + bytes(64 - N)
        self.levels = [[self.leaf(i) for i in range(2**HEIGHT)]]
        for z in range(HEIGHT):
            below = self.levels[-1]
            self.levels.append([
                self.th(adrs(TREE, 0, z + 1, t), below[2 * t] + below[2 * t + 1])
                for t in range(len(below) // 2)
            ])
        self.root = self.levels[-1][0]

    def th(self, address, message):
        return sha256(self.block + address + message)[:N]

    def chain(self, x, start, steps, leaf, chain):
        for k in range(start, start + steps):
            x = self.th(adrs(WOTS_HASH, leaf, chain, k), x)
        return x

    def secret(self, leaf, chain):
        return self.th(adrs(WOTS_PRF, leaf, chain), self.sk_seed)

    def leaf(self, leaf):
        ends = b"".join(self.chain(self.secret(leaf, j), 0, W - 1, leaf, j) for j in range(LEN))
        return self.th(adrs(WOTS_PK, leaf), ends)

    def digits(self, r, leaf, message):
        digest = sha256(self.pk_seed + self.root + r + struct.pack(">I", leaf) + message)[:N]
        return [nibble for byte in digest for nibble in (byte >> 4, byte & 15)]

    def sign(self, leaf, message):
        for ctr in range(GRIND_LIMIT):
            r = sha256(self.sk_prf + struct.pack(">I", leaf) + message + struct.pack(">I", ctr))[:N]
            digits = self.digits(r, leaf, message)
            if sum(digits) == TARGET_SUM:
                break
        else:
            raise RuntimeError("no randomizer reached the digit sum")
        values = [self.chain(self.secret(leaf, j), 0, digits[j], leaf, j) for j in range(LEN)]
        auth = [self.levels[z][(leaf >> z) ^ 1] for z in range(HEIGHT)]
        return struct.pack(">I", leaf) + r + b"".join(values) + b"".join(auth), ctr


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: oracle.py <out.json>")
    seed = bytes(range(48))
    sk_seed, sk_prf, pk_seed = seed[:16], seed[16:32], seed[32:48]
    key = Key(sk_seed, sk_prf, pk_seed)
    cases = []
    for leaf in (0, 1, 5, 31, 32, 62, 63):
        for label in (b"first message", b"second message"):
            message = sha256(label)
            signature, ctr = key.sign(leaf, message)
            cases.append({
                "leaf": leaf,
                "message": message.hex(),
                "counter": ctr,
                "signature": signature.hex(),
            })
    out = {
        "sk_seed": sk_seed.hex(),
        "sk_prf": sk_prf.hex(),
        "pk_seed": pk_seed.hex(),
        "root": key.root.hex(),
        "cases": cases,
    }
    with open(sys.argv[1], "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
        f.write("\n")


if __name__ == "__main__":
    main()
