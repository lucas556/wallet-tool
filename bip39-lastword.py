#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bip39-lastword — Derive the 12th BIP39 English mnemonic word from the first 11 words.

What it does
------------
Given 11 English BIP39 words (for a 12-word mnemonic), this tool enumerates the 128
possible 7-bit entropy tails, computes the 4-bit checksum for each, and produces the
corresponding 12th-word candidate. Exactly ONE candidate should pass BIP39 checksum
validation if the first 11 words are correct (otherwise, you may get 0 valid results).

Offline & safety
----------------
- Runs fully offline.
- This tool is intended for recovering YOUR OWN wallet or verifying your own mnemonic.

Usage
-----
A) Pass 11 words as separate args:
    python3 bip39_lastword.py toss measure okay still kidney dad sleep tuna salt rib ritual

B) Pass a single quoted string:
    python3 bip39_lastword.py "toss measure okay still kidney dad sleep tuna salt rib ritual"


"""

from __future__ import annotations

import argparse
import hashlib
import sys
from typing import List, Tuple

from mnemonic import Mnemonic


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bip39-lastword", add_help=True)
    p.add_argument(
        "words",
        nargs="+",
        help="11 BIP39 English words. You can pass 11 args or one quoted string with 11 words.",
    )
    p.add_argument(
        "--valid-only",
        action="store_true",
        help="Only print the valid 12th word (and full mnemonic).",
    )
    p.add_argument(
        "--all",
        action="store_true",
        help="Print all 128 candidates and mark the valid one (default behavior).",
    )
    return p


def normalize_words_arg(words_arg: List[str]) -> List[str]:
    # Support:
    #  - 11 separate args
    #  - a single quoted string with spaces
    if len(words_arg) == 1:
        words = words_arg[0].strip().split()
    else:
        words = words_arg
    return words


def all_last_words_from_11(
    mnemo: Mnemonic, words11: List[str]
) -> List[Tuple[int, int, str, bool]]:
    if len(words11) != 11:
        raise ValueError(f"Expected exactly 11 words, got {len(words11)}.")

    # Optimization: O(1) word -> index lookups
    word2idx = {w: i for i, w in enumerate(mnemo.wordlist)}

    try:
        idxs = [word2idx[w] for w in words11]
    except KeyError as e:
        bad = str(e).strip("'")
        raise ValueError(f"Word not in BIP39 English wordlist: '{bad}'") from None

    bits121 = "".join(f"{i:011b}" for i in idxs)  # 11*11 = 121 bits
    # no assert; raise explicit error if something is off (should never happen)
    if len(bits121) != 121:
        raise RuntimeError("Internal error: expected 121 bits from 11 words.")

    out: List[Tuple[int, int, str, bool]] = []
    for tail in range(128):  # 7-bit tail
        entropy_bits = bits121 + f"{tail:07b}"  # total 128-bit entropy
        entropy_bytes = int(entropy_bits, 2).to_bytes(16, "big")

        checksum4 = hashlib.sha256(entropy_bytes).digest()[0] >> 4
        last_index = (tail << 4) | checksum4
        last_word = mnemo.wordlist[last_index]

        phrase = " ".join(words11 + [last_word])
        ok = mnemo.check(phrase)

        out.append((tail, last_index, last_word, ok))

    return out


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    words11 = normalize_words_arg(args.words)
    # default output: show all candidates unless --valid-only specified

    mnemo = Mnemonic("english")

    try:
        cands = all_last_words_from_11(mnemo, words11)
    except Exception as e:
        print(f"[bip39-lastword] Error: {e}", file=sys.stderr)
        return 2

    valid = [x for x in cands if x[3]]


    tail, idx, w12, _ = valid[0]
    full = " ".join(words11 + [w12])
    print(f"Valid 12th word: {w12} (tail={tail}, index={idx})")
    print(f"Full mnemonic: {full}")


if __name__ == "__main__":
    raise SystemExit(main())
