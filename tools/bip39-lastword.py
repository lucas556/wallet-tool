
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import hashlib
import sys
from typing import List

from mnemonic import Mnemonic


def normalize_words_arg(argv: List[str]) -> List[str]:
    # 支持：
    # 1) 11 个参数：w1 w2 ... w11
    # 2) 1 个参数（带空格的字符串）："w1 w2 ... w11"
    if len(argv) == 1:
        return argv[0].strip().split()
    return argv


def all_12word_mnemonics_from_11(words11: List[str]) -> List[str]:
    if len(words11) != 11:
        raise ValueError(f"Expected exactly 11 words, got {len(words11)}.")

    mnemo = Mnemonic("english")
    word2idx = {w: i for i, w in enumerate(mnemo.wordlist)}

    try:
        idxs = [word2idx[w] for w in words11]
    except KeyError as e:
        bad = str(e).strip("'")
        raise ValueError(f"Word not in BIP39 English wordlist: '{bad}'") from None

    bits121 = "".join(f"{i:011b}" for i in idxs)  # 121 bits
    if len(bits121) != 121:
        raise RuntimeError("Internal error: expected 121 bits from 11 words.")

    results: List[str] = []
    for tail in range(128):
        entropy_bits = bits121 + f"{tail:07b}"  # 128-bit entropy
        entropy_bytes = int(entropy_bits, 2).to_bytes(16, "big")

        checksum4 = hashlib.sha256(entropy_bytes).digest()[0] >> 4
        last_index = (tail << 4) | checksum4
        last_word = mnemo.wordlist[last_index]

        words12 = words11 + [last_word]
        phrase = " ".join(words12)

        # 自检：正常情况下都应 True
        if not mnemo.check(phrase):
            raise RuntimeError("Unexpected: generated mnemonic failed BIP39 check.")

        results.append(phrase)

    return results


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print(
            "Usage:\n"
            "  python3 bip39_lastword.py w1 w2 ... w11\n"
            "  python3 bip39_lastword.py \"w1 w2 ... w11\"",
            file=sys.stderr,
        )
        return 2

    words11 = normalize_words_arg(argv)

    try:
        lines = all_12word_mnemonics_from_11(words11)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    # 输出：一行一个 12 词助记词（横向）
    for line in lines:
        print(line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
