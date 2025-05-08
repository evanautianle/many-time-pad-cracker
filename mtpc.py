#!/usr/bin/env python3

import binascii
import argparse
import itertools
from collections import defaultdict

SPACE = 0x20  # ASCII for space

def xor_bytes(b1, b2):
    """XOR two bytes."""
    return b1 ^ b2

def is_printable_letter(xor_result):
    """Check if XOR result suggests both are letters (a-z, A-Z) or space."""
    return 65 <= xor_result <= 90 or 97 <= xor_result <= 122 or xor_result == SPACE

def guess_key_byte(column, min_confidence):
    """Guess the key byte for a column of ciphertexts."""
    space_candidates = defaultdict(int)

    for byte1, byte2 in itertools.combinations(column, 2):
        xor_result = xor_bytes(byte1, byte2)
        if is_printable_letter(xor_result):
            space_candidates[byte1] += 1
            space_candidates[byte2] += 1

    if space_candidates:
        likely_space_byte, confidence = max(space_candidates.items(), key=lambda x: x[1])
        if confidence >= min_confidence:
            return xor_bytes(likely_space_byte, SPACE)
    return 0  # Unknown key byte

def decrypt(ciphertexts, pad):
    """Decrypt ciphertexts using the guessed pad."""
    cleartexts = []
    for ct in ciphertexts:
        cleartext = bytearray()
        for i, byte in enumerate(ct):
            if i < len(pad) and pad[i] != 0:
                clear_byte = xor_bytes(byte, pad[i])
                cleartext.append(clear_byte if 32 <= clear_byte <= 126 else ord('?'))
            else:
                cleartext.append(ord('?'))
        cleartexts.append(cleartext)
    return cleartexts

def print_results(cleartexts, pad):
    """Print the decryption results and the guessed key."""
    print("Decryption results:\n")
    for i, line in enumerate(cleartexts, 1):
        try:
            print(f"{i:2}: {line.decode('ascii')}")
        except UnicodeDecodeError:
            print(f"{i:2}: [Contains non-ASCII characters]")

    print("\nGuessed key (hex):")
    print(binascii.hexlify(pad).decode('ascii'))

def main():
    parser = argparse.ArgumentParser(description="Many-time Pad Cracker")
    parser.add_argument("--filename", type=str, default="ciphertexts.txt",
                        help="File with ciphertexts (default: ciphertexts.txt)")
    parser.add_argument("--min-confidence", type=int, default=2,
                        help="Minimum confidence score for key byte (default: 2)")
    args = parser.parse_args()

    try:
        with open(args.filename) as f:
            ciphertexts = [binascii.unhexlify(line.strip()) for line in f if line.strip()]
    except Exception as e:
        print(f"Cannot crack {args.filename} --- {e}")
        raise SystemExit(-1)

    # Guess the key
    columns = itertools.zip_longest(*ciphertexts, fillvalue=0)
    pad = bytearray(guess_key_byte(col, args.min_confidence) for col in columns)

    # Decrypt and print results
    cleartexts = decrypt(ciphertexts, pad)
    print_results(cleartexts, pad)

if __name__ == "__main__":
    main()