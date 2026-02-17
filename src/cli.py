#!/usr/bin/env python3
"""
CryptoShield CLI - Command-line interface for advanced users.
Usage: python -m cli encrypt <file> -p <password> [--algo AES-256|ChaCha20]
       python -m cli decrypt <file> -p <password>
       python -m cli hash <file>
       python -m cli verify <file> <expected_hash>
"""

import argparse
import os
import sys

from core.logger import get_logger

# Ensure src is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from encryption.algorithms import get_algorithm
from integrity.hasher import Hasher


def cmd_encrypt(args):
    Engine = get_algorithm(args.algorithm)
    engine = Engine(args.password)
    out = engine.encrypt_file(args.file, delete_original=args.secure_delete)
    logger = get_logger()
    logger.info("CLI encrypted '%s' → '%s' using %s", args.file, out, args.algorithm)
    print(f"Encrypted: {out}")


def cmd_decrypt(args):
    Engine = get_algorithm(args.algorithm)
    engine = Engine(args.password)
    logger = get_logger()
    try:
        out = engine.decrypt_file(args.file)
    except Exception as exc:
        logger.error("CLI failed to decrypt '%s' using %s: %s", args.file, args.algorithm, exc)
        raise
    else:
        logger.info("CLI decrypted '%s' → '%s' using %s", args.file, out, args.algorithm)
        print(f"Decrypted: {out}")


def cmd_hash(args):
    h = Hasher()
    print(h.generate_hash(args.file))


def cmd_verify(args):
    h = Hasher()
    ok = h.verify_hash(args.file, args.hash)
    print("OK" if ok else "MISMATCH")
    sys.exit(0 if ok else 1)


def main():
    parser = argparse.ArgumentParser(description="CryptoShield CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("file", help="File to encrypt")
    enc.add_argument("-p", "--password", required=True, help="Password")
    enc.add_argument("--algo", "--algorithm", dest="algorithm", default="AES-256", choices=["AES-256", "ChaCha20"], help="Encryption algorithm")
    enc.add_argument("--secure-delete", action="store_true", help="Securely delete original after encryption")
    enc.set_defaults(func=cmd_encrypt)

    dec = sub.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("file", help="File to decrypt")
    dec.add_argument("-p", "--password", required=True, help="Password")
    dec.add_argument("--algo", "--algorithm", dest="algorithm", default="AES-256", choices=["AES-256", "ChaCha20"])
    dec.set_defaults(func=cmd_decrypt)

    h = sub.add_parser("hash", help="Generate SHA-256 hash")
    h.add_argument("file", help="File path")
    h.set_defaults(func=cmd_hash)

    v = sub.add_parser("verify", help="Verify file hash")
    v.add_argument("file", help="File path")
    v.add_argument("hash", help="Expected SHA-256 hash")
    v.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
