"""Encrypt the Fund I deck for ftventures.io/deck.

Usage:  python3 tools/encrypt_deck.py path/to/deck.pdf
Asks for the password, writes deck/deck.bin. Never commit the PDF itself
(deck/*.pdf is git-ignored). Format: salt(16) | iv(12) | AES-256-GCM ciphertext,
key = PBKDF2-SHA256(password, salt, 600000). Must match deck/index.html.
"""
import os, sys, getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 600_000
src = sys.argv[1]
pw = os.environ.get("DECK_PASSWORD") or getpass.getpass("Deck password: ")
salt, iv = os.urandom(16), os.urandom(12)
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode())
data = open(src, "rb").read()
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "deck", "deck.bin")
open(out, "wb").write(salt + iv + AESGCM(key).encrypt(iv, data, None))
print("wrote", os.path.normpath(out), len(data), "bytes in")
