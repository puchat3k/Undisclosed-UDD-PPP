#!/usr/bin/env python3
from pathlib import Path
import os, json, hashlib, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

root = Path(__file__).resolve().parent
manifest = json.loads((root / "GSV_FULL_20260914.encryption-manifest.json").read_text())
parts = sorted(root.glob("GSV_FULL_20260914.part*.b64"))
if len(parts) != manifest["part_count"]:
    raise SystemExit(f"Expected {manifest['part_count']} parts, found {len(parts)}")

b64_text = "".join("".join(p.read_text().split()) for p in parts)
if hashlib.sha256(b64_text.encode()).hexdigest() != manifest["compact_base64_sha256"]:
    raise SystemExit("Base64 transport hash mismatch")
enc = base64.b64decode(b64_text, validate=True)
if hashlib.sha256(enc).hexdigest() != manifest["encrypted_binary_sha256"]:
    raise SystemExit("Encrypted payload SHA-256 mismatch")
if enc[:8] != b"UDDENC1\x00":
    raise SystemExit("Unexpected encrypted payload format")

key_hex = os.environ.get("UDD_KEY_HEX", "")
if len(key_hex) != 64:
    raise SystemExit("Set UDD_KEY_HEX to the 64-hex-character key")
try:
    key = bytes.fromhex(key_hex)
except ValueError:
    raise SystemExit("UDD_KEY_HEX is not valid hexadecimal")

nonce = enc[8:20]
ciphertext_and_tag = enc[20:]
plain = AESGCM(key).decrypt(nonce, ciphertext_and_tag, manifest["aad"].encode())
if hashlib.sha256(plain).hexdigest() != manifest["source_sha256"]:
    raise SystemExit("Plaintext SHA-256 mismatch")
out = root / "GSV_FULL_20260914.zip"
out.write_bytes(plain)
print(f"Verified and decrypted: {out}")
print(f"SHA256: {manifest['source_sha256']}")
