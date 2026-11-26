"""Reproduce OpenVPN test vectors independently of the Go implementation."""

import hashlib
import hmac
import json
from pathlib import Path
from struct import pack

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


LABEL = b"EXPORTER-OpenVPN-datakeys"
SIZE = 256


def tls12_export():
    # RFC 5705 with the TLS 1.2 SHA-256 P_hash and no context.
    master = bytes(range(48))
    seed = LABEL + bytes(range(48, 112))
    digest = lambda msg: hmac.new(master, msg, hashlib.sha256).digest()
    last = seed
    result = b""
    while len(result) < SIZE:
        last = digest(last)
        result += digest(last + seed)
    return result[:SIZE]


def expand_label(secret, label, context, length):
    # RFC 8446 HKDF-Expand-Label using SHA-256.
    label = b"tls13 " + label
    info = pack("!HB", length, len(label)) + label + bytes([len(context)]) + context
    output = previous = b""
    for index in range(1, (length + 31) // 32 + 1):
        previous = hmac.new(secret, previous + info + bytes([index]), hashlib.sha256).digest()
        output += previous
    return output[:length]


def tls13_export():
    empty_hash = hashlib.sha256(b"").digest()
    secret = expand_label(bytes(range(32)), LABEL, empty_hash, 32)
    return expand_label(secret, b"exporter", empty_hash, SIZE)


def packet(cipher, key, implicit, peer_id, payload):
    header = bytes([9 << 3]) + peer_id.to_bytes(3, "big") + pack("!I", 1)
    conventional = cipher(key).encrypt(header[4:] + implicit, payload, header)
    return header + conventional[-16:] + conventional[:-16]


def main():
    fixtures = []
    peer_id = 0x123456
    plaintext = bytes.fromhex("4500001800010000401100000a3100020a31000101020304")
    for version, exporter in [("tls12", tls12_export), ("tls13", tls13_export)]:
        material = exporter()
        for name, cipher, width in [
            ("AES-128-GCM", AESGCM, 16),
            ("AES-256-GCM", AESGCM, 32),
            ("CHACHA20-POLY1305", ChaCha20Poly1305, 32),
        ]:
            vectors = {"version": version, "cipher": name, "exporter": material.hex(),
                       "peer_id": peer_id, "plaintext": plaintext.hex()}
            for direction, offset in [("c2s", 0), ("s2c", 128)]:
                secret = material[offset:offset + width]
                implicit = material[offset + 64:offset + 72]
                vectors[direction] = packet(cipher, secret, implicit, peer_id, plaintext).hex()
            fixtures.append(vectors)
    destination = Path(__file__).with_name("vectors.json")
    destination.write_text(json.dumps(fixtures, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
