"""Generate the synthetic Classic KM2 vector with the OpenSSL TLS1-PRF KDF."""

import subprocess


def block(n, base):
    return bytes(range(base, base + n))


def prf(length, secret, seed):
    return bytes.fromhex(subprocess.check_output(
        ["openssl", "kdf", "-keylen", str(length), "-kdfopt", "digest:MD5-SHA1",
         "-kdfopt", "hexsecret:" + secret.hex(), "-kdfopt", "hexseed:" + seed.hex(), "TLS1-PRF"],
        text=True,
    ).strip().replace(":", ""))


secret = prf(48, block(48, 0), b"OpenVPN master secret" + block(32, 0x40) + block(32, 0x80))
keys = prf(256, secret, b"OpenVPN key expansion" + block(32, 0x60) + block(32, 0xa0)
           + block(8, 0xc0) + block(8, 0xd0))
for offset in range(0, len(keys), 32):
    print(keys[offset:offset + 32].hex())
print("odd", prf(19, b"odd", b"seed").hex())
