"""Authenticate and encrypt build payloads for an isolated CI runner."""
import base64
import os
from pathlib import Path
import sys

local_dependencies = Path(__file__).with_name("uform-public-deps")
if local_dependencies.is_dir():
    sys.path.insert(0, str(local_dependencies))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD = b"ios-ci-archive/v1"


def main():
    mode, source, target = sys.argv[1:]
    key = base64.b64decode(os.environ["CI_PAYLOAD_KEY"], validate=True)
    if len(key) != 32:
        raise ValueError("Invalid build archive encryption key")
    data = Path(source).read_bytes()
    cipher = AESGCM(key)
    if mode == "encrypt":
        nonce = os.urandom(12)
        output = nonce + cipher.encrypt(nonce, data, AAD)
    elif mode == "decrypt":
        output = cipher.decrypt(data[:12], data[12:], AAD)
    else:
        raise ValueError("Unexpected encryption mode")
    with Path(target).open("xb") as stream:
        stream.write(output)


if __name__ == "__main__":
    main()
