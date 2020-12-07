from base64 import b64encode, b64decode

from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256


def get_key(filename: str) -> RSA.RsaKey:
    with open(filename, 'r') as fh:
        data = fh.read()
        return RSA.import_key(data)


def sign(priv_key, msg) -> str:
    if isinstance(msg, str):
        msg = msg.encode('utf8')
    elif not isinstance(msg, bytes):
        raise ValueError

    hash = SHA256.new(msg)
    signer = PKCS115_SigScheme(priv_key)
    signature = signer.sign(hash)
    return b64encode(signature)


def verify(public_key, msg, signature) -> bool:
    if isinstance(msg, str):
        msg = msg.encode('utf8')
    elif not isinstance(msg, bytes):
        raise ValueError

    hash = SHA256.new(msg)
    verifier = PKCS115_SigScheme(public_key)
    try:
        verifier.verify(hash, b64decode(signature))
        return True
    except ValueError:
        return False
