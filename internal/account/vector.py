"""Independent synthetic test vector generator: python internal/account/vector.py"""
import hashlib
import hmac
import unicodedata

def hkdf(value, salt, label):
    prk = hmac.digest(salt, value, "sha256")
    return hmac.digest(prk, label + b"\x01", "sha256")

account = bytes(range(16))
salt = bytes(range(16, 32))
secret = bytes(range(32, 48))
password = unicodedata.normalize("NFKD", " Démo ").strip().encode()
ps = hkdf(salt, account, b"locklark/m0/password-salt")
p = hashlib.pbkdf2_hmac("sha256", password, ps, 650000)
s = hkdf(secret, account, b"locklark/m0/secret-key")
print(bytes(x ^ y for x, y in zip(p, s)).hex())
