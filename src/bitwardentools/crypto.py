#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import base64
import hashlib
import re
import secrets
import string
from base64 import b64decode, b64encode
from enum import IntEnum
from hashlib import pbkdf2_hmac, sha256
from hmac import new as hmac_new
from secrets import token_bytes

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from hkdf import hkdf_expand


class CIPHERS(IntEnum):
    sym = 2
    asym = 4


CACHE = {}
ITERATIONS = 2000000
ENCODED_CIPHER = {
    CIPHERS.sym: "{typ}.{b64_iv}|{b64_ct}|{b64_digest}",
    CIPHERS.asym: "{typ}.{b64_ct}",
}
ENCRYPTED_STRING_RE = re.compile("^[0-9][.].*=.*", flags=re.I | re.M)
SYM_ENCRYPTED_STRING_RE = re.compile(
    "^2[.][^=]+=+[|][^=]+=+[|][^=]+=+", flags=re.I | re.M
)


class UnimplementedError(Exception):
    """."""


class DecodeEncKeyError(ValueError):
    """."""


class WrongFormatError(DecodeEncKeyError):
    """."""


class WrongTypeDecryptError(DecodeEncKeyError):
    """."""


class MissingPartsDecryptError(DecodeEncKeyError):
    """."""


class B64DecryptError(DecodeEncKeyError):
    """."""


class DecryptError(ValueError):
    """."""


def decode_cipher_string(cipher_string):
    """decode a cipher tring into it's parts"""
    iv = None
    mac = None
    if not ENCRYPTED_STRING_RE.match(cipher_string):
        raise WrongFormatError(f"{cipher_string}")
    try:
        typ = cipher_string[0:1]
        typ = int(typ)
        assert typ < 9
    except (AssertionError, ValueError):
        raise WrongTypeDecryptError(f"{typ} is not valid")
    ct = cipher_string[2:]
    if typ == CIPHERS.asym:
        pass
    else:
        try:
            if typ == 0:
                iv, ct = ct.split("|", 2)
            else:
                iv, ct, mac = ct.split("|", 3)
        except Exception:
            raise MissingPartsDecryptError(f"{ct} is missing parts")
    if iv:
        try:
            iv = b64decode(iv)
        except Exception:
            raise B64DecryptError(f"iv {iv} not valid")
    if mac:
        try:
            mac = b64decode(mac)[0:32]
        except Exception:
            raise B64DecryptError(f"mac {mac} not valid")
    try:
        ct = b64decode(ct)
    except Exception:
        raise B64DecryptError(f"ct {ct} not valid")
    return typ, iv, ct, mac


def is_encrypted(cipher_string):
    try:
        decode_cipher_string(cipher_string)
    except DecodeEncKeyError:
        return False
    else:
        return True


def make_master_key(password, salt, iterations=ITERATIONS):
    salt = salt.lower()
    if not hasattr(password, "decode"):
        password = password.encode("utf-8")
    if not hasattr(salt, "decode"):
        salt = salt.encode("utf-8")
    return pbkdf2_hmac("sha256", password, salt, iterations)


def hash_password(password, salt, iterations=ITERATIONS):
    """base64-encode a wrapped, stretched password+salt(email) for signup/login"""
    if not hasattr(password, "decode"):
        password = password.encode("utf-8")
    master_key = make_master_key(password, salt, iterations)
    hashpw = hashlib.pbkdf2_hmac("sha256", master_key, password, 1)
    return base64.b64encode(hashpw), master_key


def load_rsa_key(key):
    rsakeys = CACHE.setdefault("rsa", {})
    if not isinstance(key, RSA.RsaKey):
        try:
            key = rsakeys[key]
        except KeyError:
            rsakeys[key] = RSA.importKey(key)
            key = rsakeys[key]
    return key


def aes_encrypt(plaintext, key, charset="utf-8"):
    enc, mac = get_sym_enc_mac(key)
    if not hasattr(plaintext, "decode"):
        plaintext = plaintext.encode(charset)
    pad_len = 16 - len(plaintext) % 16
    padding = bytes([pad_len] * pad_len)
    content = plaintext + padding
    iv = token_bytes(16)
    c = AES.new(enc, AES.MODE_CBC, iv)
    ct = c.encrypt(content)
    cmac = hmac_new(mac, iv + ct, sha256)
    return iv, ct, cmac


def encrypt_sym(plaintext, key, to_bytes=False, *a, **kw):
    # inspired from bitwarden/jslib:src/services/crypto.service.ts
    typ, (iv, ct, mac) = int(CIPHERS.sym), aes_encrypt(plaintext, key, *a, **kw)
    if mac:
        mac = mac.digest()
    if to_bytes:
        # jslib: encryptToBytes()
        ret = chr(typ).encode()
        ret += iv
        if mac:
            ret += mac
        ret += ct
    else:
        # jslib: encrypt()
        b64_iv = b64encode(iv).decode()
        b64_ct = b64encode(ct).decode()
        b64_digest = ""
        if mac:
            b64_digest = b64encode(mac).decode()
        ret = ENCODED_CIPHER[typ].format(**locals())
    return ret


def encrypt_sym_to_bytes(plaintext, key, *a, **kw):
    kw["to_bytes"] = True
    return encrypt_sym(plaintext, key, *a, **kw)


def encrypt_asym(plaintext, key, *a, **kw):
    cipher = PKCS1_OAEP.new(load_rsa_key(key)).encrypt(plaintext)
    b64_ct = b64encode(cipher).decode()
    typ = CIPHERS.asym
    return ENCODED_CIPHER[typ].format(**locals())


def encrypt(typ, plaintext, key, *a, **kw):
    try:
        enc = ENCRYPT[typ]
    except KeyError:
        raise UnimplementedError(f"can not encrypt type:{typ}")
    return enc(plaintext=plaintext, key=key, *a, **kw)


def get_sym_enc_mac(key):
    # symmetric master_key of the user
    if len(key) == 32:
        enc = hkdf_expand(key, b"enc", 32, sha256)
        mac = hkdf_expand(key, b"mac", 32, sha256)
    # symmetric key of an organization
    elif len(key) == 64:
        enc = key[:32]
        mac = key[32:]
    return enc, mac


def decrypt_sym(dct, key, div, dmac, *a, **kw):
    enc, mac = get_sym_enc_mac(key)
    hdmac = hmac_new(mac, div + dct, sha256).digest()
    if hdmac != dmac:
        raise DecryptError(f"Symetric hmac verification failed {hdmac} / {dmac}")
    c = AES.new(enc, AES.MODE_CBC, div)
    plaintext = c.decrypt(dct)
    pad_len = plaintext[-1]
    padding = bytes([pad_len] * pad_len)
    if plaintext[-pad_len:] == padding:
        plaintext = plaintext[:-pad_len]
    return plaintext


def decrypt_asym(dct, key, *a, **kw):
    return PKCS1_OAEP.new(load_rsa_key(key)).decrypt(dct)


def decrypt_bytes(cipher_bytes, key, *a, **kw):
    ret, typ = None, cipher_bytes[0]
    if typ in [2]:
        iv = cipher_bytes[1:17]
        mac = cipher_bytes[17:49]
        ct = cipher_bytes[49:]
        ret = decrypt_sym(ct, key, iv, mac)
    else:
        raise UnimplementedError(f"{typ} encType decryption is not implemented")
    return ret


def decrypt(cipher_string, key, *a, **kw):
    typ, iv, ct, mac = decode_cipher_string(cipher_string)
    try:
        dec = DECRYPT[typ]
    except KeyError:
        raise UnimplementedError(f"can not decrypt type:{typ}")
    return dec(div=iv, dct=ct, dmac=mac, key=key, *a, **kw)


def strech_key(key):
    stretched_key = key
    if len(stretched_key) < 64:
        stretched_key = hkdf_expand(key, b"enc", 32, sha256) + hkdf_expand(
            key, b"mac", 32, sha256
        )
    return stretched_key


def make_sym_key(master_key):
    stretched_key = strech_key(master_key)
    plaintext = token_bytes(64)
    return encrypt_sym(plaintext, stretched_key), plaintext


def make_asym_key(key, stretch=True):
    if stretch:
        key = strech_key(key)
    asym_key = RSA.generate(2048)
    public_key = asym_key.publickey().exportKey("DER")
    private_key = asym_key.exportKey("DER", pkcs=8)
    return encrypt_sym(private_key, key), public_key, private_key


def gen_password(length=32, alphabet=None):
    alphabet = string.ascii_letters + string.digits
    while True:
        password = "".join(secrets.choice(alphabet) for i in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and sum(c.isdigit() for c in password) >= 3
        ):
            break
    return password


DECRYPT = {CIPHERS.sym: decrypt_sym, CIPHERS.asym: decrypt_asym}
ENCRYPT = {CIPHERS.sym: encrypt_sym, CIPHERS.asym: encrypt_asym}
# vim:set et sts=4 ts=4 tw=120:
