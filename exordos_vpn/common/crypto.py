#    Copyright 2026 Genesis Corporation.
#
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from oslo_config import cfg

from exordos_vpn.common import constants as c

CONF = cfg.CONF

# AES-256-GCM nonce size in bytes
_NONCE_SIZE = 12


def _get_encryption_key():
    """Get the AES-256-GCM key from config (hex-encoded 32 bytes)."""
    key_hex = CONF[c.COMMON_DOMAIN].otp_encryption_key
    return bytes.fromhex(key_hex)


def encrypt_otp_secret(plaintext_secret):
    """Encrypt an OTP secret using AES-256-GCM.

    Args:
        plaintext_secret: Base32-encoded TOTP secret string.

    Returns:
        Base64-encoded string of nonce + ciphertext + tag.
    """
    key = _get_encryption_key()
    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_secret.encode("utf-8"), None)
    # ciphertext includes the 16-byte GCM tag at the end
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_otp_secret(encrypted_secret):
    """Decrypt an OTP secret using AES-256-GCM.

    Args:
        encrypted_secret: Base64-encoded nonce + ciphertext + tag.

    Returns:
        Base32-encoded TOTP secret string.

    Raises:
        cryptography.exceptions.InvalidTag: if decryption fails
            (tampered data or wrong key).
    """
    key = _get_encryption_key()
    raw = base64.b64decode(encrypted_secret)
    nonce = raw[:_NONCE_SIZE]
    ciphertext = raw[_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
