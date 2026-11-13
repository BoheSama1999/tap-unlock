"""Tap Unlock wire protocol (pure logic, no D-Bus / Bluetooth).

Both frames travel as BLE manufacturer-specific data under company ID 0xFFFF.

  challenge (laptop -> phone, legacy advertising, 20 bytes):
      "NK" | version=0x01 | type=0x01 | nonce[16]

  response  (phone -> laptop, extended advertising, 8 + DER bytes):
      "NK" | version=0x01 | type=0x02 | nonce[0:4] | ECDSA-P256-SHA256 DER signature
      signature covers CONTEXT | nonce

Replay protection: the laptop only accepts a signature over a nonce it is
currently advertising, and a nonce is destroyed the moment one response for it
verifies.  A captured response therefore never verifies a second time, and a
response captured before the nonce rotated is useless after the grace period.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

COMPANY_ID = 0xFFFF
MAGIC = b"NK"
VERSION = 0x01
TYPE_CHALLENGE = 0x01
TYPE_RESPONSE = 0x02
NONCE_LEN = 16
HINT_LEN = 4
CONTEXT = b"tap-unlock/v1\x00"

ROTATE_SECONDS = 30.0
GRACE_SECONDS = 5.0


def challenge_payload(nonce: bytes) -> bytes:
    return MAGIC + bytes([VERSION, TYPE_CHALLENGE]) + nonce


def is_response(data: bytes) -> bool:
    return len(data) > 4 + HINT_LEN and data[:4] == MAGIC + bytes([VERSION, TYPE_RESPONSE])


def signed_message(nonce: bytes) -> bytes:
    return CONTEXT + nonce


class ChallengeBook:
    def __init__(self, clock: Callable[[], float] = time.monotonic,
                 rand: Callable[[int], bytes] = os.urandom) -> None:
        self._clock = clock
        self._rand = rand
        self._current = b""
        self._current_born = 0.0
        self._previous = b""
        self._previous_until = 0.0
        self.rotate()

    @property
    def nonce(self) -> bytes:
        return self._current

    def due_for_rotation(self) -> bool:
        return self._clock() - self._current_born >= ROTATE_SECONDS

    def rotate(self) -> None:
        now = self._clock()
        self._previous, self._previous_until = self._current, now + GRACE_SECONDS
        self._current, self._current_born = self._rand(NONCE_LEN), now

    def _live_nonces(self) -> list[bytes]:
        live = [self._current]
        if self._previous and self._clock() < self._previous_until:
            live.append(self._previous)
        return live

    def verify(self, data: bytes, keys: Iterable[ec.EllipticCurvePublicKey]) -> bool:
        if not is_response(data):
            return False
        hint, signature = data[4:4 + HINT_LEN], data[4 + HINT_LEN:]
        for nonce in self._live_nonces():
            if nonce[:HINT_LEN] != hint:
                continue
            message = signed_message(nonce)
            for key in keys:
                try:
                    key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
                except InvalidSignature:
                    continue
                self._burn()
                return True
        return False

    def _burn(self) -> None:
        self._previous, self._previous_until = b"", 0.0
        self._current, self._current_born = self._rand(NONCE_LEN), self._clock()
