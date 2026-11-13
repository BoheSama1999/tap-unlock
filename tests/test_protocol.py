import os
import sys
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "laptop"))
import tapunlock_protocol as proto  # noqa: E402


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def phone_response(private_key, challenge):
    nonce = challenge[4:]
    signature = private_key.sign(proto.signed_message(nonce), ec.ECDSA(hashes.SHA256()))
    return b"NK\x01\x02" + nonce[:4] + signature


class ChallengeBookTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.book = proto.ChallengeBook(clock=self.clock)
        self.phone = ec.generate_private_key(ec.SECP256R1())
        self.keys = [self.phone.public_key()]

    def challenge(self):
        return proto.challenge_payload(self.book.nonce)

    def test_valid_response_is_accepted_once(self):
        response = phone_response(self.phone, self.challenge())
        self.assertTrue(self.book.verify(response, self.keys))
        self.assertFalse(self.book.verify(response, self.keys))

    def test_response_signed_by_unknown_key_is_rejected(self):
        stranger = ec.generate_private_key(ec.SECP256R1())
        self.assertFalse(self.book.verify(phone_response(stranger, self.challenge()), self.keys))

    def test_tampered_signature_is_rejected(self):
        response = bytearray(phone_response(self.phone, self.challenge()))
        response[-1] ^= 0x01
        self.assertFalse(self.book.verify(bytes(response), self.keys))

    def test_response_for_previous_nonce_valid_only_within_grace(self):
        old = phone_response(self.phone, self.challenge())
        self.book.rotate()
        self.clock.now += proto.GRACE_SECONDS - 1
        self.assertTrue(self.book.verify(old, self.keys))

        old = phone_response(self.phone, self.challenge())
        self.book.rotate()
        self.clock.now += proto.GRACE_SECONDS + 1
        self.assertFalse(self.book.verify(old, self.keys))

    def test_accepting_one_response_burns_the_previous_nonce_too(self):
        before_rotation = phone_response(self.phone, self.challenge())
        self.book.rotate()
        self.assertTrue(self.book.verify(phone_response(self.phone, self.challenge()), self.keys))
        self.assertFalse(self.book.verify(before_rotation, self.keys))

    def test_rotation_is_due_after_interval(self):
        self.assertFalse(self.book.due_for_rotation())
        self.clock.now += proto.ROTATE_SECONDS
        self.assertTrue(self.book.due_for_rotation())

    def test_challenge_frame_is_not_a_response(self):
        self.assertFalse(self.book.verify(self.challenge(), self.keys))
        self.assertEqual(len(self.challenge()), 20)


if __name__ == "__main__":
    unittest.main()
