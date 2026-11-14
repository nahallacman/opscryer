# SPDX-License-Identifier: Apache-2.0
"""Comprehensive unit tests for pure-stdlib PQC security primitives & Shamir Secret Sharing."""

import hashlib
import json
from pathlib import Path
import secrets
import sys
import unittest

_PKG_DIR = Path(__file__).resolve().parent.parent
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from pqc_security import (
    gf256_div,
    gf256_mul,
    split_secret_shares,
    reconstruct_secret_from_shares,
    verify_multi_key_locks,
    generate_pqc_keypair,
    pqc_sign,
    pqc_verify,
    pqc_seal,
    pqc_unseal,
)


class TestGF256Arithmetic(unittest.TestCase):
    """Test GF(256) finite field arithmetic properties."""

    def test_multiplication_identity_and_zero(self):
        self.assertEqual(gf256_mul(0, 42), 0)
        self.assertEqual(gf256_mul(42, 0), 0)
        self.assertEqual(gf256_mul(1, 42), 42)
        self.assertEqual(gf256_mul(42, 1), 42)

    def test_multiplication_commutativity(self):
        for _ in range(50):
            a = secrets.randbelow(256)
            b = secrets.randbelow(256)
            self.assertEqual(gf256_mul(a, b), gf256_mul(b, a))

    def test_division_and_inverse(self):
        self.assertEqual(gf256_div(0, 42), 0)
        with self.assertRaises(ZeroDivisionError):
            gf256_div(42, 0)

        for a in range(1, 256):
            inv = gf256_div(1, a)
            self.assertEqual(gf256_mul(a, inv), 1)

        for _ in range(50):
            a = secrets.randbelow(256)
            b = secrets.randbelow(255) + 1  # 1..255
            q = gf256_div(a, b)
            self.assertEqual(gf256_mul(q, b), a)


class TestShamirSecretSharing(unittest.TestCase):
    """Test pure-stdlib GF(256) Shamir Secret Sharing."""

    def test_1_of_1_single_master_key_fast_pass(self):
        secret = b"OpsCryer-Single-Master-Key-Secret-Payload-12345"
        shares = split_secret_shares(secret, k=1, n=1)
        self.assertEqual(len(shares), 1)
        self.assertEqual(shares[0]["k"], 1)
        self.assertEqual(shares[0]["n"], 1)
        self.assertEqual(shares[0]["x"], 1)
        self.assertEqual(shares[0]["data"], secret.hex())

        reconstructed = reconstruct_secret_from_shares(shares)
        self.assertEqual(reconstructed, secret)

    def test_2_of_3_threshold_reconstruction_all_combinations(self):
        secret = b"Threshold-Secret-2-of-3-AlphaBetaGamma"
        shares = split_secret_shares(secret, k=2, n=3)
        self.assertEqual(len(shares), 3)

        # Any 2 of 3 must reconstruct perfectly
        combos = [
            [shares[0], shares[1]],
            [shares[0], shares[2]],
            [shares[1], shares[2]],
            [shares[2], shares[0]],
            shares,  # All 3
        ]
        for combo in combos:
            reconstructed = reconstruct_secret_from_shares(combo)
            self.assertEqual(reconstructed, secret)

    def test_3_of_5_threshold_reconstruction(self):
        secret = secrets.token_bytes(64)
        shares = split_secret_shares(secret, k=3, n=5)
        self.assertEqual(len(shares), 5)

        # Valid 3-combinations
        sub1 = [shares[0], shares[2], shares[4]]
        sub2 = [shares[1], shares[3], shares[4]]
        sub3 = [shares[0], shares[1], shares[2]]

        self.assertEqual(reconstruct_secret_from_shares(sub1), secret)
        self.assertEqual(reconstruct_secret_from_shares(sub2), secret)
        self.assertEqual(reconstruct_secret_from_shares(sub3), secret)

    def test_insufficient_shares_fails(self):
        secret = b"TopSecretOperationalData"
        shares = split_secret_shares(secret, k=3, n=5)

        # 2 shares when 3 required
        with self.assertRaises(ValueError):
            reconstruct_secret_from_shares([shares[0], shares[1]])

    def test_duplicate_shares_deduplicated_and_validated(self):
        secret = b"ImportantClusterToken"
        shares = split_secret_shares(secret, k=2, n=3)

        # Duplicate of share 0 twice
        with self.assertRaises(ValueError):
            reconstruct_secret_from_shares([shares[0], shares[0]])

    def test_tampered_share_fails_fingerprint(self):
        secret = b"AuthenticSafetyInterlockKey"
        shares = split_secret_shares(secret, k=2, n=3)

        # Alter one byte of share data in shares[1]
        data_bytes = bytearray(bytes.fromhex(shares[1]["data"]))
        data_bytes[0] ^= 0x55
        tampered_share = dict(shares[1])
        tampered_share["data"] = data_bytes.hex()

        with self.assertRaises(ValueError):
            reconstruct_secret_from_shares([shares[0], tampered_share])

    def test_invalid_input_types_and_bounds(self):
        with self.assertRaises(TypeError):
            split_secret_shares("not_bytes", k=1, n=1)
        with self.assertRaises(ValueError):
            split_secret_shares(b"", k=1, n=1)
        with self.assertRaises(ValueError):
            split_secret_shares(b"test", k=0, n=2)
        with self.assertRaises(ValueError):
            split_secret_shares(b"test", k=4, n=3)
        with self.assertRaises(ValueError):
            split_secret_shares(b"test", k=2, n=256)
        with self.assertRaises(ValueError):
            reconstruct_secret_from_shares([])


class TestWOTSPlusMerkleSignatures(unittest.TestCase):
    """Test Winternitz OTS+ (WOTS+) with binary Merkle tree signatures."""

    def test_keygen_sign_verify_happy_path(self):
        pub, priv = generate_pqc_keypair(tree_height=2)
        self.assertEqual(pub["algorithm"], "WOTS-Merkle-SHA3")
        self.assertEqual(priv["algorithm"], "WOTS-Merkle-SHA3")
        self.assertEqual(pub["root"], priv["root"])

        msg1 = b"ActionCard:Stage:RestartNode:node-nodegamma03"
        sig1 = pqc_sign(msg1, priv)

        self.assertTrue(pqc_verify(msg1, sig1, pub))
        self.assertEqual(sig1["key_index"], 0)

        # Sign second message
        msg2 = b"ActionCard:Stage:IsolateWorkload:security-agent"
        sig2 = pqc_sign(msg2, priv)
        self.assertTrue(pqc_verify(msg2, sig2, pub))
        self.assertEqual(sig2["key_index"], 1)

    def test_tampered_message_fails_verification(self):
        pub, priv = generate_pqc_keypair(tree_height=2)
        msg = b"ActionCard:Approve:action-12345"
        sig = pqc_sign(msg, priv)

        tampered_msg = b"ActionCard:Approve:action-12345-TAMPERED"
        self.assertFalse(pqc_verify(tampered_msg, sig, pub))

    def test_tampered_signature_chunk_fails(self):
        pub, priv = generate_pqc_keypair(tree_height=2)
        msg = b"ActionCard:Approve:action-99999"
        sig = pqc_sign(msg, priv)

        tampered_sig = json.loads(json.dumps(sig))
        chunk_bytes = bytearray(bytes.fromhex(tampered_sig["signature_chunks"][0]))
        chunk_bytes[0] ^= 0x01
        tampered_sig["signature_chunks"][0] = chunk_bytes.hex()

        self.assertFalse(pqc_verify(msg, tampered_sig, pub))

    def test_wrong_public_key_fails(self):
        pub1, priv1 = generate_pqc_keypair(tree_height=2)
        pub2, _ = generate_pqc_keypair(tree_height=2)

        msg = b"TestCrossKeyAuthorization"
        sig1 = pqc_sign(msg, priv1)

        self.assertTrue(pqc_verify(msg, sig1, pub1))
        self.assertFalse(pqc_verify(msg, sig1, pub2))

    def test_key_exhaustion_raises_runtime_error(self):
        # Tree height 1 has 2^1 = 2 leaves
        pub, priv = generate_pqc_keypair(tree_height=1)
        pqc_sign(b"Msg1", priv)
        pqc_sign(b"Msg2", priv)

        with self.assertRaises(RuntimeError):
            pqc_sign(b"Msg3", priv)


class TestHybridPQCSealUnseal(unittest.TestCase):
    """Test hybrid Curve25519 + SHAKE-256 + HMAC-SHA3-512 AEAD envelope."""

    def test_seal_unseal_roundtrip(self):
        recipient_pub, recipient_priv = generate_pqc_keypair(tree_height=2)
        plaintext = b"Severance-Doctrine:Node-State-Snapshot:ZeroizeEphemeralTokens"

        envelope = pqc_seal(plaintext, recipient_pub)
        self.assertIn("header", envelope)
        self.assertIn("ciphertext", envelope)
        self.assertIn("tag", envelope)

        unsealed = pqc_unseal(envelope, recipient_priv)
        self.assertEqual(unsealed, plaintext)

    def test_seal_unseal_with_sender_signature(self):
        recipient_pub, recipient_priv = generate_pqc_keypair(tree_height=2)
        sender_pub, sender_priv = generate_pqc_keypair(tree_height=2)

        plaintext = b"AuthenticatedCommandFromMasterToWorker"
        envelope = pqc_seal(plaintext, recipient_pub, sender_privkey=sender_priv)
        self.assertIn("sender_signature", envelope)

        # Unseal with sender verification
        unsealed = pqc_unseal(envelope, recipient_priv, sender_pubkey=sender_pub)
        self.assertEqual(unsealed, plaintext)

        # Unseal with wrong sender public key fails
        wrong_sender_pub, _ = generate_pqc_keypair(tree_height=2)
        with self.assertRaises(ValueError):
            pqc_unseal(envelope, recipient_priv, sender_pubkey=wrong_sender_pub)

    def test_tampered_ciphertext_fails_unseal(self):
        recipient_pub, recipient_priv = generate_pqc_keypair(tree_height=2)
        envelope = pqc_seal(b"SecretClusterManifest", recipient_pub)

        # Tamper with ciphertext byte
        ct = bytearray(bytes.fromhex(envelope["ciphertext"]))
        ct[0] ^= 0xAA
        tampered_envelope = dict(envelope)
        tampered_envelope["ciphertext"] = ct.hex()

        with self.assertRaises(ValueError):
            pqc_unseal(tampered_envelope, recipient_priv)

    def test_tampered_header_fails_unseal(self):
        recipient_pub, recipient_priv = generate_pqc_keypair(tree_height=2)
        envelope = pqc_seal(b"SecretClusterManifest", recipient_pub)

        tampered_envelope = json.loads(json.dumps(envelope))
        tampered_envelope["header"]["nonce"] = "0" * 32

        with self.assertRaises(ValueError):
            pqc_unseal(tampered_envelope, recipient_priv)


class TestVerifyMultiKeyLocks(unittest.TestCase):
    """Test multi-key lock threshold verification."""

    def test_shamir_share_lock_verification(self):
        secret = b"MultiKeyThresholdSecret2026"
        secret_hash = hashlib.sha256(secret).hexdigest()
        shares = split_secret_shares(secret, k=2, n=3)

        payload = b"ActionPayload:ExecuteRestart"
        spec = {
            "required_k": 2,
            "expected_secret_hash": secret_hash,
        }

        # 2 shares satisfy
        self.assertTrue(verify_multi_key_locks(payload, [shares[0], shares[1]], spec))
        # 1 share fails
        self.assertFalse(verify_multi_key_locks(payload, [shares[0]], spec))

    def test_pqc_signature_lock_verification(self):
        pub1, priv1 = generate_pqc_keypair(tree_height=2)
        pub2, priv2 = generate_pqc_keypair(tree_height=2)
        pub3, priv3 = generate_pqc_keypair(tree_height=2)

        payload = b"CriticalActionPayload:DrainTraffic:ingress"
        sig1 = pqc_sign(payload, priv1)
        sig2 = pqc_sign(payload, priv2)

        spec = {
            "required_k": 2,
            "authorized_keys": [pub1["root"], pub2["root"], pub3["root"]],
        }

        approvals_2 = [
            {"signature": sig1, "public_key": pub1},
            {"signature": sig2, "public_key": pub2},
        ]
        self.assertTrue(verify_multi_key_locks(payload, approvals_2, spec))

        approvals_1 = [
            {"signature": sig1, "public_key": pub1},
        ]
        self.assertFalse(verify_multi_key_locks(payload, approvals_1, spec))


if __name__ == "__main__":
    unittest.main()
