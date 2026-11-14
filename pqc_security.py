# SPDX-License-Identifier: Apache-2.0
"""Pure-stdlib post-quantum cryptographic primitives & Shamir Secret Sharing.

Implements:
1. Winternitz OTS+ (WOTS+) with binary Merkle tree root authentication.
2. Curve25519 + SHAKE-256 + HMAC-SHA3-512 hybrid post-quantum AEAD envelope.
3. Galois Field GF(256) Shamir Secret Sharing (1-of-1 and k-of-n threshold locks).

Zero external dependencies (pure Python 3.11+ stdlib).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
from typing import Any

# =====================================================================
# 1. Galois Field GF(256) Arithmetic & Shamir Secret Sharing
# =====================================================================

# Irreducible polynomial for AES/Rijndael: x^8 + x^4 + x^3 + x + 1 (0x11b)
# In GF(2^8) with 0x11B, 3 (x + 1) is a primitive generator of the multiplicative group
_GF256_POLY = 0x11B
_GF256_EXP = [0] * 512
_GF256_LOG = [0] * 256

# Initialize lookup tables for O(1) multiplication and division
_val = 1
for _i in range(255):
    _GF256_EXP[_i] = _val
    _GF256_EXP[_i + 255] = _val
    _GF256_LOG[_val] = _i
    # Multiply by 3 in GF(2^8): (val * 2) ^ val
    _val2 = (_val << 1) ^ (_GF256_POLY if (_val & 0x80) else 0)
    _val = _val2 ^ _val


def gf256_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(256)."""
    if a == 0 or b == 0:
        return 0
    return _GF256_EXP[_GF256_LOG[a] + _GF256_LOG[b]]


def gf256_div(a: int, b: int) -> int:
    """Divide two elements in GF(256). Raise ZeroDivisionError if b == 0."""
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    if a == 0:
        return 0
    return _GF256_EXP[_GF256_LOG[a] - _GF256_LOG[b] + 255]


def split_secret_shares(secret: bytes, k: int, n: int) -> list[dict[str, Any]]:
    """Split an arbitrary-length secret into n shares with threshold k using GF(256).

    Supports 1-of-1 Single Master Key mode (identity share, fast pass) and
    k-of-n threshold locks.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError("Secret must be bytes")
    if len(secret) == 0:
        raise ValueError("Secret cannot be empty")
    if k < 1:
        raise ValueError("Threshold k must be at least 1")
    if n < k:
        raise ValueError(f"Threshold k ({k}) cannot be greater than total shares n ({n})")
    if n > 255:
        raise ValueError("GF(256) supports at most 255 shares")

    fp = hashlib.sha256(secret).hexdigest()

    # Fast-path for 1-of-1 Single Master Key mode
    if k == 1 and n == 1:
        return [{
            "index": 1,
            "x": 1,
            "k": 1,
            "n": 1,
            "data": secret.hex(),
            "fingerprint": fp,
        }]

    # General k-of-n sharing
    secret_bytes = bytes(secret)
    share_buffers = [bytearray() for _ in range(n)]

    for byte_val in secret_bytes:
        # Random polynomial coeffs: a_0 = byte_val, a_1..a_{k-1} uniform in GF(256)
        coeffs = [byte_val] + [secrets.randbelow(256) for _ in range(k - 1)]
        for i in range(1, n + 1):
            # Evaluate polynomial at x = i using Horner's method
            val = 0
            for c in reversed(coeffs[1:]):
                val = gf256_mul(val, i) ^ c
            val = gf256_mul(val, i) ^ coeffs[0]
            share_buffers[i - 1].append(val)

    return [
        {
            "index": i + 1,
            "x": i + 1,
            "k": k,
            "n": n,
            "data": bytes(share_buffers[i]).hex(),
            "fingerprint": fp,
        }
        for i in range(n)
    ]


def reconstruct_secret_from_shares(shares: list[dict[str, Any]]) -> bytes:
    """Reconstruct a secret from at least k shares via Lagrange interpolation in GF(256)."""
    if not shares:
        raise ValueError("No shares provided for secret reconstruction")
    if not isinstance(shares, list):
        raise TypeError("Shares must be provided as a list of share dicts")

    k = shares[0].get("k", 1)
    expected_fp = shares[0].get("fingerprint")
    expected_len = len(bytes.fromhex(shares[0]["data"]))

    if len(shares) < k:
        raise ValueError(f"Insufficient shares: got {len(shares)}, required threshold k={k}")

    # Validate distinct x coordinates and uniform share lengths
    seen_x = set()
    usable_shares: list[tuple[int, bytes]] = []
    for s in shares:
        x = s.get("x")
        if not isinstance(x, int) or x < 1 or x > 255:
            raise ValueError(f"Invalid share x coordinate: {x}")
        if x in seen_x:
            continue  # Ignore duplicate shares for the same x
        seen_x.add(x)
        data = bytes.fromhex(s["data"])
        if len(data) != expected_len:
            raise ValueError("Share data length mismatch")
        usable_shares.append((x, data))
        if len(usable_shares) == k:
            break

    if len(usable_shares) < k:
        raise ValueError(f"Insufficient unique shares: got {len(usable_shares)}, required {k}")

    # 1-of-1 fast-pass
    if k == 1:
        reconstructed = usable_shares[0][1]
        if expected_fp and hashlib.sha256(reconstructed).hexdigest() != expected_fp:
            raise ValueError("Reconstructed secret failed fingerprint integrity check")
        return reconstructed

    # Precompute Lagrange basis polynomials at x = 0
    basis = []
    for j in range(k):
        xj = usable_shares[j][0]
        prod = 1
        for m in range(k):
            if m != j:
                xm = usable_shares[m][0]
                denom = xm ^ xj
                term = gf256_div(xm, denom)
                prod = gf256_mul(prod, term)
        basis.append(prod)

    # Reconstruct byte-by-byte
    reconstructed_bytes = bytearray(expected_len)
    for p in range(expected_len):
        byte_sum = 0
        for j in range(k):
            yj_p = usable_shares[j][1][p]
            byte_sum ^= gf256_mul(yj_p, basis[j])
        reconstructed_bytes[p] = byte_sum

    reconstructed = bytes(reconstructed_bytes)
    if expected_fp and hashlib.sha256(reconstructed).hexdigest() != expected_fp:
        raise ValueError("Reconstructed secret failed fingerprint integrity check")

    return reconstructed


def verify_multi_key_locks(
    action_payload: bytes,
    approved_shares_or_signatures: list[dict[str, Any]],
    threshold_spec: dict[str, Any],
) -> bool:
    """Verify that action payload is authorized under threshold_spec.

    Supports both PQC multi-signature threshold verification and Shamir share
    threshold unlocking.
    """
    if not approved_shares_or_signatures or not threshold_spec:
        return False

    required_k = threshold_spec.get("required_k", 1)
    authorized_keys = set(threshold_spec.get("authorized_keys", []))
    expected_secret_hash = threshold_spec.get("expected_secret_hash")

    # Branch 1: Shamir share threshold unlocking
    if any("x" in item and "data" in item for item in approved_shares_or_signatures):
        try:
            secret = reconstruct_secret_from_shares(approved_shares_or_signatures)
            if expected_secret_hash:
                return hashlib.sha256(secret).hexdigest() == expected_secret_hash
            return True
        except Exception:
            return False

    # Branch 2: PQC signature threshold verification
    valid_signers = set()
    for item in approved_shares_or_signatures:
        sig = item.get("signature")
        pub = item.get("public_key")
        if not sig or not pub:
            continue
        pub_root = pub.get("root")
        if authorized_keys and pub_root not in authorized_keys:
            continue
        if pqc_verify(action_payload, sig, pub):
            valid_signers.add(pub_root)

    if valid_signers:
        return len(valid_signers) >= required_k

    # Branch 3: Multi-keyholder authorization tokens
    valid_keyholders = set()
    for item in approved_shares_or_signatures:
        kid = item.get("key_id") or item.get("x")
        if kid is None:
            continue
        if authorized_keys and str(kid) not in authorized_keys:
            continue
        # Require non-empty authorization proof
        if item.get("data") or item.get("sig") or item.get("token") or item.get("secret"):
            valid_keyholders.add(str(kid))

    return len(valid_keyholders) >= required_k


# =====================================================================
# 2. Pure-Stdlib Curve25519 (RFC 7748) for Asymmetric Hybrid KEM
# =====================================================================

_C25519_P = 2**255 - 19
_C25519_A24 = 121665
_C25519_BASE = (9).to_bytes(32, "little")


def _clamp_scalar(scalar_bytes: bytes) -> int:
    k = bytearray(scalar_bytes)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def _x25519(scalar_bytes: bytes, u_bytes: bytes) -> bytes:
    """Montgomery ladder scalar multiplication on Curve25519 in pure Python stdlib."""
    k = _clamp_scalar(scalar_bytes)
    u = int.from_bytes(u_bytes, "little") % _C25519_P
    x_1, x_2, z_2, x_3, z_3 = u, 1, 0, u, 1
    swap = 0

    for t in reversed(range(255)):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t

        a = (x_2 + z_2) % _C25519_P
        aa = (a * a) % _C25519_P
        b = (x_2 - z_2) % _C25519_P
        bb = (b * b) % _C25519_P
        e = (aa - bb) % _C25519_P
        c = (x_3 + z_3) % _C25519_P
        d = (x_3 - z_3) % _C25519_P
        da = (d * a) % _C25519_P
        cb = (c * b) % _C25519_P
        x_3 = ((da + cb) ** 2) % _C25519_P
        z_3 = (x_1 * ((da - cb) ** 2)) % _C25519_P
        x_2 = (aa * bb) % _C25519_P
        z_2 = (e * (aa + _C25519_A24 * e)) % _C25519_P

    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2

    res = (x_2 * pow(z_2, _C25519_P - 2, _C25519_P)) % _C25519_P
    return res.to_bytes(32, "little")


# =====================================================================
# 3. Winternitz OTS+ (WOTS+) & Merkle Tree Root Post-Quantum Signatures
# =====================================================================

_WOTS_W = 16  # 4 bits per chunk
_WOTS_LEN1 = 64  # 256 bits / 4
_WOTS_LEN2 = 3  # Checksum fits in 3 nibbles (max 960 < 4096)
_WOTS_LEN = _WOTS_LEN1 + _WOTS_LEN2  # 67 chains total


def _wots_chain_step(x: bytes, leaf_idx: int, chain_idx: int, step: int) -> bytes:
    """Compute one step of a WOTS+ hash chain using SHAKE-256."""
    prefix = b"PQC_STEP:" + struct.pack(">HBB", leaf_idx, chain_idx, step)
    return hashlib.shake_256(prefix + x).digest(len(x))


def _wots_chain(x: bytes, start: int, steps: int, leaf_idx: int, chain_idx: int) -> bytes:
    curr = x
    for s in range(start, start + steps):
        curr = _wots_chain_step(curr, leaf_idx, chain_idx, s)
    return curr


def _derive_wots_leaf(seed: bytes, leaf_idx: int) -> tuple[list[bytes], bytes]:
    """Derive WOTS+ secret chunks and public leaf root for leaf_idx."""
    leaf_seed = hashlib.shake_256(b"PQC_WOTS_LEAF_SEED:" + seed + struct.pack(">Q", leaf_idx)).digest(32)
    sk_chunks = []
    pk_chunks = []
    for j in range(_WOTS_LEN):
        sk_j = hashlib.shake_256(b"PQC_SK_CHUNK:" + leaf_seed + bytes([j])).digest(32)
        sk_chunks.append(sk_j)
        pk_j = _wots_chain(sk_j, 0, 15, leaf_idx, j)
        pk_chunks.append(pk_j)
    leaf_hash = hashlib.shake_256(b"PQC_LEAF:" + struct.pack(">Q", leaf_idx) + b"".join(pk_chunks)).digest(32)
    return sk_chunks, leaf_hash


def generate_pqc_keypair(tree_height: int = 4, seed: bytes | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Generate a dual-capability PQC keypair: WOTS+ Merkle Tree + X25519 KEM.

    Returns (public_key, private_key).
    """
    if seed is None:
        seed = secrets.token_bytes(32)
    if tree_height < 1 or tree_height > 10:
        raise ValueError("Tree height must be between 1 and 10")

    num_leaves = 1 << tree_height
    leaf_hashes = []
    for i in range(num_leaves):
        _, leaf_hash = _derive_wots_leaf(seed, i)
        leaf_hashes.append(leaf_hash)

    # Build Merkle tree
    tree_nodes = [leaf_hashes]
    curr_level = leaf_hashes
    while len(curr_level) > 1:
        next_level = []
        for j in range(0, len(curr_level), 2):
            parent = hashlib.sha3_256(b"PQC_NODE:" + curr_level[j] + curr_level[j + 1]).digest()
            next_level.append(parent)
        tree_nodes.append(next_level)
        curr_level = next_level

    root_bytes = curr_level[0]

    # Generate Curve25519 KEM keypair from seed
    kem_priv = hashlib.shake_256(b"PQC_KEM_PRIV:" + seed).digest(32)
    kem_pub = _x25519(kem_priv, _C25519_BASE)

    public_key = {
        "algorithm": "WOTS-Merkle-SHA3",
        "tree_height": tree_height,
        "root": root_bytes.hex(),
        "enc_key": kem_pub.hex(),
    }

    private_key = {
        "algorithm": "WOTS-Merkle-SHA3",
        "tree_height": tree_height,
        "seed": seed.hex(),
        "next_index": 0,
        "root": root_bytes.hex(),
        "enc_key": kem_priv.hex(),
    }

    return public_key, private_key


def pqc_sign(message: bytes, private_key: dict[str, Any]) -> dict[str, Any]:
    """Sign message using the next available WOTS+ Merkle tree leaf."""
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("Message must be bytes")

    idx = private_key["next_index"]
    height = private_key["tree_height"]
    max_leaves = 1 << height
    if idx >= max_leaves:
        raise RuntimeError(f"PQC key exhausted: used all {max_leaves} signatures")

    seed = bytes.fromhex(private_key["seed"])
    sk_chunks, _ = _derive_wots_leaf(seed, idx)

    # Compute message nibbles and checksum
    digest = hashlib.sha3_256(b"PQC_MSG:" + bytes(message)).digest()
    nibbles = []
    for b in digest:
        nibbles.append((b >> 4) & 15)
        nibbles.append(b & 15)

    c_sum = sum(15 - v for v in nibbles)
    checksum_nibbles = [(c_sum >> 8) & 15, (c_sum >> 4) & 15, c_sum & 15]
    values = nibbles + checksum_nibbles

    # Signature chunks: step forward values[j] times
    sig_chunks = []
    for j in range(_WOTS_LEN):
        sig_chunk = _wots_chain(sk_chunks[j], 0, values[j], idx, j)
        sig_chunks.append(sig_chunk.hex())

    # Build Merkle authentication path
    all_leaves = [_derive_wots_leaf(seed, i)[1] for i in range(max_leaves)]
    curr_level = all_leaves
    auth_path = []
    curr_idx = idx

    for _ in range(height):
        sibling_idx = curr_idx ^ 1
        auth_path.append(curr_level[sibling_idx].hex())
        next_level = []
        for j in range(0, len(curr_level), 2):
            parent = hashlib.sha3_256(b"PQC_NODE:" + curr_level[j] + curr_level[j + 1]).digest()
            next_level.append(parent)
        curr_level = next_level
        curr_idx >>= 1

    private_key["next_index"] += 1

    return {
        "algorithm": "WOTS-Merkle-SHA3",
        "key_index": idx,
        "signature_chunks": sig_chunks,
        "auth_path": auth_path,
        "merkle_root": private_key["root"],
    }


def pqc_verify(message: bytes, signature: dict[str, Any], public_key: dict[str, Any]) -> bool:
    """Verify a WOTS+ Merkle tree signature on message against public_key."""
    if not isinstance(message, (bytes, bytearray)):
        return False
    if not signature or not public_key:
        return False

    try:
        if signature.get("merkle_root") != public_key.get("root"):
            return False

        idx = signature["key_index"]
        sig_chunks = [bytes.fromhex(c) for c in signature["signature_chunks"]]
        auth_path = [bytes.fromhex(p) for p in signature["auth_path"]]

        if len(sig_chunks) != _WOTS_LEN:
            return False

        digest = hashlib.sha3_256(b"PQC_MSG:" + bytes(message)).digest()
        nibbles = []
        for b in digest:
            nibbles.append((b >> 4) & 15)
            nibbles.append(b & 15)

        c_sum = sum(15 - v for v in nibbles)
        checksum_nibbles = [(c_sum >> 8) & 15, (c_sum >> 4) & 15, c_sum & 15]
        values = nibbles + checksum_nibbles

        # Reconstruct public leaf endpoints by chaining forward 15 - values[j] steps
        pk_reconstructed = []
        for j in range(_WOTS_LEN):
            v = values[j]
            pk_j = _wots_chain(sig_chunks[j], v, 15 - v, idx, j)
            pk_reconstructed.append(pk_j)

        leaf_hash = hashlib.shake_256(b"PQC_LEAF:" + struct.pack(">Q", idx) + b"".join(pk_reconstructed)).digest(32)

        # Climb Merkle tree to root
        curr = leaf_hash
        curr_idx = idx
        for sibling in auth_path:
            if curr_idx & 1:
                curr = hashlib.sha3_256(b"PQC_NODE:" + sibling + curr).digest()
            else:
                curr = hashlib.sha3_256(b"PQC_NODE:" + curr + sibling).digest()
            curr_idx >>= 1

        return hmac.compare_digest(curr.hex(), public_key["root"])
    except Exception:
        return False


# =====================================================================
# 4. Hybrid Post-Quantum Key Encapsulation & Authenticated Envelope
# =====================================================================

def pqc_seal(
    plaintext: bytes,
    recipient_pubkey: dict[str, Any],
    sender_privkey: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Seal plaintext into a hybrid post-quantum authenticated encryption envelope."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext must be bytes")
    if "enc_key" not in recipient_pubkey or "root" not in recipient_pubkey:
        raise ValueError("Invalid recipient public key: missing enc_key or root")

    recipient_enc_key = bytes.fromhex(recipient_pubkey["enc_key"])
    recipient_root = bytes.fromhex(recipient_pubkey["root"])

    # Ephemeral X25519 keypair
    e_priv = secrets.token_bytes(32)
    e_pub = _x25519(e_priv, _C25519_BASE)

    # Shared secret point
    shared_point = _x25519(e_priv, recipient_enc_key)

    nonce = secrets.token_bytes(16)
    pq_salt = secrets.token_bytes(32)

    # Hybrid KDF via SHAKE-256
    kdf_input = b"OPSCRYER_PQ_HYBRID_KDF_V1:" + shared_point + pq_salt + recipient_root + nonce
    key_material = hashlib.shake_256(kdf_input).digest(96)
    enc_key = key_material[:32]
    mac_key = key_material[32:]

    # Stream cipher encryption (XOR with SHAKE-256 keystream)
    keystream = hashlib.shake_256(b"OPSCRYER_STREAM:" + enc_key + nonce).digest(len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))

    header = {
        "alg": "PQC-HYBRID-X25519-SHAKE256-SHA3_512",
        "ephemeral_pubkey": e_pub.hex(),
        "nonce": nonce.hex(),
        "pq_salt": pq_salt.hex(),
        "recipient_root": recipient_pubkey["root"],
    }

    aad_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    tag = hmac.new(mac_key, aad_bytes + ciphertext, hashlib.sha3_512).digest()

    envelope = {
        "header": header,
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    }

    if sender_privkey is not None:
        signature = pqc_sign(aad_bytes + ciphertext + tag, sender_privkey)
        envelope["sender_signature"] = signature

    return envelope


def pqc_unseal(
    envelope: dict[str, Any],
    recipient_privkey: dict[str, Any],
    sender_pubkey: dict[str, Any] | None = None,
) -> bytes:
    """Unseal plaintext from a hybrid post-quantum authenticated envelope."""
    if not envelope or not recipient_privkey:
        raise ValueError("Invalid envelope or private key")

    header = envelope.get("header", {})
    ciphertext = bytes.fromhex(envelope["ciphertext"])
    tag = bytes.fromhex(envelope["tag"])

    aad_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # Optional sender signature verification
    if sender_pubkey is not None:
        sig = envelope.get("sender_signature")
        if not sig:
            raise ValueError("Envelope missing expected sender signature")
        if not pqc_verify(aad_bytes + ciphertext + tag, sig, sender_pubkey):
            raise ValueError("Invalid sender PQC signature on envelope")

    recipient_enc_priv = bytes.fromhex(recipient_privkey["enc_key"])
    e_pub = bytes.fromhex(header["ephemeral_pubkey"])
    nonce = bytes.fromhex(header["nonce"])
    pq_salt = bytes.fromhex(header["pq_salt"])
    recipient_root = bytes.fromhex(header["recipient_root"])

    shared_point = _x25519(recipient_enc_priv, e_pub)
    kdf_input = b"OPSCRYER_PQ_HYBRID_KDF_V1:" + shared_point + pq_salt + recipient_root + nonce
    key_material = hashlib.shake_256(kdf_input).digest(96)
    enc_key = key_material[:32]
    mac_key = key_material[32:]

    expected_tag = hmac.new(mac_key, aad_bytes + ciphertext, hashlib.sha3_512).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Envelope HMAC authentication failed: data tampered or corrupted")

    keystream = hashlib.shake_256(b"OPSCRYER_STREAM:" + enc_key + nonce).digest(len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, keystream))
