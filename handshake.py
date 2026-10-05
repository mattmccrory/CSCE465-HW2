
import os
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac


PROTOCOL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"

GATEWAY_ID = b"gateway"
NODE_ID = b"node"


# Generate a long-term RSA signing key.
def generate_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )


# Sign a message using RSA-PSS and SHA-256.
def sign(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


# Verify an RSA-PSS signature.
def verify(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# Load the standardized Diffie-Hellman parameters.
def load_dh_parameters():
    with open("ffdhe3072.pem", "rb") as f:
        return serialization.load_pem_parameters(f.read())


# Generate a fresh ephemeral DH private key.
def generate_dh_key(parameters):
    return parameters.generate_private_key()


# Encode a DH public value as exactly 384 bytes.
def encode_dh_public(private_key):
    public_value = private_key.public_key().public_numbers().y
    return public_value.to_bytes(384, byteorder="big")


# Generate a fresh 16-byte nonce.
def generate_nonce():
    return os.urandom(16)


# Encode transcript fields using 4-byte big-endian length prefixes.
def encode_transcript(fields):
    transcript = b""

    for field in fields:
        transcript += len(field).to_bytes(4, byteorder="big")
        transcript += field

    return transcript


# Decode and validate a length-prefixed transcript.
def decode_transcript(transcript, expected_fields=8):
    fields = []
    offset = 0

    for _ in range(expected_fields):
        if offset + 4 > len(transcript):
            raise ValueError("Missing field length")

        length = int.from_bytes(
            transcript[offset:offset + 4],
            byteorder="big"
        )
        offset += 4

        if offset + length > len(transcript):
            raise ValueError("Incorrect field length")

        fields.append(transcript[offset:offset + length])
        offset += length

    if offset != len(transcript):
        raise ValueError("Unexpected trailing transcript data")

    if fields[0] != PROTOCOL:
        raise ValueError("Incorrect protocol label")

    if fields[1] != GROUP_ID:
        raise ValueError("Incorrect DH group")

    if fields[2] != GATEWAY_ID or fields[3] != NODE_ID:
        raise ValueError("Unexpected party identity")

    if len(fields[4]) != 384 or len(fields[5]) != 384:
        raise ValueError("Invalid DH public value length")

    if len(fields[6]) != 16 or len(fields[7]) != 16:
        raise ValueError("Invalid nonce length")

    return fields


# Create the message that a party will sign.
def signing_message(role, transcript):
    transcript_hash = hashlib.sha256(transcript).digest()
    return role + transcript_hash


# Sign the transcript using the party's RSA private key.
def sign_transcript(private_key, role, transcript):
    message = signing_message(role, transcript)
    return sign(private_key, message)


# Verify the peer's signature and expected identity.
def verify_transcript(
    public_key,
    signature,
    role,
    expected_identity,
    transcript
):
    fields = decode_transcript(transcript)

    # Verify that the expected peer identity is in the transcript.
    if role == b"gateway":
        identity = fields[2]
    elif role == b"node":
        identity = fields[3]
    else:
        raise ValueError("Unknown signing role")

    if identity != expected_identity:
        raise ValueError("Unexpected peer identity")

    message = signing_message(role, transcript)

    if not verify(public_key, signature, message):
        raise ValueError("Invalid handshake signature")

    return True


# Convert the DH shared secret to exactly 384 bytes.
def encode_shared_secret(shared_secret):
    if len(shared_secret) > 384:
        raise ValueError("Shared secret exceeds 384 bytes")

    return shared_secret.rjust(384, b"\x00")


# Derive all session keys exactly as specified in the assignment.
def derive_session_keys(shared_secret, transcript):
    z = encode_shared_secret(shared_secret)
    th = hashlib.sha256(transcript).digest()

    # Master key
    k_master = hashlib.sha256(
        b"CSCE465-KDF-v1" + z + th
    ).digest()

    # Derive individual encryption and MAC keys.
    def derive(label):
        h = hmac.HMAC(k_master, hashes.SHA256())
        h.update(label + th)
        return h.finalize()

    keys = {
        "g2n_enc": derive(b"gateway-to-node encryption"),
        "g2n_mac": derive(b"gateway-to-node MAC"),
        "n2g_enc": derive(b"node-to-gateway encryption"),
        "n2g_mac": derive(b"node-to-gateway MAC"),
    }

    # Derive the session identifier.
    h = hmac.HMAC(k_master, hashes.SHA256())
    h.update(b"session identifier" + th)
    keys["session_id"] = h.finalize()[:8]

    return keys


def perform_handshake(gateway_rsa, node_rsa, parameters):
    # Generate fresh ephemeral DH keys for this session.
    gateway_dh = generate_dh_key(parameters)
    node_dh = generate_dh_key(parameters)

    # Generate fresh nonces.
    gateway_nonce = generate_nonce()
    node_nonce = generate_nonce()

    # Construct the canonical transcript.
    fields = [
        PROTOCOL,
        GROUP_ID,
        GATEWAY_ID,
        NODE_ID,
        encode_dh_public(gateway_dh),
        encode_dh_public(node_dh),
        gateway_nonce,
        node_nonce
    ]

    transcript = encode_transcript(fields)
    validate_handshake_transcript(transcript, parameters)

    # Both parties sign their respective roles.
    gateway_signature = sign_transcript(
        gateway_rsa, b"gateway", transcript
    )

    node_signature = sign_transcript(
        node_rsa, b"node", transcript
    )

    # Node verifies the gateway.
    verify_transcript(
        gateway_rsa.public_key(),
        gateway_signature,
        b"gateway",
        GATEWAY_ID,
        transcript
    )

    # Gateway verifies the node.
    verify_transcript(
        node_rsa.public_key(),
        node_signature,
        b"node",
        NODE_ID,
        transcript
    )

    # Both parties independently calculate the shared secret.
    gateway_secret = gateway_dh.exchange(node_dh.public_key())
    node_secret = node_dh.exchange(gateway_dh.public_key())

    if encode_shared_secret(gateway_secret) != encode_shared_secret(node_secret):
        raise ValueError("Shared secrets do not match")

    # Derive session keys independently.
    gateway_keys = derive_session_keys(gateway_secret, transcript)
    node_keys = derive_session_keys(node_secret, transcript)

    if gateway_keys != node_keys:
        raise ValueError("Derived session keys do not match")

    return {
        "transcript": transcript,
        "gateway_keys": gateway_keys,
        "node_keys": node_keys,
        "gateway_signature": gateway_signature,
        "node_signature": node_signature
    }


def validate_dh_public(public_bytes, parameters):
    if len(public_bytes) != 384:
        raise ValueError("Invalid DH public value length")

    y = int.from_bytes(public_bytes, byteorder="big")

    p = parameters.parameter_numbers().p
    q = (p - 1) // 2

    # Reject values outside the valid range.
    if not 2 <= y <= p - 2:
        raise ValueError("Invalid DH public value")

    # Verify membership in the expected FFDHE subgroup.
    if pow(y, q, p) != 1:
        raise ValueError("DH public value is not in the expected subgroup")

    # Let the cryptography library construct the public key too.
    public_numbers = dh.DHPublicNumbers(
        y, parameters.parameter_numbers()
    )
    public_numbers.public_key()

    return True

def validate_handshake_transcript(transcript, parameters):
    fields = decode_transcript(transcript)

    validate_dh_public(fields[4], parameters)
    validate_dh_public(fields[5], parameters)

    return fields
