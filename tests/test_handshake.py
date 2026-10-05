
import pytest

from handshake import (
    PROTOCOL,
    GROUP_ID,
    GATEWAY_ID,
    NODE_ID,
    generate_rsa_key,
    generate_dh_key,
    encode_dh_public,
    generate_nonce,
    encode_transcript,
    decode_transcript,
    validate_handshake_transcript,
    sign_transcript,
    verify_transcript,
    load_dh_parameters,
    perform_handshake,
)


@pytest.fixture
def setup():
    parameters = load_dh_parameters()
    gateway_rsa = generate_rsa_key()
    node_rsa = generate_rsa_key()

    gateway_dh = generate_dh_key(parameters)
    node_dh = generate_dh_key(parameters)

    fields = [
        PROTOCOL,
        GROUP_ID,
        GATEWAY_ID,
        NODE_ID,
        encode_dh_public(gateway_dh),
        encode_dh_public(node_dh),
        generate_nonce(),
        generate_nonce()
    ]

    transcript = encode_transcript(fields)

    gateway_signature = sign_transcript(
        gateway_rsa, b"gateway", transcript
    )

    node_signature = sign_transcript(
        node_rsa, b"node", transcript
    )

    return (
        parameters,
        gateway_rsa,
        node_rsa,
        fields,
        transcript,
        gateway_signature,
        node_signature
    )


def test_valid_handshake(setup):
    parameters, gateway, node, *_ = setup

    session = perform_handshake(gateway, node, parameters)

    assert session["gateway_keys"] == session["node_keys"]


def test_changed_ciphertext_transcript_nonce(setup):
    parameters, gateway, _, fields, _, signature, _ = setup

    changed = list(fields)
    changed[6] = generate_nonce()

    transcript = encode_transcript(changed)

    with pytest.raises(ValueError):
        verify_transcript(
            gateway.public_key(),
            signature,
            b"gateway",
            GATEWAY_ID,
            transcript
        )


def test_changed_public_value(setup):
    parameters, gateway, _, fields, _, signature, _ = setup

    changed = list(fields)
    changed[4] = b"\x00" * 384

    transcript = encode_transcript(changed)

    with pytest.raises(ValueError):
        validate_handshake_transcript(transcript, parameters)

    with pytest.raises(ValueError):
        verify_transcript(
            gateway.public_key(),
            signature,
            b"gateway",
            GATEWAY_ID,
            transcript
        )


def test_malformed_transcript(setup):
    parameters, _, _, _, transcript, _, _ = setup

    malformed = transcript[:-1]

    with pytest.raises(ValueError):
        decode_transcript(malformed)


def test_unexpected_identity(setup):
    parameters, _, _, fields, _, _, _ = setup

    changed = list(fields)
    changed[2] = b"attacker"

    transcript = encode_transcript(changed)

    with pytest.raises(ValueError):
        decode_transcript(transcript)


def test_invalid_signature(setup):
    parameters, gateway, _, _, transcript, signature, _ = setup

    modified_signature = bytearray(signature)
    modified_signature[0] ^= 1

    with pytest.raises(ValueError):
        verify_transcript(
            gateway.public_key(),
            bytes(modified_signature),
            b"gateway",
            GATEWAY_ID,
            transcript
        )


def test_reflected_handshake_message(setup):
    parameters, _, node, _, transcript, _, node_signature = setup

    with pytest.raises(ValueError):
        verify_transcript(
            node.public_key(),
            node_signature,
            b"gateway",
            GATEWAY_ID,
            transcript
        )
