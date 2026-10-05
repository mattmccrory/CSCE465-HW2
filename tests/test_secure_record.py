
import sys
from pathlib import Path

import pytest

# Allow tests to import secure_record.py from the project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secure_record import (
    SecureChannel,
    GATEWAY_TO_NODE,
    NODE_TO_GATEWAY,
    HEADER_SIZE,
)


@pytest.fixture
def channels():
    """Create a gateway and node with matching test session keys."""
    keys = {
        "g2n_enc": b"A" * 32,
        "g2n_mac": b"B" * 32,
        "n2g_enc": b"C" * 32,
        "n2g_mac": b"D" * 32,
        "session_id": b"12345678",
    }

    gateway = SecureChannel(
        keys,
        keys["session_id"],
        GATEWAY_TO_NODE,
        NODE_TO_GATEWAY,
    )

    node = SecureChannel(
        keys,
        keys["session_id"],
        NODE_TO_GATEWAY,
        GATEWAY_TO_NODE,
    )

    return gateway, node


def test_valid_bidirectional_communication(channels):
    """Both sides can send and receive authenticated records."""
    gateway, node = channels

    message1 = b"Read notes.txt"
    record1 = gateway.seal(message1)
    plaintext1, message_type1 = node.open_record(record1)

    assert plaintext1 == message1
    assert message_type1 == 1

    message2 = b"File contents"
    record2 = node.seal(message2)
    plaintext2, message_type2 = gateway.open_record(record2)

    assert plaintext2 == message2
    assert message_type2 == 1

    assert gateway.send_sequence == 1
    assert gateway.recv_sequence == 1
    assert node.send_sequence == 1
    assert node.recv_sequence == 1


def test_modified_ciphertext_is_rejected(channels):
    """Changing ciphertext without updating the MAC must fail."""
    gateway, node = channels

    record = bytearray(gateway.seal(b"Read notes.txt"))

    # Flip one bit in the ciphertext.
    record[HEADER_SIZE] ^= 0x01

    with pytest.raises(ValueError, match="authentication failed"):
        node.open_record(bytes(record))

    # Failed authentication must not advance the receive sequence.
    assert node.recv_sequence == 0


def test_modified_authenticated_header_is_rejected(channels):
    """Changing a header field must invalidate the record's MAC."""
    gateway, node = channels

    record = bytearray(gateway.seal(b"Read notes.txt"))

    # The message_type is at byte offset 10 in the header.
    # Change it without recalculating the MAC.
    record[10] ^= 0x01

    with pytest.raises(ValueError, match="authentication failed"):
        node.open_record(bytes(record))

    assert node.recv_sequence == 0


def test_replayed_record_is_rejected(channels):
    """A receiver must reject a record it has already processed."""
    gateway, node = channels

    record = gateway.seal(b"Read notes.txt")

    # The first delivery should succeed.
    plaintext, _ = node.open_record(record)
    assert plaintext == b"Read notes.txt"
    assert node.recv_sequence == 1

    # The second delivery has sequence number 0, but the receiver
    # now expects sequence number 1.
    with pytest.raises(ValueError, match="sequence"):
        node.open_record(record)

    assert node.recv_sequence == 1


def test_wrong_direction_record_is_rejected(channels):
    """A gateway-to-node record must not be accepted by the gateway."""
    gateway, node = channels

    record = gateway.seal(b"Read notes.txt")

    # The gateway expects node-to-gateway records, not its own
    # gateway-to-node record.
    with pytest.raises(ValueError, match="direction"):
        gateway.open_record(record)

    assert gateway.recv_sequence == 0



def test_invalid_record_does_not_advance_sequence(channels):
    """An invalid record must not consume the expected sequence number."""
    gateway, node = channels

    # Create the first record (sequence 0).
    record = gateway.seal(b"Read notes.txt")

    # Save a modified copy with an invalid MAC.
    modified_record = bytearray(record)
    modified_record[-1] ^= 0x01

    # The modified record must be rejected.
    with pytest.raises(ValueError, match="authentication failed"):
        node.open_record(bytes(modified_record))

    # The failed attempt must not advance the receiver's sequence.
    assert node.recv_sequence == 0

    # The original sequence-0 record should still be accepted.
    plaintext, _ = node.open_record(record)

    assert plaintext == b"Read notes.txt"
    assert node.recv_sequence == 1
