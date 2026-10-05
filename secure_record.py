
import struct

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VERSION = 1

GATEWAY_TO_NODE = 0
NODE_TO_GATEWAY = 1

HEADER_FORMAT = ">BBQBI"
HEADER_SIZE = 15
TAG_SIZE = 32
IV_SIZE = 16


def build_header(direction, sequence, message_type, ciphertext_length):
    if direction not in (GATEWAY_TO_NODE, NODE_TO_GATEWAY):
        raise ValueError("Invalid direction")

    if not 0 <= sequence <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Invalid sequence number")

    if not 0 <= message_type <= 255:
        raise ValueError("Invalid message type")

    if not 0 <= ciphertext_length <= 0xFFFFFFFF:
        raise ValueError("Invalid ciphertext length")

    return struct.pack(
        HEADER_FORMAT,
        VERSION,
        direction,
        sequence,
        message_type,
        ciphertext_length
    )

def build_iv(session_id, sequence):
    if len(session_id) != 8:
        raise ValueError("Session ID must be exactly 8 bytes")

    if not 0 <= sequence <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Invalid sequence number")

    return session_id + sequence.to_bytes(8, "big")

class SecureChannel:
    def __init__(self, keys, session_id, send_direction, recv_direction):
        if len(session_id) != 8:
            raise ValueError("Session ID must be exactly 8 bytes")

        if send_direction not in (GATEWAY_TO_NODE, NODE_TO_GATEWAY):
            raise ValueError("Invalid sending direction")

        if recv_direction not in (GATEWAY_TO_NODE, NODE_TO_GATEWAY):
            raise ValueError("Invalid receiving direction")

        if send_direction == recv_direction:
            raise ValueError("Sending and receiving directions must differ")

        self.session_id = session_id

        self.send_direction = send_direction
        self.recv_direction = recv_direction

        self.send_sequence = 0
        self.recv_sequence = 0

        if send_direction == GATEWAY_TO_NODE:
            self.send_enc_key = keys["g2n_enc"]
            self.send_mac_key = keys["g2n_mac"]
        else:
            self.send_enc_key = keys["n2g_enc"]
            self.send_mac_key = keys["n2g_mac"]

        if recv_direction == GATEWAY_TO_NODE:
            self.recv_enc_key = keys["g2n_enc"]
            self.recv_mac_key = keys["g2n_mac"]
        else:
            self.recv_enc_key = keys["n2g_enc"]
            self.recv_mac_key = keys["n2g_mac"]

        for key in (
            self.send_enc_key,
            self.send_mac_key,
            self.recv_enc_key,
            self.recv_mac_key
        ):
            if len(key) != 32:
                raise ValueError("Encryption and MAC keys must be 32 bytes")
            
    
    def seal(self, plaintext, message_type=1):
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes")

        if not 0 <= message_type <= 255:
            raise ValueError("Invalid message type")

        if self.send_sequence > 0xFFFFFFFFFFFFFFFF:
            raise OverflowError("Sequence number exhausted")

        sequence = self.send_sequence

        # Build the record header and IV.
        iv = build_iv(self.session_id, sequence)

        header = build_header(
            self.send_direction,
            sequence,
            message_type,
            len(plaintext)
        )

        # Encrypt the plaintext using AES-256-CTR.
        cipher = Cipher(
            algorithms.AES(self.send_enc_key),
            modes.CTR(iv)
        )

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Authenticate the header, IV, and ciphertext.
        h = hmac.HMAC(self.send_mac_key, hashes.SHA256())
        h.update(header + iv + ciphertext)
        tag = h.finalize()

        # Combine the components into one record.
        record = header + ciphertext + tag

        # Advance the sequence number only after successful sealing.
        self.send_sequence += 1

        return record
    
    def open_record(self, record):
        if not isinstance(record, bytes):
            raise TypeError("Record must be bytes")

        # A record must contain at least a header and authentication tag.
        if len(record) < HEADER_SIZE + TAG_SIZE:
            raise ValueError("Record is too short")

        # Separate the header, ciphertext, and authentication tag.
        header = record[:HEADER_SIZE]
        tag = record[-TAG_SIZE:]
        ciphertext = record[HEADER_SIZE:-TAG_SIZE]

        # Parse the header.
        version, direction, sequence, message_type, ciphertext_length = (
            struct.unpack(HEADER_FORMAT, header)
        )

        # Validate the header fields.
        if version != VERSION:
            raise ValueError("Unsupported protocol version")

        if direction != self.recv_direction:
            raise ValueError("Incorrect record direction")

        if sequence != self.recv_sequence:
            raise ValueError("Unexpected sequence number")

        if ciphertext_length != len(ciphertext):
            raise ValueError("Ciphertext length mismatch")

        # Reconstruct the IV using the session ID and sequence number.
        iv = build_iv(self.session_id, sequence)

        # Verify the authentication tag BEFORE decrypting.
        h = hmac.HMAC(self.recv_mac_key, hashes.SHA256())
        h.update(header + iv + ciphertext)

        try:
            h.verify(tag)
        except Exception:
            raise ValueError("Record authentication failed")

        # Only decrypt after successful authentication.
        cipher = Cipher(
            algorithms.AES(self.recv_enc_key),
            modes.CTR(iv)
        )

        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Advance the receive counter only after successful processing.
        self.recv_sequence += 1

        return plaintext, message_type
