from __future__ import annotations

from dataclasses import dataclass
import struct

from Crypto.Cipher import AES


MAPLE_AES_KEY = bytes.fromhex(
    "29000000e100000052000000f1000000"
    "b3000000870000002400000006000000"
)
_IV_SHUFFLE = bytes.fromhex(
    "ec3f77a445d071bfb79820fc4be9b3e15c22f70c441b81bd638dd4c3f21019e"
    "0fba16e66eaaed6ce06184eeb7895dbbab6427a2a830b54676de865e72f07f3aa"
    "277b85b026fd8ba9fabea8d7cbcc92daf993602dddd2a29b395f82214c69f831"
    "87ee8ead8c6abcb56b5913f10400f65a3579488f15cd9757123e37ff9d4f51f5"
    "a370bb1475c2b872c0ed7d68c92e0d624617114d6cc47e53c125c79a1c88582c"
    "89dc026440015d38a5e2af55d5ef1a7ca75ba66f869f73e60ade2b994a479cdf"
    "09769e300ee4b294a03b341d280f36e323b403d890c83cfe5e3224501f3a438a"
    "964174ac5233f0d92980b116d3ab91b9847f611ecfc5d1563dcaf405c6e50849"
)
_FIRST_AES_CHUNK = 0x5B0
_FOLLOWING_AES_CHUNK = 0x5B4


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Handshake:
    packet_length: int
    version: int
    subversion: str
    first_iv: bytes
    second_iv: bytes
    locale: int
    trailing: bytes

    @property
    def wire_length(self) -> int:
        return self.packet_length + 2


@dataclass(frozen=True)
class EncryptedFrame:
    offset: int
    header: bytes
    payload: bytes

    @property
    def wire_length(self) -> int:
        return len(self.header) + len(self.payload)


def parse_handshake(data: bytes) -> Handshake:
    if len(data) < 6:
        raise ProtocolError("Handshake is shorter than its fixed fields")

    packet_length, version, subversion_length = struct.unpack_from("<HHH", data)
    wire_length = packet_length + 2
    if len(data) < wire_length:
        raise ProtocolError(
            f"Handshake declares {wire_length} wire bytes, only {len(data)} are present"
        )

    cursor = 6
    subversion_bytes = subversion_length * 2
    fixed_tail_length = 4 + 4 + 1
    if cursor + subversion_bytes + fixed_tail_length > wire_length:
        raise ProtocolError("Handshake subversion extends beyond the packet")

    try:
        subversion = data[cursor : cursor + subversion_bytes].decode("utf-16-le")
    except UnicodeDecodeError as error:
        raise ProtocolError("Handshake subversion is not valid UTF-16LE") from error
    cursor += subversion_bytes

    first_iv = data[cursor : cursor + 4]
    second_iv = data[cursor + 4 : cursor + 8]
    locale = data[cursor + 8]
    cursor += fixed_tail_length

    return Handshake(
        packet_length=packet_length,
        version=version,
        subversion=subversion,
        first_iv=first_iv,
        second_iv=second_iv,
        locale=locale,
        trailing=data[cursor:wire_length],
    )


def decode_frame_length(header: bytes) -> int:
    if len(header) != 4:
        raise ProtocolError(f"Encrypted frame header must be 4 bytes, got {len(header)}")
    return int.from_bytes(header[:2], "little") ^ int.from_bytes(
        header[2:], "little"
    )


def encode_frame_header(payload_length: int, iv: bytes, version_mask: int) -> bytes:
    """Build the four-byte encrypted-frame header for one cipher direction."""
    if not 0 <= payload_length <= 0xFFFF:
        raise ProtocolError(f"Frame payload length is out of range: {payload_length}")
    if len(iv) != 4:
        raise ProtocolError(f"Cipher IV must be 4 bytes, got {len(iv)}")
    first_word = int.from_bytes(iv[2:4], "little") ^ (version_mask & 0xFFFF)
    return struct.pack("<HH", first_word, first_word ^ payload_length)


def crypt_payload(payload: bytes, iv: bytes) -> bytes:
    """Encrypt or decrypt one Maple AES-OFB payload (the operation is symmetric)."""
    if len(iv) != 4:
        raise ProtocolError(f"Cipher IV must be 4 bytes, got {len(iv)}")

    transformed = bytearray(payload)
    cipher = AES.new(MAPLE_AES_KEY, AES.MODE_ECB)
    offset = 0
    chunk_length = _FIRST_AES_CHUNK
    while offset < len(transformed):
        segment_end = min(offset + chunk_length, len(transformed))
        keystream = iv * 4
        cursor = offset
        while cursor < segment_end:
            keystream = cipher.encrypt(keystream)
            block_end = min(cursor + AES.block_size, segment_end)
            for index in range(block_end - cursor):
                transformed[cursor + index] ^= keystream[index]
            cursor = block_end
        offset = segment_end
        chunk_length = _FOLLOWING_AES_CHUNK
    return bytes(transformed)


def shuffle_iv(iv: bytes) -> bytes:
    """Advance a four-byte IV after one encrypted frame."""
    if len(iv) != 4:
        raise ProtocolError(f"Cipher IV must be 4 bytes, got {len(iv)}")

    shuffled = bytearray((0xF2, 0x53, 0x50, 0xC6))
    for value in iv:
        shuffled[0] = (shuffled[0] + _IV_SHUFFLE[shuffled[1]] - value) & 0xFF
        shuffled[1] = (
            shuffled[1] - (shuffled[2] ^ _IV_SHUFFLE[value])
        ) & 0xFF
        shuffled[2] ^= (_IV_SHUFFLE[shuffled[3]] + value) & 0xFF
        shuffled[3] = (
            shuffled[3] - (shuffled[0] - _IV_SHUFFLE[value])
        ) & 0xFF
        packed = int.from_bytes(shuffled, "little")
        packed = ((packed << 3) | (packed >> 29)) & 0xFFFFFFFF
        shuffled[:] = packed.to_bytes(4, "little")
    return bytes(shuffled)


def parse_encrypted_frames(data: bytes, *, offset: int = 0) -> tuple[EncryptedFrame, ...]:
    frames: list[EncryptedFrame] = []
    cursor = offset
    while cursor < len(data):
        remaining = len(data) - cursor
        if remaining < 4:
            raise ProtocolError(
                f"Encrypted stream ends with a {remaining}-byte partial header"
            )

        header = data[cursor : cursor + 4]
        payload_length = decode_frame_length(header)
        payload_start = cursor + 4
        payload_end = payload_start + payload_length
        if payload_end > len(data):
            raise ProtocolError(
                f"Frame at offset {cursor} declares {payload_length} payload bytes, "
                f"only {len(data) - payload_start} are present"
            )

        frames.append(
            EncryptedFrame(
                offset=cursor,
                header=header,
                payload=data[payload_start:payload_end],
            )
        )
        cursor = payload_end

    return tuple(frames)
