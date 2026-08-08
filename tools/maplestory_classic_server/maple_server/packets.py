from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address
import struct


class PacketShapeError(ValueError):
    """Raised when a plaintext packet does not match an interpreted shape."""


class PacketReader:
    def __init__(self, payload: bytes, *, packet_name: str) -> None:
        self.payload = payload
        self.packet_name = packet_name
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.payload) - self.offset

    def _read(self, size: int, field: str) -> bytes:
        end = self.offset + size
        if end > len(self.payload):
            raise PacketShapeError(
                f"{self.packet_name}.{field} needs {size} bytes at offset "
                f"{self.offset}, only {self.remaining} remain"
            )
        value = self.payload[self.offset:end]
        self.offset = end
        return value

    def u8(self, field: str) -> int:
        return self._read(1, field)[0]

    def i8(self, field: str) -> int:
        return struct.unpack("<b", self._read(1, field))[0]

    def u16(self, field: str) -> int:
        return int.from_bytes(self._read(2, field), "little")

    def u32(self, field: str) -> int:
        return int.from_bytes(self._read(4, field), "little")

    def i32(self, field: str) -> int:
        return int.from_bytes(self._read(4, field), "little", signed=True)

    def i64(self, field: str) -> int:
        return int.from_bytes(self._read(8, field), "little", signed=True)

    def bytes(self, size: int, field: str) -> bytes:
        return self._read(size, field)

    def utf16_string(self, field: str, *, trailing_byte: bool) -> str:
        character_count = self.u16(f"{field}.character_count")
        encoded = self._read(character_count * 2, f"{field}.utf16le")
        try:
            value = encoded.decode("utf-16-le")
        except UnicodeDecodeError as error:
            raise PacketShapeError(
                f"{self.packet_name}.{field} is not valid UTF-16LE"
            ) from error
        if trailing_byte:
            terminator = self.u8(f"{field}.trailing_byte")
            if terminator != 0:
                raise PacketShapeError(
                    f"{self.packet_name}.{field} trailing byte is "
                    f"{terminator}, expected 0"
                )
        return value

    def finish(self) -> None:
        if self.remaining:
            raise PacketShapeError(
                f"{self.packet_name} has {self.remaining} uninterpreted bytes "
                f"at offset {self.offset}"
            )


def encode_utf16_string(value: str, *, trailing_byte: bool) -> bytes:
    encoded = value.encode("utf-16-le")
    character_count = len(encoded) // 2
    if character_count > 0xFFFF:
        raise PacketShapeError("UTF-16 string exceeds 65535 code units")
    return (
        struct.pack("<H", character_count)
        + encoded
        + (b"\x00" if trailing_byte else b"")
    )


def _expect_opcode(reader: PacketReader, expected: int) -> None:
    actual = reader.u16("opcode")
    if actual != expected:
        raise PacketShapeError(
            f"{reader.packet_name}.opcode is {actual}, expected {expected}"
        )


@dataclass(frozen=True)
class AccountLoginResponse:
    result: int
    account_id: int
    gender: int
    administrator: int
    restricted: bool
    account_name: str
    unknown_u16: int
    account_flags: tuple[int, int, int]
    created_at_ticks: int
    secondary_name: str
    tertiary_name: str
    trailing: bytes = b"\x00\x00"
    opcode: int = 0

    @classmethod
    def parse(cls, payload: bytes) -> "AccountLoginResponse":
        reader = PacketReader(payload, packet_name="account_login_response")
        opcode = reader.u16("opcode")
        if opcode not in {0, 1}:
            raise PacketShapeError(
                f"account_login_response.opcode is {opcode}, expected 0 or 1"
            )
        result = reader.u8("result")
        if result != 0:
            raise PacketShapeError(
                "only the successful account response (result 0) has a "
                "validated shape"
            )
        account_id = reader.u32("account_id")
        gender = reader.u8("gender")
        administrator = reader.u8("administrator")
        restricted_raw = reader.u8("restricted")
        if restricted_raw not in {0, 1}:
            raise PacketShapeError(
                f"account_login_response.restricted is {restricted_raw}, "
                "expected boolean 0 or 1"
            )
        account_name = reader.utf16_string(
            "account_name", trailing_byte=False
        )
        unknown_u16 = reader.u16("unknown_u16")
        account_flags = (
            reader.u8("account_flag_0"),
            reader.u8("account_flag_1"),
            reader.u8("account_flag_2"),
        )
        created_at_ticks = reader.i64("created_at_ticks")
        secondary_name = reader.utf16_string(
            "secondary_name", trailing_byte=False
        )
        tertiary_name = reader.utf16_string(
            "tertiary_name", trailing_byte=False
        )
        trailing = reader.bytes(2, "trailing")
        reader.finish()
        return cls(
            result=result,
            account_id=account_id,
            gender=gender,
            administrator=administrator,
            restricted=bool(restricted_raw),
            account_name=account_name,
            unknown_u16=unknown_u16,
            account_flags=account_flags,
            created_at_ticks=created_at_ticks,
            secondary_name=secondary_name,
            tertiary_name=tertiary_name,
            trailing=trailing,
            opcode=opcode,
        )

    def to_bytes(self) -> bytes:
        if self.result != 0:
            raise PacketShapeError(
                "only successful account responses can use this builder"
            )
        if len(self.account_flags) != 3:
            raise PacketShapeError("account_flags must contain exactly 3 bytes")
        if len(self.trailing) != 2:
            raise PacketShapeError("account response trailing field must be 2 bytes")
        return b"".join(
            (
                struct.pack(
                    "<HBIBBB",
                    self.opcode,
                    self.result,
                    self.account_id,
                    self.gender,
                    self.administrator,
                    int(self.restricted),
                ),
                encode_utf16_string(self.account_name, trailing_byte=False),
                struct.pack("<HBBBq", self.unknown_u16, *self.account_flags, self.created_at_ticks),
                encode_utf16_string(self.secondary_name, trailing_byte=False),
                encode_utf16_string(self.tertiary_name, trailing_byte=False),
                self.trailing,
            )
        )


@dataclass(frozen=True)
class ChannelRecord:
    name: str
    population: int
    world_id: int
    channel_id: int
    adult_channel: bool
    unknown: int


@dataclass(frozen=True)
class WorldBalloon:
    x: int
    y: int
    message: str


@dataclass(frozen=True)
class WorldRecord:
    world_id: int
    name: str
    flag: int
    event_description: str
    event_exp_rate: int
    event_drop_rate: int
    channels: tuple[ChannelRecord, ...]
    balloons: tuple[WorldBalloon, ...] = ()
    opcode: int = 2

    @classmethod
    def parse(cls, payload: bytes) -> "WorldRecord":
        reader = PacketReader(payload, packet_name="world_record")
        _expect_opcode(reader, 2)
        world_id = reader.i8("world_id")
        if world_id == -1:
            raise PacketShapeError("world-list sentinel is not a world record")
        name = reader.utf16_string("name", trailing_byte=True)
        flag = reader.u8("flag")
        event_description = reader.utf16_string(
            "event_description", trailing_byte=True
        )
        event_exp_rate = reader.u16("event_exp_rate")
        event_drop_rate = reader.u16("event_drop_rate")
        channel_count = reader.u8("channel_count")
        channels: list[ChannelRecord] = []
        for index in range(channel_count):
            channel_name = reader.utf16_string(
                f"channels[{index}].name", trailing_byte=True
            )
            population = reader.i32(f"channels[{index}].population")
            channel_world_id = reader.u8(f"channels[{index}].world_id")
            channel_id = reader.u8(f"channels[{index}].channel_id")
            adult_raw = reader.u8(f"channels[{index}].adult_channel")
            if adult_raw not in {0, 1}:
                raise PacketShapeError(
                    f"world_record.channels[{index}].adult_channel is "
                    f"{adult_raw}, expected boolean 0 or 1"
                )
            unknown = reader.i32(f"channels[{index}].unknown")
            if channel_world_id != world_id:
                raise PacketShapeError(
                    f"world_record.channels[{index}].world_id is "
                    f"{channel_world_id}, expected parent world {world_id}"
                )
            channels.append(
                ChannelRecord(
                    name=channel_name,
                    population=population,
                    world_id=channel_world_id,
                    channel_id=channel_id,
                    adult_channel=bool(adult_raw),
                    unknown=unknown,
                )
            )
        balloon_count = reader.u16("balloon_count")
        balloons = tuple(
            WorldBalloon(
                x=reader.u16(f"balloons[{index}].x"),
                y=reader.u16(f"balloons[{index}].y"),
                message=reader.utf16_string(
                    f"balloons[{index}].message", trailing_byte=True
                ),
            )
            for index in range(balloon_count)
        )
        reader.finish()
        channel_ids = [channel.channel_id for channel in channels]
        if len(channel_ids) != len(set(channel_ids)):
            raise PacketShapeError("world_record contains duplicate channel ids")
        return cls(
            world_id=world_id,
            name=name,
            flag=flag,
            event_description=event_description,
            event_exp_rate=event_exp_rate,
            event_drop_rate=event_drop_rate,
            channels=tuple(channels),
            balloons=balloons,
        )

    def to_bytes(self) -> bytes:
        if not -128 <= self.world_id <= 127 or self.world_id == -1:
            raise PacketShapeError("world_id must be a signed byte other than -1")
        if len(self.channels) > 0xFF:
            raise PacketShapeError("world record exceeds 255 channels")
        if len(self.balloons) > 0xFFFF:
            raise PacketShapeError("world record exceeds 65535 balloons")
        payload = bytearray(struct.pack("<Hb", self.opcode, self.world_id))
        payload.extend(encode_utf16_string(self.name, trailing_byte=True))
        payload.extend(struct.pack("<B", self.flag))
        payload.extend(
            encode_utf16_string(self.event_description, trailing_byte=True)
        )
        payload.extend(
            struct.pack(
                "<HHB",
                self.event_exp_rate,
                self.event_drop_rate,
                len(self.channels),
            )
        )
        for channel in self.channels:
            if channel.world_id != self.world_id:
                raise PacketShapeError(
                    f"channel {channel.channel_id} belongs to world "
                    f"{channel.world_id}, not {self.world_id}"
                )
            payload.extend(encode_utf16_string(channel.name, trailing_byte=True))
            payload.extend(
                struct.pack(
                    "<iBBBi",
                    channel.population,
                    channel.world_id,
                    channel.channel_id,
                    int(channel.adult_channel),
                    channel.unknown,
                )
            )
        payload.extend(struct.pack("<H", len(self.balloons)))
        for balloon in self.balloons:
            payload.extend(struct.pack("<HH", balloon.x, balloon.y))
            payload.extend(
                encode_utf16_string(balloon.message, trailing_byte=True)
            )
        return bytes(payload)


@dataclass(frozen=True)
class WorldListEnd:
    opcode: int = 2
    world_id: int = -1

    @classmethod
    def parse(cls, payload: bytes) -> "WorldListEnd":
        reader = PacketReader(payload, packet_name="world_list_end")
        _expect_opcode(reader, 2)
        world_id = reader.i8("world_id")
        reader.finish()
        if world_id != -1:
            raise PacketShapeError(
                f"world_list_end.world_id is {world_id}, expected -1"
            )
        return cls()

    def to_bytes(self) -> bytes:
        return struct.pack("<Hb", self.opcode, self.world_id)


@dataclass(frozen=True)
class WorldSelection:
    world_id: int
    opcode: int = 4

    @classmethod
    def parse(cls, payload: bytes) -> "WorldSelection":
        reader = PacketReader(payload, packet_name="world_selection")
        _expect_opcode(reader, 4)
        world_id = reader.u32("world_id")
        reader.finish()
        return cls(world_id=world_id)

    def to_bytes(self) -> bytes:
        return struct.pack("<HI", self.opcode, self.world_id)


@dataclass(frozen=True)
class ChannelSelection:
    world_id: int
    channel_id: int
    client_address: IPv4Address
    opcode: int = 5

    @classmethod
    def parse(cls, payload: bytes) -> "ChannelSelection":
        reader = PacketReader(payload, packet_name="channel_selection")
        _expect_opcode(reader, 5)
        world_id = reader.u8("world_id")
        channel_id = reader.u16("channel_id")
        client_address = IPv4Address(reader.bytes(4, "client_address"))
        reader.finish()
        return cls(
            world_id=world_id,
            channel_id=channel_id,
            client_address=client_address,
        )

    def to_bytes(self) -> bytes:
        return struct.pack("<HBH", self.opcode, self.world_id, self.channel_id) + bytes(
            self.client_address.packed
        )


@dataclass(frozen=True)
class CharacterListEnvelope:
    result: int
    opaque_payload: bytes
    opcode: int = 4

    @classmethod
    def parse(cls, payload: bytes) -> "CharacterListEnvelope":
        reader = PacketReader(payload, packet_name="character_list")
        _expect_opcode(reader, 4)
        result = reader.i8("result")
        opaque_payload = reader.bytes(reader.remaining, "opaque_payload")
        reader.finish()
        return cls(result=result, opaque_payload=opaque_payload)

    def to_bytes(self) -> bytes:
        return struct.pack("<Hb", self.opcode, self.result) + self.opaque_payload


@dataclass(frozen=True)
class CharacterSelection:
    character_id: int
    opcode: int = 7

    @classmethod
    def parse(cls, payload: bytes) -> "CharacterSelection":
        reader = PacketReader(payload, packet_name="character_selection")
        _expect_opcode(reader, 7)
        character_id = reader.u32("character_id")
        reader.finish()
        return cls(character_id=character_id)

    def to_bytes(self) -> bytes:
        return struct.pack("<HI", self.opcode, self.character_id)


@dataclass(frozen=True)
class WorldHandoff:
    result: int
    address: IPv4Address
    port: int
    character_id: int
    trailing: bytes = b"\x00" * 5
    opcode: int = 5

    @classmethod
    def parse(cls, payload: bytes) -> "WorldHandoff":
        reader = PacketReader(payload, packet_name="world_handoff")
        _expect_opcode(reader, 5)
        result = reader.u16("result")
        address = IPv4Address(reader.bytes(4, "address"))
        port = reader.u16("port")
        character_id = reader.u32("character_id")
        trailing = reader.bytes(5, "trailing")
        reader.finish()
        if trailing != b"\x00" * 5:
            raise PacketShapeError(
                "world_handoff.trailing is not the observed five zero bytes"
            )
        return cls(
            result=result,
            address=address,
            port=port,
            character_id=character_id,
            trailing=trailing,
        )

    def to_bytes(self) -> bytes:
        if not 0 <= self.port <= 0xFFFF:
            raise PacketShapeError(f"world handoff port is out of range: {self.port}")
        if len(self.trailing) != 5:
            raise PacketShapeError("world handoff trailing field must be 5 bytes")
        return b"".join(
            (
                struct.pack("<HH", self.opcode, self.result),
                self.address.packed,
                struct.pack("<HI", self.port, self.character_id),
                self.trailing,
            )
        )
