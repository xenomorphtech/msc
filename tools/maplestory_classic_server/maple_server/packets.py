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

    def i16(self, field: str) -> int:
        return int.from_bytes(self._read(2, field), "little", signed=True)

    def u32(self, field: str) -> int:
        return int.from_bytes(self._read(4, field), "little")

    def i32(self, field: str) -> int:
        return int.from_bytes(self._read(4, field), "little", signed=True)

    def i64(self, field: str) -> int:
        return int.from_bytes(self._read(8, field), "little", signed=True)

    def u64(self, field: str) -> int:
        return int.from_bytes(self._read(8, field), "little")

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
class ChannelTransitionResponse:
    """Observed two-stage response between world and channel selection.

    Stage 0 carries two transition values whose application-level meaning is
    not named yet. Stage 1 carries the selected world id. Both variants are
    nevertheless structurally complete and consume every observed byte.
    """

    stage: int
    transition_values: tuple[int, int] | None = None
    world_id: int | None = None
    opcode: int = 402

    def __post_init__(self) -> None:
        if self.stage == 0:
            if self.transition_values is None or self.world_id is not None:
                raise PacketShapeError(
                    "channel_transition stage 0 requires two transition values"
                )
            if any(not 0 <= value <= 0xFFFFFFFF for value in self.transition_values):
                raise PacketShapeError(
                    "channel_transition transition values must be uint32"
                )
            return
        if self.stage == 1:
            if self.transition_values is not None or self.world_id is None:
                raise PacketShapeError(
                    "channel_transition stage 1 requires one world id"
                )
            if not 0 <= self.world_id <= 0xFFFFFFFF:
                raise PacketShapeError(
                    "channel_transition world id must be uint32"
                )
            return
        raise PacketShapeError(
            f"channel_transition stage is {self.stage}, expected 0 or 1"
        )

    @classmethod
    def parse(cls, payload: bytes) -> "ChannelTransitionResponse":
        reader = PacketReader(payload, packet_name="channel_transition")
        _expect_opcode(reader, 402)
        stage = reader.u16("stage")
        if stage == 0:
            transition_values = (
                reader.u32("transition_value_0"),
                reader.u32("transition_value_1"),
            )
            reader.finish()
            return cls(stage=stage, transition_values=transition_values)
        if stage == 1:
            world_id = reader.u32("world_id")
            reader.finish()
            return cls(stage=stage, world_id=world_id)
        raise PacketShapeError(
            f"channel_transition.stage is {stage}, expected 0 or 1"
        )

    def to_bytes(self) -> bytes:
        if self.stage == 0:
            assert self.transition_values is not None
            return struct.pack(
                "<HHII", self.opcode, self.stage, *self.transition_values
            )
        assert self.world_id is not None
        return struct.pack("<HHI", self.opcode, self.stage, self.world_id)


@dataclass(frozen=True)
class Opcode13Ack:
    result: int
    opcode: int = 13

    @classmethod
    def parse(cls, payload: bytes) -> "Opcode13Ack":
        reader = PacketReader(payload, packet_name="opcode_13_ack")
        _expect_opcode(reader, 13)
        result = reader.u8("result")
        reader.finish()
        return cls(result=result)

    def to_bytes(self) -> bytes:
        return struct.pack("<HB", self.opcode, self.result)


@dataclass(frozen=True)
class Opcode13Envelope:
    message_type: int
    opaque_payload: bytes
    opcode: int = 13

    @classmethod
    def parse(cls, payload: bytes) -> "Opcode13Envelope":
        reader = PacketReader(payload, packet_name="opcode_13_envelope")
        _expect_opcode(reader, 13)
        message_type = reader.u8("message_type")
        payload_length = reader.u32("payload_length")
        opaque_payload = reader.bytes(payload_length, "opaque_payload")
        reader.finish()
        return cls(
            message_type=message_type,
            opaque_payload=opaque_payload,
        )

    def to_bytes(self) -> bytes:
        return (
            struct.pack(
                "<HBI", self.opcode, self.message_type, len(self.opaque_payload)
            )
            + self.opaque_payload
        )


@dataclass(frozen=True)
class ClientStatusMessage:
    message: str
    message_type: int = 15
    opcode: int = 13

    @classmethod
    def parse(cls, payload: bytes) -> "ClientStatusMessage":
        reader = PacketReader(payload, packet_name="client_status_message")
        _expect_opcode(reader, 13)
        message_type = reader.u8("message_type")
        if message_type != 15:
            raise PacketShapeError(
                f"client_status_message.message_type is {message_type}, "
                "expected 15"
            )
        message = reader.utf16_string("message", trailing_byte=True)
        reader.finish()
        return cls(message=message)

    def to_bytes(self) -> bytes:
        return (
            struct.pack("<HB", self.opcode, self.message_type)
            + encode_utf16_string(self.message, trailing_byte=True)
        )


@dataclass(frozen=True)
class ServerTime:
    ticks: int
    opcode: int = 134

    @classmethod
    def parse(cls, payload: bytes) -> "ServerTime":
        reader = PacketReader(payload, packet_name="server_time")
        _expect_opcode(reader, 134)
        ticks = reader.i64("ticks")
        reader.finish()
        return cls(ticks=ticks)

    def to_bytes(self) -> bytes:
        return struct.pack("<Hq", self.opcode, self.ticks)


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


@dataclass(frozen=True)
class WorldEntryRequest:
    """Observed world-session entry envelope; the inner ticket stays opaque."""

    character_id: int
    opaque_ticket: bytes
    opcode: int = 8

    @classmethod
    def parse(cls, payload: bytes) -> "WorldEntryRequest":
        reader = PacketReader(payload, packet_name="world_entry_request")
        _expect_opcode(reader, 8)
        character_id = reader.u32("character_id")
        opaque_ticket = reader.bytes(60, "opaque_ticket")
        reader.finish()
        return cls(character_id=character_id, opaque_ticket=opaque_ticket)

    def to_bytes(self) -> bytes:
        if len(self.opaque_ticket) != 60:
            raise PacketShapeError("world entry ticket must contain exactly 60 bytes")
        return struct.pack("<HI", self.opcode, self.character_id) + self.opaque_ticket


@dataclass(frozen=True)
class FieldSnapshotEnvelope:
    """Field-change packet with a validated opcode and opaque snapshot body."""

    opaque_snapshot: bytes
    opcode: int = 157

    @classmethod
    def parse(cls, payload: bytes) -> "FieldSnapshotEnvelope":
        reader = PacketReader(payload, packet_name="field_snapshot")
        _expect_opcode(reader, 157)
        opaque_snapshot = reader.bytes(reader.remaining, "opaque_snapshot")
        reader.finish()
        if not opaque_snapshot:
            raise PacketShapeError("field_snapshot has an empty snapshot body")
        return cls(opaque_snapshot=opaque_snapshot)

    def to_bytes(self) -> bytes:
        if not self.opaque_snapshot:
            raise PacketShapeError("field snapshot body cannot be empty")
        return struct.pack("<H", self.opcode) + self.opaque_snapshot


@dataclass(frozen=True)
class InitialCharacterSnapshot:
    """Typed character-stat prefix embedded in the initial field snapshot."""

    data_flags: int
    character_id: int
    name: str
    gender: int
    skin: int
    face_id: int
    hair_id: int
    companion_id: int
    level: int
    job_id: int
    strength: int
    dexterity: int
    intelligence: int
    luck: int
    current_hp: int
    max_hp: int
    current_mp: int
    max_mp: int
    ability_points: int
    skill_points: int
    experience: int
    fame: int
    map_id: int
    portal_index: int
    opaque_state_flag: int
    opaque_state_u64: int

    @classmethod
    def parse_from(cls, reader: PacketReader) -> "InitialCharacterSnapshot":
        snapshot = cls(
            data_flags=reader.u32("character.data_flags"),
            character_id=reader.u32("character.character_id"),
            name=reader.utf16_string("character.name", trailing_byte=True),
            gender=reader.u8("character.gender"),
            skin=reader.u8("character.skin"),
            face_id=reader.u32("character.face_id"),
            hair_id=reader.u32("character.hair_id"),
            companion_id=reader.u64("character.companion_id"),
            level=reader.u8("character.level"),
            job_id=reader.u16("character.job_id"),
            strength=reader.u16("character.strength"),
            dexterity=reader.u16("character.dexterity"),
            intelligence=reader.u16("character.intelligence"),
            luck=reader.u16("character.luck"),
            current_hp=reader.u16("character.current_hp"),
            max_hp=reader.u16("character.max_hp"),
            current_mp=reader.u16("character.current_mp"),
            max_mp=reader.u16("character.max_mp"),
            ability_points=reader.u16("character.ability_points"),
            skill_points=reader.u16("character.skill_points"),
            experience=reader.u32("character.experience"),
            fame=reader.i16("character.fame"),
            map_id=reader.u32("character.map_id"),
            portal_index=reader.u8("character.portal_index"),
            opaque_state_flag=reader.u8("character.opaque_state_flag"),
            opaque_state_u64=reader.u64("character.opaque_state_u64"),
        )
        snapshot._validate()
        return snapshot

    def _validate(self) -> None:
        if not self.name:
            raise PacketShapeError("initial character snapshot name cannot be empty")
        if self.gender not in (0, 1):
            raise PacketShapeError(
                f"initial character snapshot gender is {self.gender}, expected 0 or 1"
            )
        if self.level == 0:
            raise PacketShapeError("initial character snapshot level cannot be zero")
        if self.character_id == 0:
            raise PacketShapeError(
                "initial character snapshot character id cannot be zero"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return b"".join(
                (
                    struct.pack("<II", self.data_flags, self.character_id),
                    encode_utf16_string(self.name, trailing_byte=True),
                    struct.pack(
                        "<BBIIQBH",
                        self.gender,
                        self.skin,
                        self.face_id,
                        self.hair_id,
                        self.companion_id,
                        self.level,
                        self.job_id,
                    ),
                    struct.pack(
                        "<HHHH",
                        self.strength,
                        self.dexterity,
                        self.intelligence,
                        self.luck,
                    ),
                    struct.pack(
                        "<HHHHHH",
                        self.current_hp,
                        self.max_hp,
                        self.current_mp,
                        self.max_mp,
                        self.ability_points,
                        self.skill_points,
                    ),
                    struct.pack(
                        "<IhIBBQ",
                        self.experience,
                        self.fame,
                        self.map_id,
                        self.portal_index,
                        self.opaque_state_flag,
                        self.opaque_state_u64,
                    ),
                )
            )
        except struct.error as error:
            raise PacketShapeError(
                f"initial character snapshot field is out of range: {error}"
            ) from error


INITIAL_ITEM_SENTINEL_TICKS = 94_354_848_000_000_000


@dataclass(frozen=True)
class InitialInventoryItem:
    """Inventory item boundary with common fields and lossless record bytes."""

    slot: int
    record_type: int
    item_id: int
    cash_item: bool
    expires_at_ticks: int
    quantity: int | None
    raw_record: bytes

    def to_bytes(self) -> bytes:
        if not 1 <= self.slot <= 0xFF:
            raise PacketShapeError(
                f"initial inventory item slot is out of range: {self.slot}"
            )
        if len(self.raw_record) < 6:
            raise PacketShapeError("initial inventory item record is truncated")
        if self.raw_record[0] != self.record_type:
            raise PacketShapeError(
                "initial inventory item record-type byte does not match"
            )
        if int.from_bytes(self.raw_record[1:5], "little") != self.item_id:
            raise PacketShapeError(
                "initial inventory item template id does not match record bytes"
            )
        return bytes((self.slot,)) + self.raw_record


@dataclass(frozen=True)
class InitialInventoryGroup:
    name: str
    items: tuple[InitialInventoryItem, ...]

    def to_bytes(self) -> bytes:
        return b"".join(item.to_bytes() for item in self.items) + b"\x00"


@dataclass(frozen=True)
class InitialInventorySnapshot:
    """Capture-backed inventory lists at the start of the large opaque tail."""

    opaque_prefix: bytes
    groups: tuple[InitialInventoryGroup, ...]
    opaque_remainder: bytes

    @classmethod
    def parse(cls, payload: bytes) -> "InitialInventorySnapshot":
        reader = PacketReader(payload, packet_name="initial_inventory_snapshot")
        opaque_prefix = reader.bytes(30, "opaque_prefix")
        sentinel = int.from_bytes(opaque_prefix[-8:], "little", signed=True)
        if sentinel != INITIAL_ITEM_SENTINEL_TICKS:
            raise PacketShapeError(
                "initial inventory prefix does not end in the 1900-01-01 sentinel"
            )

        groups: list[InitialInventoryGroup] = []
        for index in range(5):
            groups.append(
                cls._parse_equipment_group(
                    reader, name=f"equipment_group_{index + 1}"
                )
            )
        for name in ("use", "setup", "etc"):
            groups.append(cls._parse_stack_group(reader, name=name))
        groups.append(cls._parse_cash_group(reader))
        opaque_remainder = reader.bytes(reader.remaining, "opaque_remainder")
        reader.finish()
        if not opaque_remainder:
            raise PacketShapeError(
                "initial inventory snapshot has no post-inventory remainder"
            )
        return cls(
            opaque_prefix=opaque_prefix,
            groups=tuple(groups),
            opaque_remainder=opaque_remainder,
        )

    @staticmethod
    def _read_common_item_prefix(
        reader: PacketReader, *, expected_type: int
    ) -> tuple[int, bool, int, int]:
        record_start = reader.offset
        record_type = reader.u8("item.record_type")
        if record_type != expected_type:
            raise PacketShapeError(
                f"initial inventory item type is {record_type}, "
                f"expected {expected_type}"
            )
        item_id = reader.u32("item.item_id")
        cash_flag = reader.u8("item.cash_flag")
        if cash_flag not in (0, 1):
            raise PacketShapeError(
                f"initial inventory cash flag is {cash_flag}, expected 0 or 1"
            )
        if cash_flag:
            reader.u64("item.cash_id")
        expires_at_ticks = reader.i64("item.expires_at_ticks")
        return record_start, bool(cash_flag), item_id, expires_at_ticks

    @classmethod
    def _parse_equipment_group(
        cls, reader: PacketReader, *, name: str
    ) -> InitialInventoryGroup:
        items: list[InitialInventoryItem] = []
        sentinel_bytes = INITIAL_ITEM_SENTINEL_TICKS.to_bytes(
            8, "little", signed=True
        )
        while True:
            slot = reader.u8(f"{name}.slot")
            if slot == 0:
                break
            record_start, cash_item, item_id, expires_at_ticks = (
                cls._read_common_item_prefix(reader, expected_type=1)
            )
            first_sentinel = reader.payload.find(sentinel_bytes, reader.offset)
            if first_sentinel < 0:
                raise PacketShapeError(
                    f"initial inventory {name} item lacks its first sentinel"
                )
            second_sentinel = reader.payload.find(
                sentinel_bytes, first_sentinel + len(sentinel_bytes)
            )
            if second_sentinel < 0:
                raise PacketShapeError(
                    f"initial inventory {name} item lacks its second sentinel"
                )
            record_end = second_sentinel + len(sentinel_bytes) + 4
            if record_end > len(reader.payload):
                raise PacketShapeError(
                    f"initial inventory {name} item tail is truncated"
                )
            if (
                reader.payload[first_sentinel + 8 : first_sentinel + 12]
                != b"\xff" * 4
            ):
                raise PacketShapeError(
                    f"initial inventory {name} first sentinel tail is not -1"
                )
            if (
                reader.payload[second_sentinel + 8 : record_end]
                != b"\x00" * 4
            ):
                raise PacketShapeError(
                    f"initial inventory {name} second sentinel tail is not zero"
                )
            reader.bytes(
                record_end - reader.offset,
                f"{name}.item_record_tail",
            )
            raw_record = reader.payload[record_start:record_end]
            items.append(
                InitialInventoryItem(
                    slot=slot,
                    record_type=1,
                    item_id=item_id,
                    cash_item=cash_item,
                    expires_at_ticks=expires_at_ticks,
                    quantity=None,
                    raw_record=raw_record,
                )
            )
        return InitialInventoryGroup(name=name, items=tuple(items))

    @classmethod
    def _parse_stack_group(
        cls, reader: PacketReader, *, name: str
    ) -> InitialInventoryGroup:
        items: list[InitialInventoryItem] = []
        while True:
            slot = reader.u8(f"{name}.slot")
            if slot == 0:
                break
            record_start, cash_item, item_id, expires_at_ticks = (
                cls._read_common_item_prefix(reader, expected_type=2)
            )
            quantity = reader.u16(f"{name}.quantity")
            reader.utf16_string(f"{name}.owner", trailing_byte=True)
            reader.bytes(10, f"{name}.opaque_item_metadata")
            sentinel = reader.i64(f"{name}.sentinel_filetime_ticks")
            if sentinel != INITIAL_ITEM_SENTINEL_TICKS:
                raise PacketShapeError(
                    f"initial inventory {name} item sentinel is {sentinel}"
                )
            reader.u32(f"{name}.opaque_tail_u32")
            raw_record = reader.payload[record_start : reader.offset]
            items.append(
                InitialInventoryItem(
                    slot=slot,
                    record_type=2,
                    item_id=item_id,
                    cash_item=cash_item,
                    expires_at_ticks=expires_at_ticks,
                    quantity=quantity,
                    raw_record=raw_record,
                )
            )
        return InitialInventoryGroup(name=name, items=tuple(items))

    @classmethod
    def _parse_cash_group(cls, reader: PacketReader) -> InitialInventoryGroup:
        items: list[InitialInventoryItem] = []
        while True:
            slot = reader.u8("cash.slot")
            if slot == 0:
                break
            record_start, cash_item, item_id, expires_at_ticks = (
                cls._read_common_item_prefix(reader, expected_type=3)
            )
            reader.utf16_string("cash.owner", trailing_byte=True)
            reader.u8("cash.opaque_flag_1")
            reader.u16("cash.opaque_u16_1")
            reader.u8("cash.opaque_flag_2")
            reader.i64("cash.opaque_timestamp")
            reader.bytes(4, "cash.opaque_metadata")
            reader.u32("cash.opaque_u32_1")
            reader.u16("cash.opaque_u16_2")
            reader.u8("cash.opaque_flag_3")
            reader.u32("cash.opaque_u32_2")
            reader.u16("cash.opaque_u16_3")
            reader.u32("cash.opaque_u32_3")
            raw_record = reader.payload[record_start : reader.offset]
            items.append(
                InitialInventoryItem(
                    slot=slot,
                    record_type=3,
                    item_id=item_id,
                    cash_item=cash_item,
                    expires_at_ticks=expires_at_ticks,
                    quantity=None,
                    raw_record=raw_record,
                )
            )
        return InitialInventoryGroup(name="cash", items=tuple(items))

    def to_bytes(self) -> bytes:
        expected_names = (
            "equipment_group_1",
            "equipment_group_2",
            "equipment_group_3",
            "equipment_group_4",
            "equipment_group_5",
            "use",
            "setup",
            "etc",
            "cash",
        )
        if tuple(group.name for group in self.groups) != expected_names:
            raise PacketShapeError(
                "initial inventory snapshot groups are missing or out of order"
            )
        if not self.opaque_remainder:
            raise PacketShapeError(
                "initial inventory snapshot remainder cannot be empty"
            )
        return (
            self.opaque_prefix
            + b"".join(group.to_bytes() for group in self.groups)
            + self.opaque_remainder
        )


@dataclass(frozen=True)
class InitialFieldTrailer:
    """Fixed final 112 bytes of the initial field packet."""

    opaque_blocks: tuple[bytes, bytes]
    reserved_u16: int
    opaque_texts: tuple[str, str, str, str, str]
    constant_u8: int
    reserved_u32: int
    sentinel_filetime_ticks: int
    server_local_filetime_ticks: int
    unknown_tail_u32: int

    @classmethod
    def parse_from(cls, reader: PacketReader) -> "InitialFieldTrailer":
        trailer = cls(
            opaque_blocks=(
                reader.bytes(17, "trailer.opaque_block_1"),
                reader.bytes(17, "trailer.opaque_block_2"),
            ),
            reserved_u16=reader.u16("trailer.reserved_u16"),
            opaque_texts=(
                reader.utf16_string("trailer.opaque_text_1", trailing_byte=True),
                reader.utf16_string("trailer.opaque_text_2", trailing_byte=True),
                reader.utf16_string("trailer.opaque_text_3", trailing_byte=True),
                reader.utf16_string("trailer.opaque_text_4", trailing_byte=True),
                reader.utf16_string("trailer.opaque_text_5", trailing_byte=True),
            ),
            constant_u8=reader.u8("trailer.constant_u8"),
            reserved_u32=reader.u32("trailer.reserved_u32"),
            sentinel_filetime_ticks=reader.i64(
                "trailer.sentinel_filetime_ticks"
            ),
            server_local_filetime_ticks=reader.i64(
                "trailer.server_local_filetime_ticks"
            ),
            unknown_tail_u32=reader.u32("trailer.unknown_tail_u32"),
        )
        trailer._validate()
        return trailer

    def _validate(self) -> None:
        expected_block = b"\x01\x01\x01\x00" + b"\xff" * 4 + b"\x00" * 9
        if self.opaque_blocks != (expected_block, expected_block):
            raise PacketShapeError(
                "initial field trailer opaque blocks do not match the captured shape"
            )
        if self.reserved_u16 != 0 or self.reserved_u32 != 0:
            raise PacketShapeError(
                "initial field trailer reserved integers must be zero"
            )
        text_lengths = tuple(
            len(value.encode("utf-16-le")) // 2 for value in self.opaque_texts
        )
        if text_lengths != (
            0,
            1,
            1,
            16,
            0,
        ):
            raise PacketShapeError(
                "initial field trailer text lengths must be 0/1/1/16/0"
            )
        if self.constant_u8 != 2:
            raise PacketShapeError(
                "initial field trailer constant byte must be two"
            )
        if self.sentinel_filetime_ticks != INITIAL_ITEM_SENTINEL_TICKS:
            raise PacketShapeError(
                "initial field trailer sentinel must encode 1900-01-01"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return b"".join(
                (
                    *self.opaque_blocks,
                    struct.pack("<H", self.reserved_u16),
                    *(
                        encode_utf16_string(value, trailing_byte=True)
                        for value in self.opaque_texts
                    ),
                    struct.pack(
                        "<BIqqI",
                        self.constant_u8,
                        self.reserved_u32,
                        self.sentinel_filetime_ticks,
                        self.server_local_filetime_ticks,
                        self.unknown_tail_u32,
                    ),
                )
            )
        except struct.error as error:
            raise PacketShapeError(
                f"initial field trailer field is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class InitialProgressionSnapshot:
    """Skill, property, timestamp, saved-map, and trailer collections."""

    reserved_flag: int
    skill_levels: tuple[tuple[int, int], ...]
    reserved_u16_1: int
    string_properties: tuple[tuple[int, str], ...]
    timestamp_properties: tuple[tuple[int, int], ...]
    reserved_i64: int
    saved_map_ids: tuple[int, ...]
    reserved_flag_2: int
    constant_u32: int
    variant: int
    extended_properties: tuple[tuple[int, str], ...]
    reserved_u16_2: int
    trailer: InitialFieldTrailer

    @classmethod
    def parse(cls, payload: bytes) -> "InitialProgressionSnapshot":
        reader = PacketReader(payload, packet_name="initial_progression_snapshot")
        reserved_flag = reader.u8("reserved_flag")
        skill_levels = tuple(
            (
                reader.u32(f"skill_levels[{index}].skill_id"),
                reader.u32(f"skill_levels[{index}].level"),
            )
            for index in range(reader.u16("skill_level_count"))
        )
        reserved_u16_1 = reader.u16("reserved_u16_1")
        string_properties = tuple(
            (
                reader.u32(f"string_properties[{index}].key"),
                reader.utf16_string(
                    f"string_properties[{index}].value", trailing_byte=True
                ),
            )
            for index in range(reader.u16("string_property_count"))
        )
        timestamp_properties = tuple(
            (
                reader.u32(f"timestamp_properties[{index}].key"),
                reader.i64(f"timestamp_properties[{index}].ticks"),
            )
            for index in range(reader.u16("timestamp_property_count"))
        )
        reserved_i64 = reader.i64("reserved_i64")
        saved_map_ids = tuple(
            reader.u32(f"saved_map_ids[{index}]") for index in range(16)
        )
        reserved_flag_2 = reader.u8("reserved_flag_2")
        constant_u32 = reader.u32("constant_u32")
        variant = reader.u8("variant")
        extended_properties = tuple(
            (
                reader.u32(f"extended_properties[{index}].key"),
                reader.utf16_string(
                    f"extended_properties[{index}].value", trailing_byte=True
                ),
            )
            for index in range(reader.u16("extended_property_count"))
        )
        reserved_u16_2 = reader.u16("reserved_u16_2")
        snapshot = cls(
            reserved_flag=reserved_flag,
            skill_levels=skill_levels,
            reserved_u16_1=reserved_u16_1,
            string_properties=string_properties,
            timestamp_properties=timestamp_properties,
            reserved_i64=reserved_i64,
            saved_map_ids=saved_map_ids,
            reserved_flag_2=reserved_flag_2,
            constant_u32=constant_u32,
            variant=variant,
            extended_properties=extended_properties,
            reserved_u16_2=reserved_u16_2,
            trailer=InitialFieldTrailer.parse_from(reader),
        )
        reader.finish()
        snapshot._validate()
        return snapshot

    def _validate(self) -> None:
        if self.reserved_flag != 0 or self.reserved_flag_2 != 0:
            raise PacketShapeError(
                "initial progression snapshot reserved flags must be zero"
            )
        if self.reserved_u16_1 != 0 or self.reserved_u16_2 != 0:
            raise PacketShapeError(
                "initial progression snapshot reserved integers must be zero"
            )
        if self.reserved_i64 != 0:
            raise PacketShapeError(
                "initial progression snapshot reserved int64 must be zero"
            )
        if len(self.saved_map_ids) != 16:
            raise PacketShapeError(
                "initial progression snapshot must contain 16 saved map ids"
            )
        if self.constant_u32 != 1:
            raise PacketShapeError(
                "initial progression snapshot constant integer must be one"
            )
        if self.variant not in (1, 2):
            raise PacketShapeError(
                f"initial progression snapshot variant is {self.variant}"
            )

    @staticmethod
    def _encode_keyed_strings(values: tuple[tuple[int, str], ...]) -> bytes:
        return b"".join(
            struct.pack("<I", key)
            + encode_utf16_string(value, trailing_byte=True)
            for key, value in values
        )

    def to_bytes(self) -> bytes:
        self._validate()
        if len(self.skill_levels) > 0xFFFF:
            raise PacketShapeError("initial progression has too many skill levels")
        if len(self.string_properties) > 0xFFFF:
            raise PacketShapeError(
                "initial progression has too many string properties"
            )
        if len(self.timestamp_properties) > 0xFFFF:
            raise PacketShapeError(
                "initial progression has too many timestamp properties"
            )
        if len(self.extended_properties) > 0xFFFF:
            raise PacketShapeError(
                "initial progression has too many extended properties"
            )
        try:
            return b"".join(
                (
                    struct.pack("<BH", self.reserved_flag, len(self.skill_levels)),
                    b"".join(
                        struct.pack("<II", skill_id, level)
                        for skill_id, level in self.skill_levels
                    ),
                    struct.pack(
                        "<HH",
                        self.reserved_u16_1,
                        len(self.string_properties),
                    ),
                    self._encode_keyed_strings(self.string_properties),
                    struct.pack("<H", len(self.timestamp_properties)),
                    b"".join(
                        struct.pack("<Iq", key, ticks)
                        for key, ticks in self.timestamp_properties
                    ),
                    struct.pack("<q", self.reserved_i64),
                    struct.pack("<16I", *self.saved_map_ids),
                    struct.pack(
                        "<BIBH",
                        self.reserved_flag_2,
                        self.constant_u32,
                        self.variant,
                        len(self.extended_properties),
                    ),
                    self._encode_keyed_strings(self.extended_properties),
                    struct.pack("<H", self.reserved_u16_2),
                    self.trailer.to_bytes(),
                )
            )
        except struct.error as error:
            raise PacketShapeError(
                f"initial progression field is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class InitialFieldSnapshot:
    """Initial opcode-157 field packet with a typed character-stat prefix."""

    marker: int
    reserved_flag: int
    contains_character_data: int
    character_data_mode: int
    reserved_u16: int
    opaque_session_u32s: tuple[int, int, int]
    sentinel_i64: int
    character_record_prefix: int
    character: InitialCharacterSnapshot
    opaque_tail: bytes
    opcode: int = 157

    @classmethod
    def parse(cls, payload: bytes) -> "InitialFieldSnapshot":
        reader = PacketReader(payload, packet_name="initial_field_snapshot")
        _expect_opcode(reader, 157)
        snapshot = cls(
            marker=reader.u32("marker"),
            reserved_flag=reader.u8("reserved_flag"),
            contains_character_data=reader.u8("contains_character_data"),
            character_data_mode=reader.u8("character_data_mode"),
            reserved_u16=reader.u16("reserved_u16"),
            opaque_session_u32s=(
                reader.u32("opaque_session_u32_1"),
                reader.u32("opaque_session_u32_2"),
                reader.u32("opaque_session_u32_3"),
            ),
            sentinel_i64=reader.i64("sentinel_i64"),
            character_record_prefix=reader.u8("character_record_prefix"),
            character=InitialCharacterSnapshot.parse_from(reader),
            opaque_tail=reader.bytes(reader.remaining, "opaque_tail"),
        )
        reader.finish()
        snapshot._validate()
        return snapshot

    @property
    def typed_prefix_bytes(self) -> int:
        return len(self.to_bytes()) - len(self.opaque_tail)

    def parse_inventory(self) -> InitialInventorySnapshot:
        return InitialInventorySnapshot.parse(self.opaque_tail)

    def parse_progression(self) -> InitialProgressionSnapshot:
        return InitialProgressionSnapshot.parse(
            self.parse_inventory().opaque_remainder
        )

    def _validate(self) -> None:
        if self.marker != 23:
            raise PacketShapeError(
                f"initial field snapshot marker is {self.marker}, expected 23"
            )
        if self.reserved_flag != 0 or self.reserved_u16 != 0:
            raise PacketShapeError(
                "initial field snapshot reserved fields must be zero"
            )
        if self.contains_character_data != 1 or self.character_data_mode != 1:
            raise PacketShapeError(
                "initial field snapshot character-data flags must both be one"
            )
        if self.sentinel_i64 != -1:
            raise PacketShapeError(
                "initial field snapshot signed sentinel must be minus one"
            )
        if self.character_record_prefix != 0:
            raise PacketShapeError(
                "initial field snapshot character-record prefix must be zero"
            )
        if len(self.opaque_session_u32s) != 3:
            raise PacketShapeError(
                "initial field snapshot must contain three opaque session integers"
            )
        if not self.opaque_tail:
            raise PacketShapeError("initial field snapshot tail cannot be empty")

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            prefix = struct.pack(
                "<HIBBBHIIIqB",
                self.opcode,
                self.marker,
                self.reserved_flag,
                self.contains_character_data,
                self.character_data_mode,
                self.reserved_u16,
                *self.opaque_session_u32s,
                self.sentinel_i64,
                self.character_record_prefix,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"initial field snapshot field is out of range: {error}"
            ) from error
        return prefix + self.character.to_bytes() + self.opaque_tail


@dataclass(frozen=True)
class CompactFieldTransition:
    marker: int
    reserved_flag: int
    transition_sequence: int
    map_id: int
    portal_index: int
    current_hp: int
    reserved_u16: int
    opaque_text_1: str
    opaque_text_2: str
    opaque_text_3: str
    reserved_u32: int
    constant_u32: int
    reserved_flag_2: int
    sentinel_filetime_ticks: int
    server_local_filetime_ticks: int
    unknown_tail_u32: int
    opcode: int = 157

    @classmethod
    def parse(cls, payload: bytes) -> "CompactFieldTransition":
        if len(payload) != 95:
            raise PacketShapeError(
                f"compact field transition has {len(payload)} bytes, expected 95"
            )
        reader = PacketReader(payload, packet_name="compact_field_transition")
        _expect_opcode(reader, 157)
        transition = cls(
            marker=reader.u32("marker"),
            reserved_flag=reader.u8("reserved_flag"),
            transition_sequence=reader.u32("transition_sequence"),
            map_id=reader.u32("map_id"),
            portal_index=reader.u8("portal_index"),
            current_hp=reader.u32("current_hp"),
            reserved_u16=reader.u16("reserved_u16"),
            opaque_text_1=reader.utf16_string(
                "opaque_text_1", trailing_byte=True
            ),
            opaque_text_2=reader.utf16_string(
                "opaque_text_2", trailing_byte=True
            ),
            opaque_text_3=reader.utf16_string(
                "opaque_text_3", trailing_byte=False
            ),
            reserved_u32=reader.u32("reserved_u32"),
            constant_u32=reader.u32("constant_u32"),
            reserved_flag_2=reader.u8("reserved_flag_2"),
            sentinel_filetime_ticks=reader.i64("sentinel_filetime_ticks"),
            server_local_filetime_ticks=reader.i64(
                "server_local_filetime_ticks"
            ),
            unknown_tail_u32=reader.u32("unknown_tail_u32"),
        )
        reader.finish()
        transition._validate()
        return transition

    def _validate(self) -> None:
        if self.marker != 23:
            raise PacketShapeError(
                f"compact field transition marker is {self.marker}, expected 23"
            )
        if self.reserved_flag != 0 or self.reserved_flag_2 != 0:
            raise PacketShapeError(
                "compact field transition reserved flags must be zero"
            )
        if self.reserved_u16 != 0 or self.reserved_u32 != 0:
            raise PacketShapeError(
                "compact field transition reserved integers must be zero"
            )
        if self.constant_u32 != 2:
            raise PacketShapeError(
                "compact field transition constant integer must be two"
            )
        if self.sentinel_filetime_ticks != 94_354_848_000_000_000:
            raise PacketShapeError(
                "compact field transition sentinel must encode 1900-01-01"
            )
        if len(self.opaque_text_1) != 1 or len(self.opaque_text_2) != 1:
            raise PacketShapeError(
                "compact field transition short strings must contain one character"
            )
        if len(self.opaque_text_3) != 16:
            raise PacketShapeError(
                "compact field transition long string must contain 16 characters"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            encoded = (
                struct.pack(
                    "<HIBIIBIH",
                    self.opcode,
                    self.marker,
                    self.reserved_flag,
                    self.transition_sequence,
                    self.map_id,
                    self.portal_index,
                    self.current_hp,
                    self.reserved_u16,
                )
                + encode_utf16_string(
                    self.opaque_text_1, trailing_byte=True
                )
                + encode_utf16_string(
                    self.opaque_text_2, trailing_byte=True
                )
                + encode_utf16_string(
                    self.opaque_text_3, trailing_byte=False
                )
                + struct.pack(
                    "<IIBqqI",
                    self.reserved_u32,
                    self.constant_u32,
                    self.reserved_flag_2,
                    self.sentinel_filetime_ticks,
                    self.server_local_filetime_ticks,
                    self.unknown_tail_u32,
                )
            )
        except struct.error as error:
            raise PacketShapeError(
                f"compact field transition field is out of range: {error}"
            ) from error
        if len(encoded) != 95:
            raise PacketShapeError(
                f"compact field transition encoded to {len(encoded)} bytes"
            )
        return encoded


@dataclass(frozen=True)
class NpcSpawn:
    object_id: int
    template_id: int
    x: int
    cy: int
    faces_left: bool
    foothold_id: int
    range_left: int
    range_right: int
    hidden: bool
    opcode: int = 300

    @classmethod
    def parse(cls, payload: bytes) -> "NpcSpawn":
        reader = PacketReader(payload, packet_name="npc_spawn")
        _expect_opcode(reader, 300)
        object_id = reader.u32("object_id")
        template_id = reader.u32("template_id")
        x = reader.i16("x")
        cy = reader.i16("cy")
        faces_left_raw = reader.u8("faces_left")
        if faces_left_raw not in {0, 1}:
            raise PacketShapeError(
                f"npc_spawn.faces_left is {faces_left_raw}, expected boolean 0 or 1"
            )
        foothold_id = reader.u16("foothold_id")
        range_left = reader.i16("range_left")
        range_right = reader.i16("range_right")
        hidden_raw = reader.u8("hidden")
        if hidden_raw not in {0, 1}:
            raise PacketShapeError(
                f"npc_spawn.hidden is {hidden_raw}, expected boolean 0 or 1"
            )
        reader.finish()
        if range_left > range_right:
            raise PacketShapeError(
                f"npc_spawn range is reversed: {range_left} > {range_right}"
            )
        return cls(
            object_id=object_id,
            template_id=template_id,
            x=x,
            cy=cy,
            faces_left=bool(faces_left_raw),
            foothold_id=foothold_id,
            range_left=range_left,
            range_right=range_right,
            hidden=bool(hidden_raw),
        )

    def to_bytes(self) -> bytes:
        if self.range_left > self.range_right:
            raise PacketShapeError(
                f"npc spawn range is reversed: {self.range_left} > {self.range_right}"
            )
        return struct.pack(
            "<HIIhhBHhhB",
            self.opcode,
            self.object_id,
            self.template_id,
            self.x,
            self.cy,
            int(self.faces_left),
            self.foothold_id,
            self.range_left,
            self.range_right,
            int(self.hidden),
        )


@dataclass(frozen=True)
class NpcStateUpdate:
    object_id: int
    action: int
    parameter: int
    opcode: int = 303

    @classmethod
    def parse(cls, payload: bytes) -> "NpcStateUpdate":
        reader = PacketReader(payload, packet_name="npc_state_update")
        _expect_opcode(reader, 303)
        object_id = reader.u32("object_id")
        action = reader.u8("action")
        parameter = reader.u8("parameter")
        reader.finish()
        return cls(object_id=object_id, action=action, parameter=parameter)

    def to_bytes(self) -> bytes:
        return struct.pack(
            "<HIBB", self.opcode, self.object_id, self.action, self.parameter
        )


@dataclass(frozen=True)
class MobSpawnData:
    spawn_marker: int
    template_id: int
    opaque_status: bytes
    x: int
    y: int
    stance: int
    foothold_id: int
    origin_foothold_id: int
    spawn_effect: int
    opaque_tail: bytes

    @classmethod
    def parse(cls, payload: bytes) -> "MobSpawnData":
        if len(payload) not in {42, 50}:
            raise PacketShapeError(
                f"mob spawn body has {len(payload)} bytes, expected 42 or 50"
            )
        reader = PacketReader(payload, packet_name="mob_spawn_data")
        spawn_marker = reader.u8("spawn_marker")
        if spawn_marker != 1:
            raise PacketShapeError(
                f"mob spawn marker is {spawn_marker}, expected one"
            )
        template_id = reader.u32("template_id")
        opaque_status = reader.bytes(len(payload) - 20, "opaque_status")
        x = reader.i16("x")
        y = reader.i16("y")
        stance = reader.u8("stance")
        foothold_id = reader.u16("foothold_id")
        origin_foothold_id = reader.u16("origin_foothold_id")
        spawn_effect = reader.i16("spawn_effect")
        opaque_tail = reader.bytes(4, "opaque_tail")
        reader.finish()
        return cls(
            spawn_marker=spawn_marker,
            template_id=template_id,
            opaque_status=opaque_status,
            x=x,
            y=y,
            stance=stance,
            foothold_id=foothold_id,
            origin_foothold_id=origin_foothold_id,
            spawn_effect=spawn_effect,
            opaque_tail=opaque_tail,
        )

    def to_bytes(self) -> bytes:
        if self.spawn_marker != 1:
            raise PacketShapeError("mob spawn marker must be one")
        if len(self.opaque_status) not in {22, 30}:
            raise PacketShapeError(
                "mob spawn opaque status must contain 22 or 30 bytes"
            )
        if len(self.opaque_tail) != 4:
            raise PacketShapeError("mob spawn opaque tail must contain four bytes")
        return (
            struct.pack("<BI", self.spawn_marker, self.template_id)
            + self.opaque_status
            + struct.pack(
                "<hhBHHh",
                self.x,
                self.y,
                self.stance,
                self.foothold_id,
                self.origin_foothold_id,
                self.spawn_effect,
            )
            + self.opaque_tail
        )


@dataclass(frozen=True)
class MobEnterField:
    object_id: int
    spawn: MobSpawnData
    opcode: int = 279

    @classmethod
    def parse(cls, payload: bytes) -> "MobEnterField":
        reader = PacketReader(payload, packet_name="mob_enter_field")
        _expect_opcode(reader, 279)
        object_id = reader.u32("object_id")
        spawn = MobSpawnData.parse(
            reader.bytes(reader.remaining, "spawn")
        )
        reader.finish()
        return cls(object_id=object_id, spawn=spawn)

    def to_bytes(self) -> bytes:
        return struct.pack("<HI", self.opcode, self.object_id) + self.spawn.to_bytes()


@dataclass(frozen=True)
class MobLeaveField:
    object_id: int
    reason: int
    opcode: int = 280

    @classmethod
    def parse(cls, payload: bytes) -> "MobLeaveField":
        reader = PacketReader(payload, packet_name="mob_leave_field")
        _expect_opcode(reader, 280)
        object_id = reader.u32("object_id")
        reason = reader.u8("reason")
        reader.finish()
        if reason not in {0, 1}:
            raise PacketShapeError(
                f"mob leave reason is {reason}, expected zero or one"
            )
        return cls(object_id=object_id, reason=reason)

    def to_bytes(self) -> bytes:
        if self.reason not in {0, 1}:
            raise PacketShapeError("mob leave reason must be zero or one")
        return struct.pack("<HIB", self.opcode, self.object_id, self.reason)


@dataclass(frozen=True)
class CharacterStatUpdate:
    request_flag: int
    stat_mask: int
    intelligence: int | None = None
    luck: int | None = None
    current_hp: int | None = None
    current_mp: int | None = None
    ability_points: int | None = None
    experience: int | None = None
    mesos: int | None = None
    opaque_tail: bytes = b"\x00"
    opcode: int = 41

    INTELLIGENCE = 0x0000_0100
    LUCK = 0x0000_0200
    CURRENT_HP = 0x0000_0400
    CURRENT_MP = 0x0000_1000
    ABILITY_POINTS = 0x0000_4000
    EXPERIENCE = 0x0001_0000
    MESOS = 0x0004_0000
    _FIELD_SPECS = (
        (INTELLIGENCE, "intelligence", "<H", 2),
        (LUCK, "luck", "<H", 2),
        (CURRENT_HP, "current_hp", "<H", 2),
        (CURRENT_MP, "current_mp", "<H", 2),
        (ABILITY_POINTS, "ability_points", "<H", 2),
        (EXPERIENCE, "experience", "<I", 4),
        (MESOS, "mesos", "<Q", 8),
    )
    _KNOWN_MASK = sum(spec[0] for spec in _FIELD_SPECS)

    @property
    def values(self) -> dict[str, int]:
        return {
            field_name: value
            for bit, field_name, _, _ in self._FIELD_SPECS
            if self.stat_mask & bit
            for value in (getattr(self, field_name),)
            if value is not None
        }

    @classmethod
    def parse(cls, payload: bytes) -> "CharacterStatUpdate":
        reader = PacketReader(payload, packet_name="character_stat_update")
        _expect_opcode(reader, 41)
        request_flag = reader.u8("request_flag")
        stat_mask = reader.u32("stat_mask")
        unknown_mask = stat_mask & ~cls._KNOWN_MASK
        if unknown_mask:
            raise PacketShapeError(
                "character stat update mask contains unsupported bits "
                f"0x{unknown_mask:08x}"
            )
        values: dict[str, int] = {}
        for bit, field_name, _, width in cls._FIELD_SPECS:
            if stat_mask & bit:
                values[field_name] = int.from_bytes(
                    reader.bytes(width, field_name), "little"
                )
        opaque_tail = reader.bytes(reader.remaining, "opaque_tail")
        if stat_mask:
            if opaque_tail != b"\x00":
                raise PacketShapeError(
                    "character stat update with values must end in one zero byte"
                )
        elif opaque_tail not in {b"\x00", b"\x01\x01"}:
            raise PacketShapeError(
                "zero-mask character stat update tail must be 00 or 0101"
            )
        return cls(
            request_flag=request_flag,
            stat_mask=stat_mask,
            opaque_tail=opaque_tail,
            **values,
        )

    def to_bytes(self) -> bytes:
        unknown_mask = self.stat_mask & ~self._KNOWN_MASK
        if unknown_mask:
            raise PacketShapeError(
                "character stat update mask contains unsupported bits "
                f"0x{unknown_mask:08x}"
            )
        encoded_values: list[bytes] = []
        for bit, field_name, format_string, _ in self._FIELD_SPECS:
            value = getattr(self, field_name)
            present = bool(self.stat_mask & bit)
            if present != (value is not None):
                requirement = "requires" if present else "does not allow"
                raise PacketShapeError(
                    f"character stat mask {requirement} {field_name}"
                )
            if value is not None:
                encoded_values.append(struct.pack(format_string, value))
        if self.stat_mask:
            if self.opaque_tail != b"\x00":
                raise PacketShapeError(
                    "character stat update with values must end in one zero byte"
                )
        elif self.opaque_tail not in {b"\x00", b"\x01\x01"}:
            raise PacketShapeError(
                "zero-mask character stat update tail must be 00 or 0101"
            )
        return (
            struct.pack("<HBI", self.opcode, self.request_flag, self.stat_mask)
            + b"".join(encoded_values)
            + self.opaque_tail
        )


@dataclass(frozen=True)
class InventoryModification:
    operation: int
    inventory_type: int
    slot: int
    quantity: int | None = None
    item: InitialInventoryItem | None = None

    ADD = 0
    UPDATE_QUANTITY = 1
    REMOVE = 3
    INVENTORY_NAMES = {
        1: "equip",
        2: "use",
        3: "setup",
        4: "etc",
        5: "cash",
    }
    OPERATION_NAMES = {
        ADD: "add",
        UPDATE_QUANTITY: "update_quantity",
        REMOVE: "remove",
    }

    @classmethod
    def _parse_item(
        cls,
        reader: PacketReader,
        *,
        inventory_type: int,
        slot: int,
        field_prefix: str,
    ) -> InitialInventoryItem:
        if inventory_type not in {2, 3, 4, 5}:
            raise PacketShapeError(
                "inventory add record supports captured inventory types "
                "two through five"
            )
        record_start = reader.offset
        expected_record_type = 3 if inventory_type == 5 else 2
        record_type = reader.u8(f"{field_prefix}.item.record_type")
        if record_type != expected_record_type:
            raise PacketShapeError(
                f"inventory type {inventory_type} add record type is "
                f"{record_type}, expected {expected_record_type}"
            )
        item_id = reader.u32(f"{field_prefix}.item.item_id")
        cash_flag = reader.u8(f"{field_prefix}.item.cash_flag")
        if cash_flag not in {0, 1}:
            raise PacketShapeError(
                f"inventory item cash flag is {cash_flag}, expected zero or one"
            )
        if cash_flag:
            reader.u64(f"{field_prefix}.item.cash_id")
        expires_at_ticks = reader.i64(
            f"{field_prefix}.item.expires_at_ticks"
        )
        quantity: int | None = None
        if inventory_type in {2, 3, 4}:
            quantity = reader.u16(f"{field_prefix}.item.quantity")
            reader.utf16_string(
                f"{field_prefix}.item.owner", trailing_byte=True
            )
            reader.bytes(10, f"{field_prefix}.item.opaque_metadata")
            sentinel = reader.i64(
                f"{field_prefix}.item.sentinel_filetime_ticks"
            )
            if sentinel != INITIAL_ITEM_SENTINEL_TICKS:
                raise PacketShapeError(
                    f"inventory item sentinel is {sentinel}, expected "
                    f"{INITIAL_ITEM_SENTINEL_TICKS}"
                )
            reader.u32(f"{field_prefix}.item.opaque_tail_u32")
        else:
            reader.utf16_string(
                f"{field_prefix}.item.owner", trailing_byte=True
            )
            reader.u8(f"{field_prefix}.item.opaque_flag_1")
            reader.u16(f"{field_prefix}.item.opaque_u16_1")
            reader.u8(f"{field_prefix}.item.opaque_flag_2")
            reader.i64(f"{field_prefix}.item.opaque_timestamp")
            reader.bytes(4, f"{field_prefix}.item.opaque_metadata")
            reader.u32(f"{field_prefix}.item.opaque_u32_1")
            reader.u16(f"{field_prefix}.item.opaque_u16_2")
            reader.u8(f"{field_prefix}.item.opaque_flag_3")
            reader.u32(f"{field_prefix}.item.opaque_u32_2")
            reader.u16(f"{field_prefix}.item.opaque_u16_3")
            reader.u32(f"{field_prefix}.item.opaque_u32_3")
        raw_record = reader.payload[record_start : reader.offset]
        return InitialInventoryItem(
            slot=slot,
            record_type=record_type,
            item_id=item_id,
            cash_item=bool(cash_flag),
            expires_at_ticks=expires_at_ticks,
            quantity=quantity,
            raw_record=raw_record,
        )

    @classmethod
    def parse(
        cls,
        reader: PacketReader,
        *,
        modification_index: int,
    ) -> "InventoryModification":
        field = f"modifications[{modification_index}]"
        operation = reader.u8(f"{field}.operation")
        if operation not in cls.OPERATION_NAMES:
            expected = ", ".join(str(value) for value in cls.OPERATION_NAMES)
            raise PacketShapeError(
                f"inventory operation is {operation}, expected one of {expected}"
            )
        inventory_type = reader.u8(f"{field}.inventory_type")
        if inventory_type not in cls.INVENTORY_NAMES:
            raise PacketShapeError(
                f"inventory type is {inventory_type}, expected one through five"
            )
        slot = reader.i16(f"{field}.slot")
        quantity = None
        item = None
        if operation == cls.UPDATE_QUANTITY:
            if inventory_type not in {2, 3, 4}:
                raise PacketShapeError(
                    "inventory quantity update requires a stack inventory"
                )
            quantity = reader.u16(f"{field}.quantity")
        elif operation == cls.ADD:
            item = cls._parse_item(
                reader,
                inventory_type=inventory_type,
                slot=slot,
                field_prefix=field,
            )
        return cls(
            operation=operation,
            inventory_type=inventory_type,
            slot=slot,
            quantity=quantity,
            item=item,
        )

    def safe_dict(self) -> dict[str, object]:
        details: dict[str, object] = {
            "operation": self.OPERATION_NAMES.get(self.operation, "unknown"),
            "inventory": self.INVENTORY_NAMES.get(
                self.inventory_type, "unknown"
            ),
            "slot": self.slot,
        }
        if self.quantity is not None:
            details["quantity"] = self.quantity
        if self.item is not None:
            details["item"] = {
                "record_type": self.item.record_type,
                "item_id": self.item.item_id,
                "cash_item": self.item.cash_item,
                "expires_at_ticks": self.item.expires_at_ticks,
                "quantity": self.item.quantity,
                "record_bytes": len(self.item.raw_record),
            }
        return details

    def to_bytes(self) -> bytes:
        if self.operation not in self.OPERATION_NAMES:
            expected = ", ".join(str(value) for value in self.OPERATION_NAMES)
            raise PacketShapeError(
                f"inventory operation is {self.operation}, expected one of {expected}"
            )
        if self.inventory_type not in self.INVENTORY_NAMES:
            raise PacketShapeError(
                f"inventory type is {self.inventory_type}, expected one through five"
            )
        if not -0x8000 <= self.slot <= 0x7FFF:
            raise PacketShapeError("inventory slot must fit in a signed short")
        body = struct.pack(
            "<BBh", self.operation, self.inventory_type, self.slot
        )
        if self.operation == self.UPDATE_QUANTITY:
            if self.inventory_type not in {2, 3, 4}:
                raise PacketShapeError(
                    "inventory quantity update requires a stack inventory"
                )
            if self.quantity is None or self.item is not None:
                raise PacketShapeError(
                    "inventory quantity update requires quantity and no item"
                )
            if not 0 <= self.quantity <= 0xFFFF:
                raise PacketShapeError(
                    "inventory quantity must fit in an unsigned short"
                )
            return body + struct.pack("<H", self.quantity)
        if self.operation == self.ADD:
            if self.quantity is not None or self.item is None:
                raise PacketShapeError(
                    "inventory add requires an item and no separate quantity"
                )
            if self.item.slot != self.slot:
                raise PacketShapeError(
                    "inventory add slot does not match the item slot"
                )
            expected_record_type = 3 if self.inventory_type == 5 else 2
            if self.inventory_type not in {2, 3, 4, 5}:
                raise PacketShapeError(
                    "inventory add record supports captured inventory types "
                    "two through five"
                )
            if self.item.record_type != expected_record_type:
                raise PacketShapeError(
                    "inventory add item record type does not match inventory"
                )
            return body + self.item.to_bytes()[1:]
        if self.quantity is not None or self.item is not None:
            raise PacketShapeError("inventory remove has no quantity or item")
        return body


@dataclass(frozen=True)
class InventoryChangeSet:
    update_flag: int
    modifications: tuple[InventoryModification, ...]
    opcode: int = 39

    @classmethod
    def parse(cls, payload: bytes) -> "InventoryChangeSet":
        reader = PacketReader(payload, packet_name="inventory_change_set")
        _expect_opcode(reader, 39)
        update_flag = reader.u8("update_flag")
        modification_count = reader.u8("modification_count")
        modifications = tuple(
            InventoryModification.parse(reader, modification_index=index)
            for index in range(modification_count)
        )
        reader.finish()
        return cls(update_flag=update_flag, modifications=modifications)

    def to_bytes(self) -> bytes:
        if not 0 <= self.update_flag <= 0xFF:
            raise PacketShapeError("inventory update flag must fit in one byte")
        if len(self.modifications) > 0xFF:
            raise PacketShapeError(
                "inventory change set cannot contain more than 255 modifications"
            )
        return (
            struct.pack(
                "<HBB", self.opcode, self.update_flag, len(self.modifications)
            )
            + b"".join(
                modification.to_bytes() for modification in self.modifications
            )
        )


@dataclass(frozen=True)
class PlayerMovementCommand:
    command_type: int
    opaque_payload: bytes

    _PAYLOAD_LENGTHS = {0: 13, 1: 7, 3: 5, 5: 13}

    @classmethod
    def absolute(
        cls,
        *,
        command_type: int = 0,
        position_x: int,
        position_y: int,
        velocity_x: int,
        velocity_y: int,
        foothold_id: int,
        stance: int,
        duration_ms: int,
    ) -> "PlayerMovementCommand":
        if command_type not in {0, 5}:
            raise PacketShapeError(
                "absolute player movement command type must be zero or five"
            )
        return cls(
            command_type=command_type,
            opaque_payload=struct.pack(
                "<hhhhHBH",
                position_x,
                position_y,
                velocity_x,
                velocity_y,
                foothold_id,
                stance,
                duration_ms,
            ),
        )

    @classmethod
    def relative(
        cls,
        *,
        velocity_x: int,
        velocity_y: int,
        stance: int,
        duration_ms: int,
    ) -> "PlayerMovementCommand":
        return cls(
            command_type=1,
            opaque_payload=struct.pack(
                "<hhBH", velocity_x, velocity_y, stance, duration_ms
            ),
        )

    @classmethod
    def compact(cls, opaque_payload: bytes) -> "PlayerMovementCommand":
        return cls(command_type=3, opaque_payload=opaque_payload)

    @property
    def byte_length(self) -> int:
        return 1 + len(self.opaque_payload)

    @property
    def position(self) -> tuple[int, int] | None:
        if self.command_type not in {0, 5}:
            return None
        return struct.unpack_from("<hh", self.opaque_payload)

    def safe_dict(self) -> dict[str, object]:
        if self.command_type in {0, 5}:
            (
                position_x,
                position_y,
                velocity_x,
                velocity_y,
                foothold_id,
                stance,
                duration_ms,
            ) = struct.unpack("<hhhhHBH", self.opaque_payload)
            return {
                "type": self.command_type,
                "kind": (
                    "absolute"
                    if self.command_type == 0
                    else "alternate_absolute"
                ),
                "position_x": position_x,
                "position_y": position_y,
                "velocity_x": velocity_x,
                "velocity_y": velocity_y,
                "foothold_id": foothold_id,
                "stance": stance,
                "duration_ms": duration_ms,
            }
        if self.command_type == 1:
            velocity_x, velocity_y, stance, duration_ms = struct.unpack(
                "<hhBH", self.opaque_payload
            )
            return {
                "type": self.command_type,
                "kind": "relative",
                "velocity_x": velocity_x,
                "velocity_y": velocity_y,
                "stance": stance,
                "duration_ms": duration_ms,
            }
        return {
            "type": self.command_type,
            "kind": "compact_opaque",
            "opaque_payload_bytes": len(self.opaque_payload),
        }

    @classmethod
    def parse(
        cls,
        reader: PacketReader,
        *,
        command_index: int,
        field_prefix: str = "movement",
    ) -> "PlayerMovementCommand":
        field = f"{field_prefix}.commands[{command_index}]"
        command_type = reader.u8(f"{field}.type")
        payload_length = cls._PAYLOAD_LENGTHS.get(command_type)
        if payload_length is None:
            expected = ", ".join(str(value) for value in cls._PAYLOAD_LENGTHS)
            raise PacketShapeError(
                f"{reader.packet_name}.{field}.type is {command_type}, "
                f"expected one of {expected}"
            )
        return cls(
            command_type=command_type,
            opaque_payload=reader.bytes(
                payload_length, f"{field}.opaque_payload"
            ),
        )

    def to_bytes(self) -> bytes:
        expected_length = self._PAYLOAD_LENGTHS.get(self.command_type)
        if expected_length is None:
            expected = ", ".join(str(value) for value in self._PAYLOAD_LENGTHS)
            raise PacketShapeError(
                f"player movement command type is {self.command_type}, "
                f"expected one of {expected}"
            )
        if len(self.opaque_payload) != expected_length:
            raise PacketShapeError(
                f"player movement command type {self.command_type} needs "
                f"{expected_length} opaque bytes, got "
                f"{len(self.opaque_payload)}"
            )
        return bytes((self.command_type,)) + self.opaque_payload


@dataclass(frozen=True)
class PlayerMovementPath:
    reference_x: int
    reference_y: int
    commands: tuple[PlayerMovementCommand, ...]

    @classmethod
    def parse_from(
        cls, reader: PacketReader, *, field_prefix: str = "movement"
    ) -> "PlayerMovementPath":
        reference_x = reader.i16(f"{field_prefix}.reference_x")
        reference_y = reader.i16(f"{field_prefix}.reference_y")
        command_count = reader.u8(f"{field_prefix}.command_count")
        if command_count == 0:
            raise PacketShapeError("player movement path has no commands")
        commands = tuple(
            PlayerMovementCommand.parse(
                reader,
                command_index=index,
                field_prefix=field_prefix,
            )
            for index in range(command_count)
        )
        return cls(
            reference_x=reference_x,
            reference_y=reference_y,
            commands=commands,
        )

    @property
    def final_position(self) -> tuple[int, int] | None:
        return next(
            (
                command.position
                for command in reversed(self.commands)
                if command.position is not None
            ),
            None,
        )

    def to_bytes(self) -> bytes:
        if not self.commands:
            raise PacketShapeError("player movement path must contain a command")
        if len(self.commands) > 255:
            raise PacketShapeError(
                "player movement path cannot contain more than 255 commands"
            )
        return (
            struct.pack(
                "<hhB",
                self.reference_x,
                self.reference_y,
                len(self.commands),
            )
            + b"".join(command.to_bytes() for command in self.commands)
        )


@dataclass(frozen=True)
class PlayerMovementSubmission:
    control_value: int
    movement: PlayerMovementPath
    trailer_marker: int
    path_start_x: int
    path_start_y: int
    path_end_x: int
    path_end_y: int
    opcode: int = 182

    @classmethod
    def parse(cls, payload: bytes) -> "PlayerMovementSubmission":
        reader = PacketReader(payload, packet_name="player_movement_submission")
        _expect_opcode(reader, 182)
        control_value = reader.u32("control_value")
        movement = PlayerMovementPath.parse_from(reader)
        trailer_marker = reader.u8("trailer_marker")
        if trailer_marker != 0:
            raise PacketShapeError(
                "player movement submission trailer marker must be zero"
            )
        path_start_x = reader.i16("path_start_x")
        path_start_y = reader.i16("path_start_y")
        path_end_x = reader.i16("path_end_x")
        path_end_y = reader.i16("path_end_y")
        reader.finish()
        return cls(
            control_value=control_value,
            movement=movement,
            trailer_marker=trailer_marker,
            path_start_x=path_start_x,
            path_start_y=path_start_y,
            path_end_x=path_end_x,
            path_end_y=path_end_y,
        )

    def to_bytes(self) -> bytes:
        if self.trailer_marker != 0:
            raise PacketShapeError(
                "player movement submission trailer marker must be zero"
            )
        return (
            struct.pack("<HI", self.opcode, self.control_value)
            + self.movement.to_bytes()
            + struct.pack(
                "<Bhhhh",
                self.trailer_marker,
                self.path_start_x,
                self.path_start_y,
                self.path_end_x,
                self.path_end_y,
            )
        )


@dataclass(frozen=True)
class PlayerMovementBroadcast:
    object_id: int
    control_value: int
    movement: PlayerMovementPath
    opcode: int = 202

    @classmethod
    def parse(cls, payload: bytes) -> "PlayerMovementBroadcast":
        reader = PacketReader(payload, packet_name="player_movement_broadcast")
        _expect_opcode(reader, 202)
        object_id = reader.u32("object_id")
        control_value = reader.u32("control_value")
        movement = PlayerMovementPath.parse_from(reader)
        reader.finish()
        return cls(
            object_id=object_id,
            control_value=control_value,
            movement=movement,
        )

    def to_bytes(self) -> bytes:
        return (
            struct.pack(
                "<HII", self.opcode, self.object_id, self.control_value
            )
            + self.movement.to_bytes()
        )


@dataclass(frozen=True)
class MobMovementCommand:
    command_type: int
    opaque_payload: bytes

    @property
    def byte_length(self) -> int:
        return 1 + len(self.opaque_payload)

    @classmethod
    def absolute(
        cls,
        *,
        position_x: int,
        position_y: int,
        velocity_x: int,
        velocity_y: int,
        foothold_id: int,
        stance: int,
        duration_ms: int,
    ) -> "MobMovementCommand":
        return cls(
            command_type=0,
            opaque_payload=struct.pack(
                "<hhhhHBH",
                position_x,
                position_y,
                velocity_x,
                velocity_y,
                foothold_id,
                stance,
                duration_ms,
            ),
        )

    @classmethod
    def relative(
        cls,
        *,
        command_type: int,
        velocity_x: int,
        velocity_y: int,
        stance: int,
        duration_ms: int,
    ) -> "MobMovementCommand":
        if command_type not in {1, 2}:
            raise PacketShapeError(
                "relative movement command type must be one or two"
            )
        return cls(
            command_type=command_type,
            opaque_payload=struct.pack(
                "<hhBH", velocity_x, velocity_y, stance, duration_ms
            ),
        )

    @property
    def position(self) -> tuple[int, int] | None:
        if self.command_type != 0:
            return None
        return struct.unpack_from("<hh", self.opaque_payload)

    @property
    def velocity(self) -> tuple[int, int]:
        offset = 4 if self.command_type == 0 else 0
        return struct.unpack_from("<hh", self.opaque_payload, offset)

    @property
    def foothold_id(self) -> int | None:
        if self.command_type != 0:
            return None
        return struct.unpack_from("<H", self.opaque_payload, 8)[0]

    @property
    def stance(self) -> int:
        offset = 10 if self.command_type == 0 else 4
        return self.opaque_payload[offset]

    @property
    def duration_ms(self) -> int:
        offset = 11 if self.command_type == 0 else 5
        return struct.unpack_from("<H", self.opaque_payload, offset)[0]

    def safe_dict(self) -> dict[str, object]:
        velocity_x, velocity_y = self.velocity
        result: dict[str, object] = {
            "type": self.command_type,
            "kind": "absolute" if self.command_type == 0 else "relative",
            "velocity_x": velocity_x,
            "velocity_y": velocity_y,
            "stance": self.stance,
            "duration_ms": self.duration_ms,
        }
        position = self.position
        if position is not None:
            result["position_x"], result["position_y"] = position
            result["foothold_id"] = self.foothold_id
        return result

    @classmethod
    def parse(
        cls, reader: PacketReader, *, command_index: int
    ) -> "MobMovementCommand":
        command_type = reader.u8(f"commands[{command_index}].type")
        payload_lengths = {0: 13, 1: 7, 2: 7}
        try:
            payload_length = payload_lengths[command_type]
        except KeyError as error:
            raise PacketShapeError(
                "mob_movement_path.commands"
                f"[{command_index}].type is {command_type}, expected 0, 1, or 2"
            ) from error
        return cls(
            command_type=command_type,
            opaque_payload=reader.bytes(
                payload_length, f"commands[{command_index}].opaque_payload"
            ),
        )

    def to_bytes(self) -> bytes:
        payload_lengths = {0: 13, 1: 7, 2: 7}
        expected_length = payload_lengths.get(self.command_type)
        if expected_length is None:
            raise PacketShapeError(
                f"movement command type is {self.command_type}, expected 0, 1, or 2"
            )
        if len(self.opaque_payload) != expected_length:
            raise PacketShapeError(
                f"movement command type {self.command_type} needs "
                f"{expected_length} opaque bytes, got {len(self.opaque_payload)}"
            )
        return bytes((self.command_type,)) + self.opaque_payload


@dataclass(frozen=True)
class MobMovementPath:
    opaque_control: bytes
    reference_x: int
    reference_y: int
    commands: tuple[MobMovementCommand, ...]
    trailer_marker: int
    path_start_x: int
    path_start_y: int
    path_end_x: int
    path_end_y: int

    @classmethod
    def parse(cls, payload: bytes) -> "MobMovementPath":
        reader = PacketReader(payload, packet_name="mob_movement_path")
        opaque_control = reader.bytes(19, "opaque_control")
        reference_x = reader.i16("reference_x")
        reference_y = reader.i16("reference_y")
        command_count = reader.u8("command_count")
        if command_count == 0:
            raise PacketShapeError("mob movement path has no commands")
        commands = tuple(
            MobMovementCommand.parse(reader, command_index=index)
            for index in range(command_count)
        )
        trailer_marker = reader.u8("trailer_marker")
        if trailer_marker != 0:
            raise PacketShapeError(
                f"mob movement path trailer marker is {trailer_marker}, expected 0"
            )
        path_start_x = reader.i16("path_start_x")
        path_start_y = reader.i16("path_start_y")
        path_end_x = reader.i16("path_end_x")
        path_end_y = reader.i16("path_end_y")
        reader.finish()
        return cls(
            opaque_control=opaque_control,
            reference_x=reference_x,
            reference_y=reference_y,
            commands=commands,
            trailer_marker=trailer_marker,
            path_start_x=path_start_x,
            path_start_y=path_start_y,
            path_end_x=path_end_x,
            path_end_y=path_end_y,
        )

    def to_bytes(self) -> bytes:
        if len(self.opaque_control) != 19:
            raise PacketShapeError(
                "mob movement path control prefix must contain exactly 19 bytes"
            )
        if not self.commands:
            raise PacketShapeError("mob movement path must contain a command")
        if len(self.commands) > 255:
            raise PacketShapeError(
                "mob movement path cannot contain more than 255 commands"
            )
        if self.trailer_marker != 0:
            raise PacketShapeError("mob movement path trailer marker must be zero")
        return (
            self.opaque_control
            + struct.pack(
                "<hhB", self.reference_x, self.reference_y, len(self.commands)
            )
            + b"".join(command.to_bytes() for command in self.commands)
            + struct.pack(
                "<Bhhhh",
                self.trailer_marker,
                self.path_start_x,
                self.path_start_y,
                self.path_end_x,
                self.path_end_y,
            )
        )


@dataclass(frozen=True)
class MobControllerChange:
    control_level: int
    object_id: int
    spawn: MobSpawnData | None = None
    opcode: int = 281

    @classmethod
    def parse(cls, payload: bytes) -> "MobControllerChange":
        reader = PacketReader(payload, packet_name="mob_controller_change")
        _expect_opcode(reader, 281)
        control_level = reader.u8("control_level")
        if control_level not in {0, 1, 2}:
            raise PacketShapeError(
                f"mob control level is {control_level}, expected 0, 1, or 2"
            )
        object_id = reader.u32("object_id")
        spawn = (
            MobSpawnData.parse(reader.bytes(reader.remaining, "spawn"))
            if reader.remaining
            else None
        )
        reader.finish()
        if control_level == 0 and spawn is not None:
            raise PacketShapeError(
                "mob control level zero must not include spawn data"
            )
        if control_level != 0 and spawn is None:
            raise PacketShapeError(
                "nonzero mob control level requires spawn data"
            )
        return cls(
            control_level=control_level,
            object_id=object_id,
            spawn=spawn,
        )

    def to_bytes(self) -> bytes:
        if self.control_level not in {0, 1, 2}:
            raise PacketShapeError("mob control level must be zero, one, or two")
        if self.control_level == 0 and self.spawn is not None:
            raise PacketShapeError(
                "mob control level zero cannot include spawn data"
            )
        if self.control_level != 0 and self.spawn is None:
            raise PacketShapeError(
                "nonzero mob control level requires spawn data"
            )
        return (
            struct.pack("<HBI", self.opcode, self.control_level, self.object_id)
            + (self.spawn.to_bytes() if self.spawn is not None else b"")
        )


@dataclass(frozen=True)
class MobMovementBroadcast:
    object_id: int
    opaque_control: bytes
    reference_x: int
    reference_y: int
    commands: tuple[MobMovementCommand, ...]
    opcode: int = 282

    @classmethod
    def parse(cls, payload: bytes) -> "MobMovementBroadcast":
        reader = PacketReader(payload, packet_name="mob_movement_broadcast")
        _expect_opcode(reader, 282)
        object_id = reader.u32("object_id")
        opaque_control = reader.bytes(7, "opaque_control")
        reference_x = reader.i16("reference_x")
        reference_y = reader.i16("reference_y")
        command_count = reader.u8("command_count")
        if command_count == 0:
            raise PacketShapeError("mob movement broadcast has no commands")
        commands = tuple(
            MobMovementCommand.parse(reader, command_index=index)
            for index in range(command_count)
        )
        reader.finish()
        return cls(
            object_id=object_id,
            opaque_control=opaque_control,
            reference_x=reference_x,
            reference_y=reference_y,
            commands=commands,
        )

    def to_bytes(self) -> bytes:
        if len(self.opaque_control) != 7:
            raise PacketShapeError(
                "mob movement broadcast control prefix must contain seven bytes"
            )
        if not self.commands:
            raise PacketShapeError(
                "mob movement broadcast must contain a command"
            )
        if len(self.commands) > 255:
            raise PacketShapeError(
                "mob movement broadcast cannot contain more than 255 commands"
            )
        return (
            struct.pack("<HI", self.opcode, self.object_id)
            + self.opaque_control
            + struct.pack(
                "<hhB", self.reference_x, self.reference_y, len(self.commands)
            )
            + b"".join(command.to_bytes() for command in self.commands)
        )


@dataclass(frozen=True)
class MobMovementSubmission:
    object_id: int
    sequence: int
    opaque_movement: bytes
    opcode: int = 207

    @classmethod
    def parse(cls, payload: bytes) -> "MobMovementSubmission":
        reader = PacketReader(payload, packet_name="mob_movement_submission")
        _expect_opcode(reader, 207)
        object_id = reader.u32("object_id")
        sequence = reader.u16("sequence")
        opaque_movement = reader.bytes(reader.remaining, "opaque_movement")
        reader.finish()
        if not opaque_movement:
            raise PacketShapeError("mob movement payload is empty")
        MobMovementPath.parse(opaque_movement)
        return cls(
            object_id=object_id,
            sequence=sequence,
            opaque_movement=opaque_movement,
        )

    def to_bytes(self) -> bytes:
        if not self.opaque_movement:
            raise PacketShapeError("mob movement payload cannot be empty")
        MobMovementPath.parse(self.opaque_movement)
        return (
            struct.pack("<HIH", self.opcode, self.object_id, self.sequence)
            + self.opaque_movement
        )

    @property
    def movement_path(self) -> MobMovementPath:
        return MobMovementPath.parse(self.opaque_movement)


@dataclass(frozen=True)
class MobMovementAcknowledgement:
    object_id: int
    sequence: int
    status_flag: int
    status_value: int
    status_auxiliary_1: int
    status_auxiliary_2: int
    opcode: int = 283

    @classmethod
    def parse(cls, payload: bytes) -> "MobMovementAcknowledgement":
        reader = PacketReader(payload, packet_name="mob_movement_acknowledgement")
        _expect_opcode(reader, 283)
        object_id = reader.u32("object_id")
        sequence = reader.u16("sequence")
        status_flag = reader.u8("status_flag")
        status_value = reader.u16("status_value")
        status_auxiliary_1 = reader.u8("status_auxiliary_1")
        status_auxiliary_2 = reader.u8("status_auxiliary_2")
        reader.finish()
        if status_flag not in {0, 1}:
            raise PacketShapeError(
                "mob movement acknowledgement status flag must be zero or one"
            )
        return cls(
            object_id=object_id,
            sequence=sequence,
            status_flag=status_flag,
            status_value=status_value,
            status_auxiliary_1=status_auxiliary_1,
            status_auxiliary_2=status_auxiliary_2,
        )

    def to_bytes(self) -> bytes:
        if self.status_flag not in {0, 1}:
            raise PacketShapeError(
                "mob movement acknowledgement status flag must be zero or one"
            )
        try:
            return struct.pack(
                "<HIHBHBB",
                self.opcode,
                self.object_id,
                self.sequence,
                self.status_flag,
                self.status_value,
                self.status_auxiliary_1,
                self.status_auxiliary_2,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"mob movement acknowledgement field is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class WorldBootstrapAcknowledgement:
    opaque_value: int
    opcode: int = 301

    @classmethod
    def parse(cls, payload: bytes) -> "WorldBootstrapAcknowledgement":
        reader = PacketReader(payload, packet_name="world_bootstrap_acknowledgement")
        _expect_opcode(reader, 301)
        opaque_value = reader.u32("opaque_value")
        reader.finish()
        return cls(opaque_value=opaque_value)

    def to_bytes(self) -> bytes:
        return struct.pack("<HI", self.opcode, self.opaque_value)


@dataclass(frozen=True)
class FieldLoadStage:
    stage: int
    trailing: int = 0
    opcode: int = 158

    @classmethod
    def parse(cls, payload: bytes) -> "FieldLoadStage":
        reader = PacketReader(payload, packet_name="field_load_stage")
        _expect_opcode(reader, 158)
        stage = reader.u32("stage")
        trailing = reader.u32("trailing")
        reader.finish()
        if stage not in {1, 2}:
            raise PacketShapeError(
                f"field_load_stage.stage is {stage}, expected observed stage 1 or 2"
            )
        if trailing != 0:
            raise PacketShapeError(
                f"field_load_stage.trailing is {trailing}, expected 0"
            )
        return cls(stage=stage, trailing=trailing)

    def to_bytes(self) -> bytes:
        if self.stage not in {1, 2}:
            raise PacketShapeError("field load stage must be 1 or 2")
        if self.trailing != 0:
            raise PacketShapeError("field load trailing value must be zero")
        return struct.pack("<HII", self.opcode, self.stage, self.trailing)


@dataclass(frozen=True)
class HeartbeatResponse:
    """Client response to an opcode-10 server heartbeat probe."""

    opaque_token: bytes
    opcode: int = 23

    @classmethod
    def parse(cls, payload: bytes) -> "HeartbeatResponse":
        reader = PacketReader(payload, packet_name="heartbeat_response")
        _expect_opcode(reader, 23)
        opaque_token = reader.bytes(8, "opaque_token")
        reader.finish()
        return cls(opaque_token=opaque_token)

    def to_bytes(self) -> bytes:
        if len(self.opaque_token) != 8:
            raise PacketShapeError("heartbeat token must contain exactly 8 bytes")
        return struct.pack("<H", self.opcode) + self.opaque_token


@dataclass(frozen=True)
class HeartbeatProbe:
    """Exact empty-body server heartbeat probe observed before opcode 23."""

    opcode: int = 10

    @classmethod
    def parse(cls, payload: bytes) -> "HeartbeatProbe":
        reader = PacketReader(payload, packet_name="heartbeat_probe")
        _expect_opcode(reader, 10)
        reader.finish()
        return cls()

    def to_bytes(self) -> bytes:
        return struct.pack("<H", self.opcode)


@dataclass(frozen=True)
class WorldSessionTermination:
    """Observed terminal world-session envelope; the reason body is opaque."""

    opaque_reason: bytes
    opcode: int = 9

    @classmethod
    def parse(cls, payload: bytes) -> "WorldSessionTermination":
        reader = PacketReader(payload, packet_name="world_session_termination")
        _expect_opcode(reader, 9)
        opaque_reason = reader.bytes(7, "opaque_reason")
        reader.finish()
        return cls(opaque_reason=opaque_reason)

    def to_bytes(self) -> bytes:
        if len(self.opaque_reason) != 7:
            raise PacketShapeError(
                "world session termination reason must contain exactly 7 bytes"
            )
        return struct.pack("<H", self.opcode) + self.opaque_reason
