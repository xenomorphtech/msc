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
        return cls(
            object_id=object_id,
            sequence=sequence,
            opaque_movement=opaque_movement,
        )

    def to_bytes(self) -> bytes:
        if not self.opaque_movement:
            raise PacketShapeError("mob movement payload cannot be empty")
        return (
            struct.pack("<HIH", self.opcode, self.object_id, self.sequence)
            + self.opaque_movement
        )


@dataclass(frozen=True)
class MobMovementAcknowledgement:
    object_id: int
    sequence: int
    opaque_status: bytes
    opcode: int = 283

    @classmethod
    def parse(cls, payload: bytes) -> "MobMovementAcknowledgement":
        reader = PacketReader(payload, packet_name="mob_movement_acknowledgement")
        _expect_opcode(reader, 283)
        object_id = reader.u32("object_id")
        sequence = reader.u16("sequence")
        opaque_status = reader.bytes(5, "opaque_status")
        reader.finish()
        return cls(
            object_id=object_id,
            sequence=sequence,
            opaque_status=opaque_status,
        )

    def to_bytes(self) -> bytes:
        if len(self.opaque_status) != 5:
            raise PacketShapeError(
                "mob movement acknowledgement status must contain exactly 5 bytes"
            )
        return (
            struct.pack("<HIH", self.opcode, self.object_id, self.sequence)
            + self.opaque_status
        )


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
class HeartbeatRequest:
    opaque_token: bytes
    opcode: int = 23

    @classmethod
    def parse(cls, payload: bytes) -> "HeartbeatRequest":
        reader = PacketReader(payload, packet_name="heartbeat_request")
        _expect_opcode(reader, 23)
        opaque_token = reader.bytes(8, "opaque_token")
        reader.finish()
        return cls(opaque_token=opaque_token)

    def to_bytes(self) -> bytes:
        if len(self.opaque_token) != 8:
            raise PacketShapeError("heartbeat token must contain exactly 8 bytes")
        return struct.pack("<H", self.opcode) + self.opaque_token


@dataclass(frozen=True)
class HeartbeatAcknowledgement:
    opcode: int = 10

    @classmethod
    def parse(cls, payload: bytes) -> "HeartbeatAcknowledgement":
        reader = PacketReader(payload, packet_name="heartbeat_acknowledgement")
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
