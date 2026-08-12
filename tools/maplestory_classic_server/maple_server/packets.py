from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address
import math
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


def _il2cpp_boolean_byte(
    value: bool, raw_value: int | None, *, field_name: str
) -> int:
    """Preserve a parsed IL2CPP boolean byte while checking its truth value."""

    if type(value) is not bool:
        raise PacketShapeError(f"{field_name} must be a boolean")
    encoded = int(value) if raw_value is None else raw_value
    if not 0 <= encoded <= 0xFF:
        raise PacketShapeError(f"{field_name} raw byte is out of range")
    if (encoded != 0) != value:
        raise PacketShapeError(
            f"{field_name} raw byte does not match its boolean value"
        )
    return encoded


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
class ServerOpcode0AccountBootstrapProbe:
    """Exact local diagnostic account-prefix probe, not a full account result."""

    account_id: int = field(repr=False)
    account_name: str = field(repr=False)
    result: int = 0
    account_flags: tuple[int, int, int] = (0, 0, 0)
    reserved_suffix: bytes = field(default=b"\x00" * 16, repr=False)
    opcode: int = 0

    @property
    def account_name_code_units(self) -> int:
        return len(self.account_name.encode("utf-16-le")) // 2

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode0AccountBootstrapProbe":
        reader = PacketReader(
            payload, packet_name="server_opcode_0_account_bootstrap_probe"
        )
        _expect_opcode(reader, 0)
        record = cls(
            result=reader.u8("result"),
            account_id=reader.u32("account_id"),
            account_flags=(
                reader.u8("gender"),
                reader.u8("administrator"),
                reader.u8("restricted"),
            ),
            account_name=reader.utf16_string(
                "account_name", trailing_byte=False
            ),
            reserved_suffix=reader.bytes(16, "reserved_suffix"),
        )
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode != 0:
            raise PacketShapeError(
                "local account bootstrap probe opcode must be 0"
            )
        if self.result != 0:
            raise PacketShapeError(
                "local account bootstrap probe result must be zero"
            )
        if not 0 <= self.account_id <= 0xFFFF_FFFF:
            raise PacketShapeError(
                "local account bootstrap probe account id must fit in u32"
            )
        if self.account_flags != (0, 0, 0):
            raise PacketShapeError(
                "local account bootstrap probe flags must all be zero"
            )
        if self.account_name_code_units != 4:
            raise PacketShapeError(
                "local account bootstrap probe name must contain four code units"
            )
        if self.reserved_suffix != b"\x00" * 16:
            raise PacketShapeError(
                "local account bootstrap probe suffix must contain 16 zero bytes"
            )

    def safe_dict(self) -> dict[str, object]:
        return {
            "diagnostic_probe": True,
            "result": self.result,
            "account_id_present": True,
            "account_name_code_units": self.account_name_code_units,
            "account_name_redacted": True,
            "account_flags_zero": True,
            "reserved_suffix_bytes": len(self.reserved_suffix),
            "reserved_suffix_zero": True,
            "account_authenticated": False,
        }

    def to_bytes(self) -> bytes:
        self._validate()
        return (
            struct.pack(
                "<HBI3B",
                self.opcode,
                self.result,
                self.account_id,
                *self.account_flags,
            )
            + encode_utf16_string(self.account_name, trailing_byte=False)
            + self.reserved_suffix
        )


@dataclass(frozen=True)
class LoginServerOpcode3Record:
    """Generated-read-backed neutral login record for server opcode 3."""

    leading_value: int = field(repr=False)
    neutral_value: int = field(repr=False)
    flag: bool
    opcode: int = 3

    @classmethod
    def parse(cls, payload: bytes) -> "LoginServerOpcode3Record":
        reader = PacketReader(payload, packet_name="login_server_opcode_3")
        _expect_opcode(reader, 3)
        leading_value = reader.u8("leading_value")
        neutral_value = reader.i32("neutral_value")
        flag_raw = reader.u8("flag")
        if flag_raw not in {0, 1}:
            raise PacketShapeError(
                "login server opcode-3 flag must be boolean"
            )
        reader.finish()
        return cls(
            leading_value=leading_value,
            neutral_value=neutral_value,
            flag=bool(flag_raw),
        )

    def safe_dict(self) -> dict[str, object]:
        return {
            "leading_value_redacted": True,
            "neutral_value_redacted": True,
            "flag": self.flag,
            "higher_level_role": "neutral",
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 3:
            raise PacketShapeError("login server opcode-3 record opcode must be 3")
        if not 0 <= self.leading_value <= 0xFF:
            raise PacketShapeError(
                "login server opcode-3 leading value must fit u8"
            )
        if not -(1 << 31) <= self.neutral_value < (1 << 31):
            raise PacketShapeError(
                "login server opcode-3 neutral value must fit i32"
            )
        return struct.pack(
            "<HBiB",
            self.opcode,
            self.leading_value,
            self.neutral_value,
            int(self.flag),
        )


@dataclass(frozen=True)
class LoginClientOpcode255Record:
    """Capture-bounded redacted u32 record for client opcode 255."""

    neutral_value: int = field(repr=False)
    opcode: int = 255

    @classmethod
    def parse(cls, payload: bytes) -> "LoginClientOpcode255Record":
        reader = PacketReader(payload, packet_name="login_client_opcode_255")
        _expect_opcode(reader, 255)
        record = cls(neutral_value=reader.u32("neutral_value"))
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, object]:
        return {
            "value_width_bits": 32,
            "value_redacted": True,
            "higher_level_role": "neutral",
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 255:
            raise PacketShapeError(
                "login client opcode-255 record opcode must be 255"
            )
        if not 0 <= self.neutral_value <= 0xFFFF_FFFF:
            raise PacketShapeError(
                "login client opcode-255 neutral value must fit u32"
            )
        return struct.pack("<HI", self.opcode, self.neutral_value)


@dataclass(frozen=True)
class LoginServerOpcode390Record:
    """Generated-read-backed neutral u8 record for server opcode 390."""

    neutral_value: int = field(repr=False)
    opcode: int = 390

    @classmethod
    def parse(cls, payload: bytes) -> "LoginServerOpcode390Record":
        reader = PacketReader(payload, packet_name="login_server_opcode_390")
        _expect_opcode(reader, 390)
        record = cls(neutral_value=reader.u8("neutral_value"))
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, object]:
        return {
            "value_width_bits": 8,
            "value_redacted": True,
            "higher_level_role": "neutral",
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 390:
            raise PacketShapeError(
                "login server opcode-390 record opcode must be 390"
            )
        if not 0 <= self.neutral_value <= 0xFF:
            raise PacketShapeError(
                "login server opcode-390 neutral value must fit u8"
            )
        return struct.pack("<HB", self.opcode, self.neutral_value)


@dataclass(frozen=True)
class LoginClientOpcode9TextRecord:
    """Capture-bounded redacted text record for client opcode 9."""

    opaque_text: str = field(repr=False)
    opcode: int = 9

    @property
    def text_code_units(self) -> int:
        return len(self.opaque_text.encode("utf-16-le")) // 2

    @classmethod
    def parse(cls, payload: bytes) -> "LoginClientOpcode9TextRecord":
        reader = PacketReader(payload, packet_name="login_client_opcode_9")
        _expect_opcode(reader, 9)
        record = cls(
            opaque_text=reader.utf16_string(
                "opaque_text", trailing_byte=True
            )
        )
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, object]:
        return {
            "text_code_units": self.text_code_units,
            "text_redacted": True,
            "higher_level_role": "neutral",
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 9:
            raise PacketShapeError("login client opcode-9 record opcode must be 9")
        return struct.pack("<H", self.opcode) + encode_utf16_string(
            self.opaque_text, trailing_byte=True
        )


@dataclass(frozen=True)
class LoginServerOpcode6TextRecord:
    """Generated-read-backed redacted text record for server opcode 6."""

    opaque_text: str = field(repr=False)
    neutral_value: int = field(repr=False)
    opcode: int = 6

    @property
    def text_code_units(self) -> int:
        return len(self.opaque_text.encode("utf-16-le")) // 2

    @classmethod
    def parse(cls, payload: bytes) -> "LoginServerOpcode6TextRecord":
        reader = PacketReader(payload, packet_name="login_server_opcode_6")
        _expect_opcode(reader, 6)
        record = cls(
            opaque_text=reader.utf16_string(
                "opaque_text", trailing_byte=True
            ),
            neutral_value=reader.u8("neutral_value"),
        )
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, object]:
        return {
            "text_code_units": self.text_code_units,
            "text_redacted": True,
            "value_width_bits": 8,
            "value_redacted": True,
            "higher_level_role": "neutral",
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 6:
            raise PacketShapeError("login server opcode-6 record opcode must be 6")
        if not 0 <= self.neutral_value <= 0xFF:
            raise PacketShapeError(
                "login server opcode-6 neutral value must fit u8"
            )
        return (
            struct.pack("<H", self.opcode)
            + encode_utf16_string(self.opaque_text, trailing_byte=True)
            + struct.pack("<B", self.neutral_value)
        )


@dataclass(frozen=True)
class LoginServerOpcode35Record:
    """Single capture-bounded redacted login-prelude record."""

    opaque_text: str = field(repr=False)
    opcode: int = 35

    @property
    def text_code_units(self) -> int:
        return len(self.opaque_text.encode("utf-16-le")) // 2

    @classmethod
    def parse(cls, payload: bytes) -> "LoginServerOpcode35Record":
        reader = PacketReader(payload, packet_name="login_server_opcode_35")
        _expect_opcode(reader, 35)
        if reader.u8("reserved_prefix_0") != 0:
            raise PacketShapeError(
                "login server opcode-35 prefix[0] must be zero"
            )
        if reader.u8("prefix_marker") != 1:
            raise PacketShapeError(
                "login server opcode-35 prefix marker must be one"
            )
        opaque_text = reader.utf16_string("opaque_text", trailing_byte=True)
        if reader.bytes(3, "reserved_suffix") != b"\x00" * 3:
            raise PacketShapeError(
                "login server opcode-35 suffix must be three zero bytes"
            )
        reader.finish()
        record = cls(opaque_text=opaque_text)
        record._validate()
        return record

    def _validate(self) -> None:
        if self.text_code_units != 7:
            raise PacketShapeError(
                "login server opcode-35 text must contain seven code units"
            )

    def safe_dict(self) -> dict[str, object]:
        return {
            "prefix_constants": [0, 1],
            "text_code_units": self.text_code_units,
            "text_redacted": True,
            "reserved_suffix_zero": True,
            "higher_level_role": "neutral",
        }

    def to_bytes(self) -> bytes:
        self._validate()
        if self.opcode != 35:
            raise PacketShapeError(
                "login server opcode-35 record opcode must be 35"
            )
        return (
            struct.pack("<HBB", self.opcode, 0, 1)
            + encode_utf16_string(self.opaque_text, trailing_byte=True)
            + b"\x00" * 3
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
class Opcode13Type1Envelope:
    opaque_payload: bytes
    message_type: int = 1
    opcode: int = 13

    @classmethod
    def parse(cls, payload: bytes) -> "Opcode13Type1Envelope":
        reader = PacketReader(payload, packet_name="opcode_13_type_1_envelope")
        _expect_opcode(reader, 13)
        message_type = reader.u8("message_type")
        if message_type != 1:
            raise PacketShapeError(
                f"opcode_13_type_1_envelope.message_type is {message_type}, "
                "expected 1"
            )
        opaque_payload = reader.bytes(8, "opaque_payload")
        reader.finish()
        return cls(opaque_payload=opaque_payload)

    def to_bytes(self) -> bytes:
        if self.message_type != 1:
            raise PacketShapeError(
                f"opcode-13 fixed envelope type is {self.message_type}, "
                "expected 1"
            )
        if len(self.opaque_payload) != 8:
            raise PacketShapeError(
                "opcode-13 type-1 envelope needs 8 opaque bytes, got "
                f"{len(self.opaque_payload)}"
            )
        return struct.pack(
            "<HB", self.opcode, self.message_type
        ) + self.opaque_payload


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
class LoginServerFixedRecord:
    """Capture-bounded, value-redacted fixed login-server record."""

    opcode: int
    value: int = field(repr=False)

    VALUE_WIDTHS = {20: 4, 21: 1, 23: 4, 161: 1}
    ZERO_VALUE_OPCODES = {21, 23, 161}

    @classmethod
    def parse(cls, payload: bytes) -> "LoginServerFixedRecord":
        reader = PacketReader(payload, packet_name="login_server_fixed_record")
        opcode = reader.u16("opcode")
        width = cls.VALUE_WIDTHS.get(opcode)
        if width is None:
            raise PacketShapeError(
                f"unsupported fixed login-server opcode {opcode}"
            )
        value = reader.u8("value") if width == 1 else reader.u32("value")
        reader.finish()
        record = cls(opcode=opcode, value=value)
        record._validate()
        return record

    def _validate(self) -> None:
        width = self.VALUE_WIDTHS.get(self.opcode)
        if width is None:
            raise PacketShapeError(
                f"unsupported fixed login-server opcode {self.opcode}"
            )
        maximum = 0xFF if width == 1 else 0xFFFF_FFFF
        if not 0 <= self.value <= maximum:
            raise PacketShapeError(
                "fixed login-server value does not fit its captured width"
            )
        if self.opcode in self.ZERO_VALUE_OPCODES and self.value != 0:
            raise PacketShapeError(
                f"fixed login-server opcode {self.opcode} value must be zero"
            )

    def safe_dict(self) -> dict[str, object]:
        return {
            "value_width_bits": self.VALUE_WIDTHS[self.opcode] * 8,
            "value_zero": self.value == 0,
            "value_redacted": True,
        }

    def to_bytes(self) -> bytes:
        self._validate()
        if self.VALUE_WIDTHS[self.opcode] == 1:
            return struct.pack("<HB", self.opcode, self.value)
        return struct.pack("<HI", self.opcode, self.value)


@dataclass(frozen=True)
class ServerOpcode22IndexedTextLedger:
    """Capture-bounded, text-redacted indexed ledger for server opcode 22."""

    opaque_entries: tuple[tuple[int, str], ...] = field(repr=False)
    opcode: int = 22

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode22IndexedTextLedger":
        reader = PacketReader(
            payload, packet_name="server_opcode_22_indexed_text_ledger"
        )
        _expect_opcode(reader, 22)
        entry_count = reader.u32("entry_count")
        if entry_count > 0x1_0000:
            raise PacketShapeError(
                "server opcode-22 entry count must fit the u16 index space"
            )
        entries: list[tuple[int, str]] = []
        for entry_index in range(entry_count):
            text = reader.utf16_string(
                f"opaque_entries[{entry_index}].text",
                trailing_byte=True,
            )
            index = reader.u16(f"opaque_entries[{entry_index}].index")
            entries.append((index, text))
        reader.finish()
        ledger = cls(opaque_entries=tuple(entries))
        ledger._validate()
        return ledger

    @property
    def text_code_units(self) -> int:
        return sum(
            len(text.encode("utf-16-le")) // 2
            for _, text in self.opaque_entries
        )

    def _validate(self) -> None:
        if self.opcode != 22:
            raise PacketShapeError(
                "server opcode-22 indexed-text ledger opcode must be 22"
            )
        entry_count = len(self.opaque_entries)
        if entry_count > 0x1_0000:
            raise PacketShapeError(
                "server opcode-22 entry count must fit the u16 index space"
            )
        indices = {index for index, _ in self.opaque_entries}
        if indices != set(range(entry_count)):
            raise PacketShapeError(
                "server opcode-22 indices must be a complete unique range"
            )
        for _, text in self.opaque_entries:
            encode_utf16_string(text, trailing_byte=True)

    def safe_dict(self) -> dict[str, object]:
        return {
            "entry_count": len(self.opaque_entries),
            "complete_index_set": True,
            "text_code_units": self.text_code_units,
            "nonempty_text_entries": sum(
                bool(text) for _, text in self.opaque_entries
            ),
            "text_values_redacted": True,
        }

    def to_bytes(self) -> bytes:
        self._validate()
        return (
            struct.pack("<HI", self.opcode, len(self.opaque_entries))
            + b"".join(
                encode_utf16_string(text, trailing_byte=True)
                + struct.pack("<H", index)
                for index, text in self.opaque_entries
            )
        )


@dataclass(frozen=True)
class ClientOpcode6RecordSet:
    """Capture-bounded, value-redacted indexed record set for client opcode 6."""

    neutral_header: tuple[int, int, int, int, int, int, int, int, int] = field(
        repr=False
    )
    opaque_entries: tuple[tuple[int, int], ...] = field(repr=False)
    opcode: int = 6

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode6RecordSet":
        reader = PacketReader(payload, packet_name="client_opcode_6_record_set")
        _expect_opcode(reader, 6)
        neutral_header = (
            reader.u32("neutral_header_0"),
            reader.u32("neutral_header_1"),
            reader.u32("neutral_header_2"),
            reader.u32("neutral_header_3"),
            reader.u32("neutral_header_4"),
            reader.u32("neutral_header_5"),
            reader.u32("neutral_header_6"),
            reader.u32("neutral_header_7"),
            reader.u32("neutral_header_8"),
        )
        record_count = reader.u32("record_count")
        if record_count > 0x1_0000:
            raise PacketShapeError(
                "client opcode-6 record count must fit the u16 index space"
            )
        if reader.remaining != record_count * 6:
            raise PacketShapeError(
                "client opcode-6 record count does not match remaining bytes"
            )
        record_set = cls(
            neutral_header=neutral_header,
            opaque_entries=tuple(
                (
                    reader.u16(f"opaque_entries[{index}].index"),
                    reader.u32(f"opaque_entries[{index}].value"),
                )
                for index in range(record_count)
            ),
        )
        reader.finish()
        record_set._validate()
        return record_set

    def _validate(self) -> None:
        if self.opcode != 6:
            raise PacketShapeError("client opcode-6 record-set opcode must be 6")
        if len(self.neutral_header) != 9:
            raise PacketShapeError(
                "client opcode-6 record-set header must contain nine u32 fields"
            )
        if any(
            value < 0 or value > 0xFFFF_FFFF
            for value in self.neutral_header
        ):
            raise PacketShapeError(
                "client opcode-6 neutral header values must fit in u32"
            )
        if self.neutral_header[1] != 0 or self.neutral_header[5] != 0:
            raise PacketShapeError(
                "client opcode-6 reserved header fields 1 and 5 must be zero"
            )
        record_count = len(self.opaque_entries)
        if record_count > 0x1_0000:
            raise PacketShapeError(
                "client opcode-6 record count must fit the u16 index space"
            )
        indices = {index for index, _ in self.opaque_entries}
        if indices != set(range(record_count)):
            raise PacketShapeError(
                "client opcode-6 record indices must be a complete unique range"
            )
        if any(
            value < 0 or value > 0xFFFF_FFFF
            for _, value in self.opaque_entries
        ):
            raise PacketShapeError(
                "client opcode-6 opaque record values must fit in u32"
            )

    def safe_dict(self) -> dict[str, object]:
        return {
            "neutral_header_fields": len(self.neutral_header),
            "reserved_zero_field_indices": [1, 5],
            "record_count": len(self.opaque_entries),
            "complete_index_set": True,
            "header_values_redacted": True,
            "opaque_values_redacted": True,
        }

    def to_bytes(self) -> bytes:
        self._validate()
        return (
            struct.pack("<H", self.opcode)
            + struct.pack("<9I", *self.neutral_header)
            + struct.pack("<I", len(self.opaque_entries))
            + b"".join(
                struct.pack("<HI", index, value)
                for index, value in self.opaque_entries
            )
        )


@dataclass(frozen=True)
class ClientOpcode31Record:
    """Capture-bounded, content-redacted variable record for client opcode 31."""

    reserved_prefix: bytes = field(repr=False)
    variant: int
    opaque_texts: tuple[str, str, str] = field(repr=False)
    opaque_blob: bytes = field(repr=False)
    reserved_suffix: bytes = field(repr=False)
    opcode: int = 31

    @property
    def text_code_units(self) -> tuple[int, int, int]:
        return (
            len(self.opaque_texts[0].encode("utf-16-le")) // 2,
            len(self.opaque_texts[1].encode("utf-16-le")) // 2,
            len(self.opaque_texts[2].encode("utf-16-le")) // 2,
        )

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode31Record":
        reader = PacketReader(payload, packet_name="client_opcode_31_record")
        _expect_opcode(reader, 31)
        record = cls(
            reserved_prefix=reader.bytes(20, "reserved_prefix"),
            variant=reader.u8("variant"),
            opaque_texts=tuple(
                reader.utf16_string(
                    f"opaque_text_{index}", trailing_byte=True
                )
                for index in range(1, 4)
            ),
            opaque_blob=reader.bytes(
                reader.u32("opaque_blob_length"), "opaque_blob"
            ),
            reserved_suffix=reader.bytes(3, "reserved_suffix"),
        )
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode != 31:
            raise PacketShapeError("client opcode-31 record opcode must be 31")
        if self.reserved_prefix != b"\x00" * 20:
            raise PacketShapeError(
                "client opcode-31 reserved prefix must contain 20 zero bytes"
            )
        if self.variant != 2:
            raise PacketShapeError("client opcode-31 variant must be 2")
        if len(self.opaque_texts) != 3:
            raise PacketShapeError(
                "client opcode-31 record must contain three text fields"
            )
        if len(self.opaque_blob) != 48:
            raise PacketShapeError(
                "client opcode-31 opaque blob must contain 48 bytes"
            )
        if self.reserved_suffix != b"\x00" * 3:
            raise PacketShapeError(
                "client opcode-31 reserved suffix must contain three zero bytes"
            )

    def safe_dict(self) -> dict[str, object]:
        return {
            "variant": self.variant,
            "reserved_prefix_zero": True,
            "text_code_units": list(self.text_code_units),
            "text_fields_redacted": True,
            "opaque_blob_bytes": len(self.opaque_blob),
            "opaque_blob_redacted": True,
            "reserved_suffix_zero": True,
        }

    def to_bytes(self) -> bytes:
        self._validate()
        return (
            struct.pack("<H", self.opcode)
            + self.reserved_prefix
            + struct.pack("<B", self.variant)
            + b"".join(
                encode_utf16_string(text, trailing_byte=True)
                for text in self.opaque_texts
            )
            + struct.pack("<I", len(self.opaque_blob))
            + self.opaque_blob
            + self.reserved_suffix
        )


@dataclass(frozen=True)
class ClientOpcode274OpaqueTextRecord:
    """Single capture-bounded, text-redacted client opcode-274 variant."""

    opaque_text_1: str = field(repr=False)
    middle_value: int
    flags: tuple[int, int]
    opaque_text_2: str = field(repr=False)
    opcode: int = 274

    EXPECTED_TEXT_CODE_UNITS = (768, 74)

    @property
    def text_code_units(self) -> tuple[int, int]:
        return (
            len(self.opaque_text_1.encode("utf-16-le")) // 2,
            len(self.opaque_text_2.encode("utf-16-le")) // 2,
        )

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode274OpaqueTextRecord":
        reader = PacketReader(
            payload, packet_name="client_opcode_274_opaque_text_record"
        )
        _expect_opcode(reader, 274)
        record = cls(
            opaque_text_1=reader.utf16_string(
                "opaque_text_1", trailing_byte=True
            ),
            middle_value=reader.u32("middle_value"),
            flags=(reader.u8("flag_1"), reader.u8("flag_2")),
            opaque_text_2=reader.utf16_string(
                "opaque_text_2", trailing_byte=True
            ),
        )
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode != 274:
            raise PacketShapeError(
                "client opcode-274 opaque-text record opcode must be 274"
            )
        if self.text_code_units != self.EXPECTED_TEXT_CODE_UNITS:
            raise PacketShapeError(
                "client opcode-274 text widths must match the captured "
                "768/74-code-unit variant"
            )
        if self.middle_value != 2:
            raise PacketShapeError(
                "client opcode-274 captured middle value must be 2"
            )
        if self.flags != (1, 1):
            raise PacketShapeError(
                "client opcode-274 captured flags must both be 1"
            )

    def safe_dict(self) -> dict[str, object]:
        return {
            "text_code_units": list(self.text_code_units),
            "text_fields_redacted": True,
            "middle_value": self.middle_value,
            "flags": list(self.flags),
            "higher_level_role": "neutral",
        }

    def to_bytes(self) -> bytes:
        self._validate()
        return (
            struct.pack("<H", self.opcode)
            + encode_utf16_string(self.opaque_text_1, trailing_byte=True)
            + struct.pack("<IBB", self.middle_value, *self.flags)
            + encode_utf16_string(self.opaque_text_2, trailing_byte=True)
        )


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
class CharacterLookEntry:
    """One slot/template pair in a character-select appearance list."""

    slot: int
    item_id: int

    def to_bytes(self) -> bytes:
        if not 0 <= self.slot < 0xFF:
            raise PacketShapeError(
                f"character look slot is out of range: {self.slot}"
            )
        if not 1 <= self.item_id <= 0xFFFF_FFFF:
            raise PacketShapeError(
                f"character look item id is out of range: {self.item_id}"
            )
        return struct.pack("<BI", self.slot, self.item_id)


@dataclass(frozen=True)
class CharacterListAppearance:
    """Lossless typed appearance suffix used by a character-list record."""

    gender: int
    skin: int
    face_id: int
    visible_entries: tuple[CharacterLookEntry, ...]
    masked_entries: tuple[CharacterLookEntry, ...]
    cash_weapon_id: int
    opaque_style_values: tuple[int, int, int, int, int, int, int]

    @staticmethod
    def _parse_entries(
        reader: PacketReader, *, field: str
    ) -> tuple[CharacterLookEntry, ...]:
        entries: list[CharacterLookEntry] = []
        seen_slots: set[int] = set()
        while True:
            slot = reader.u8(f"{field}.slot")
            if slot == 0xFF:
                break
            if slot in seen_slots:
                raise PacketShapeError(
                    f"character_list.{field} repeats slot {slot}"
                )
            seen_slots.add(slot)
            item_id = reader.u32(f"{field}.item_id")
            if item_id == 0:
                raise PacketShapeError(
                    f"character_list.{field} slot {slot} has a zero item id"
                )
            entries.append(CharacterLookEntry(slot=slot, item_id=item_id))
        return tuple(entries)

    @classmethod
    def parse_from(cls, reader: PacketReader) -> "CharacterListAppearance":
        appearance = cls(
            gender=reader.u8("appearance.gender"),
            skin=reader.u8("appearance.skin"),
            face_id=reader.u32("appearance.face_id"),
            visible_entries=cls._parse_entries(
                reader, field="appearance.visible_entries"
            ),
            masked_entries=cls._parse_entries(
                reader, field="appearance.masked_entries"
            ),
            cash_weapon_id=reader.u32("appearance.cash_weapon_id"),
            opaque_style_values=tuple(
                reader.u32(f"appearance.opaque_style_values[{index}]")
                for index in range(7)
            ),
        )
        appearance._validate()
        return appearance

    @property
    def hair_id(self) -> int | None:
        return next(
            (entry.item_id for entry in self.visible_entries if entry.slot == 0),
            None,
        )

    def _validate(self) -> None:
        if self.gender not in (0, 1):
            raise PacketShapeError(
                f"character list appearance gender is {self.gender}, "
                "expected 0 or 1"
            )
        if not 0 <= self.skin <= 0xFF:
            raise PacketShapeError(
                f"character list appearance skin is out of range: {self.skin}"
            )
        if not 1 <= self.face_id <= 0xFFFF_FFFF:
            raise PacketShapeError(
                f"character list face id is out of range: {self.face_id}"
            )
        if len(self.opaque_style_values) != 7:
            raise PacketShapeError(
                "character list appearance must contain seven style values"
            )
        for field, entries in (
            ("visible", self.visible_entries),
            ("masked", self.masked_entries),
        ):
            slots = [entry.slot for entry in entries]
            if len(slots) != len(set(slots)):
                raise PacketShapeError(
                    f"character list {field} appearance slots repeat"
                )

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return b"".join(
                (
                    struct.pack("<BBI", self.gender, self.skin, self.face_id),
                    *(entry.to_bytes() for entry in self.visible_entries),
                    b"\xff",
                    *(entry.to_bytes() for entry in self.masked_entries),
                    b"\xff",
                    struct.pack("<I", self.cash_weapon_id),
                    struct.pack("<7I", *self.opaque_style_values),
                )
            )
        except struct.error as error:
            raise PacketShapeError(
                f"character list appearance field is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class CharacterListRanking:
    """Four signed ranking values conditionally attached to one entry."""

    values: tuple[int, int, int, int]

    @classmethod
    def parse_from(cls, reader: PacketReader) -> "CharacterListRanking":
        return cls(
            values=tuple(
                reader.i32(f"ranking.values[{index}]") for index in range(4)
            )
        )

    def to_bytes(self) -> bytes:
        if len(self.values) != 4:
            raise PacketShapeError(
                "character list ranking must contain four signed values"
            )
        try:
            return struct.pack("<4i", *self.values)
        except struct.error as error:
            raise PacketShapeError(
                f"character list ranking value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class CharacterListRecord:
    """Character stats, appearance, and optional ranking in login opcode 4."""

    snapshot: InitialCharacterSnapshot
    appearance: CharacterListAppearance
    entry_code: int
    ranking: CharacterListRanking | None = None

    @classmethod
    def parse_from(cls, reader: PacketReader) -> "CharacterListRecord":
        snapshot = InitialCharacterSnapshot.parse_from(reader)
        appearance = CharacterListAppearance.parse_from(reader)
        entry_code = reader.u8("record.entry_code")
        ranking_present = reader.u8("record.ranking_present")
        if ranking_present not in (0, 1):
            raise PacketShapeError(
                "character_list.record.ranking_present is "
                f"{ranking_present}, expected 0 or 1"
            )
        ranking = (
            CharacterListRanking.parse_from(reader)
            if ranking_present
            else None
        )
        record = cls(
            snapshot=snapshot,
            appearance=appearance,
            entry_code=entry_code,
            ranking=ranking,
        )
        record._validate()
        return record

    def _validate(self) -> None:
        expected = (
            self.snapshot.gender,
            self.snapshot.skin,
            self.snapshot.face_id,
            self.snapshot.hair_id,
        )
        actual = (
            self.appearance.gender,
            self.appearance.skin,
            self.appearance.face_id,
            self.appearance.hair_id,
        )
        if actual != expected:
            raise PacketShapeError(
                "character list appearance identity does not match its stat "
                "snapshot"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        if not 0 <= self.entry_code <= 0xFF:
            raise PacketShapeError(
                f"character list entry code is out of range: {self.entry_code}"
            )
        return b"".join(
            (
                self.snapshot.to_bytes(),
                self.appearance.to_bytes(),
                bytes((self.entry_code, int(self.ranking is not None))),
                self.ranking.to_bytes() if self.ranking is not None else b"",
            )
        )


@dataclass(frozen=True)
class CharacterListEnvelope:
    """Typed success response with a lossless fallback for error variants."""

    result: int
    reserved_u32_1: int = 0
    reserved_u32_2: int = 0
    records: tuple[CharacterListRecord, ...] = ()
    trailer_u8_1: int = 0
    trailer_u8_2: int = 1
    trailer_u32: int = 3
    failure_payload: bytes = b""
    opcode: int = 4

    @classmethod
    def parse(cls, payload: bytes) -> "CharacterListEnvelope":
        reader = PacketReader(payload, packet_name="character_list")
        _expect_opcode(reader, 4)
        result = reader.i8("result")
        if result != 0:
            failure_payload = reader.bytes(
                reader.remaining, "failure_payload"
            )
            reader.finish()
            return cls(result=result, failure_payload=failure_payload)
        reserved_u32_1 = reader.u32("reserved_u32_1")
        reserved_u32_2 = reader.u32("reserved_u32_2")
        record_count = reader.u8("record_count")
        records = tuple(
            CharacterListRecord.parse_from(reader)
            for _ in range(record_count)
        )
        trailer_u8_1 = reader.u8("trailer_u8_1")
        trailer_u8_2 = reader.u8("trailer_u8_2")
        trailer_u32 = reader.u32("trailer_u32")
        reader.finish()
        return cls(
            result=result,
            reserved_u32_1=reserved_u32_1,
            reserved_u32_2=reserved_u32_2,
            records=records,
            trailer_u8_1=trailer_u8_1,
            trailer_u8_2=trailer_u8_2,
            trailer_u32=trailer_u32,
        )

    def to_bytes(self) -> bytes:
        if not -0x80 <= self.result <= 0x7F:
            raise PacketShapeError(
                f"character list result is out of range: {self.result}"
            )
        prefix = struct.pack("<Hb", self.opcode, self.result)
        if self.result != 0:
            if self.records:
                raise PacketShapeError(
                    "failed character list response cannot contain records"
                )
            return prefix + self.failure_payload
        if self.failure_payload:
            raise PacketShapeError(
                "successful character list response cannot have a failure payload"
            )
        if len(self.records) > 0xFF:
            raise PacketShapeError(
                "character list cannot contain more than 255 records"
            )
        try:
            return b"".join(
                (
                    prefix,
                    struct.pack(
                        "<IIB",
                        self.reserved_u32_1,
                        self.reserved_u32_2,
                        len(self.records),
                    ),
                    *(record.to_bytes() for record in self.records),
                    struct.pack(
                        "<BBI",
                        self.trailer_u8_1,
                        self.trailer_u8_2,
                        self.trailer_u32,
                    ),
                )
            )
        except struct.error as error:
            raise PacketShapeError(
                f"character list envelope field is out of range: {error}"
            ) from error


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
    """Observed world-session entry envelope with a typed character id."""

    entry_value: int
    character_id: int
    opaque_ticket: bytes
    opcode: int = 8

    @classmethod
    def parse(cls, payload: bytes) -> "WorldEntryRequest":
        reader = PacketReader(payload, packet_name="world_entry_request")
        _expect_opcode(reader, 8)
        entry_value = reader.u32("entry_value")
        character_id = reader.u32("character_id")
        opaque_ticket = reader.bytes(56, "opaque_ticket")
        reader.finish()
        if character_id == 0:
            raise PacketShapeError("world entry character id cannot be zero")
        return cls(
            entry_value=entry_value,
            character_id=character_id,
            opaque_ticket=opaque_ticket,
        )

    def to_bytes(self) -> bytes:
        if not 0 <= self.entry_value <= 0xFFFF_FFFF:
            raise PacketShapeError("world entry value must fit in u32")
        if not 1 <= self.character_id <= 0xFFFF_FFFF:
            raise PacketShapeError("world entry character id must fit in nonzero u32")
        if len(self.opaque_ticket) != 56:
            raise PacketShapeError("world entry ticket must contain exactly 56 bytes")
        return (
            struct.pack(
                "<HII", self.opcode, self.entry_value, self.character_id
            )
            + self.opaque_ticket
        )


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

    character_id: int
    data_flags: int
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
            character_id=reader.u32("character.character_id"),
            data_flags=reader.u32("character.data_flags"),
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
                    struct.pack("<II", self.character_id, self.data_flags),
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


@dataclass(frozen=True)
class ClientOpcode10CharacterCreationRequest:
    """Capture-correlated character-creation request with redacted values."""

    name: str = field(repr=False)
    neutral_values: tuple[int, ...] = field(repr=False)
    opcode: int = 10

    @property
    def name_code_units(self) -> int:
        return len(self.name.encode("utf-16-le")) // 2

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode10CharacterCreationRequest":
        reader = PacketReader(payload, packet_name="character_creation_request")
        _expect_opcode(reader, 10)
        request = cls(
            name=reader.utf16_string("name", trailing_byte=True),
            neutral_values=tuple(
                reader.u32(f"neutral_values[{index}]") for index in range(8)
            ),
        )
        reader.finish()
        request._validate()
        return request

    def _validate(self) -> None:
        if not self.name:
            raise PacketShapeError("character creation request name cannot be empty")
        if len(self.neutral_values) != 8:
            raise PacketShapeError(
                "character creation request must contain eight u32 values"
            )
        if any(not 0 <= value <= 0xFFFF_FFFF for value in self.neutral_values):
            raise PacketShapeError(
                "character creation request neutral value must fit u32"
            )

    def appearance_fingerprint(self) -> tuple[int, ...]:
        return self.neutral_values[1:]

    def safe_dict(self) -> dict[str, object]:
        return {
            "name_code_units": self.name_code_units,
            "name_redacted": True,
            "neutral_u32_values": len(self.neutral_values),
            "neutral_values_redacted": True,
        }

    def to_bytes(self) -> bytes:
        self._validate()
        if self.opcode != 10:
            raise PacketShapeError(
                "character creation request opcode must be 10"
            )
        return (
            struct.pack("<H", self.opcode)
            + encode_utf16_string(self.name, trailing_byte=True)
            + struct.pack("<8I", *self.neutral_values)
        )


@dataclass(frozen=True)
class CharacterCreationAppearance:
    """Compact appearance suffix in the captured creation response."""

    gender: int
    skin: int
    face_id: int
    visible_entries: tuple[CharacterLookEntry, ...]
    masked_entries: tuple[CharacterLookEntry, ...]
    cash_weapon_id: int
    opaque_style_values: tuple[int, int, int] = field(repr=False)

    @classmethod
    def parse_from(cls, reader: PacketReader) -> "CharacterCreationAppearance":
        appearance = cls(
            gender=reader.u8("creation_appearance.gender"),
            skin=reader.u8("creation_appearance.skin"),
            face_id=reader.u32("creation_appearance.face_id"),
            visible_entries=CharacterListAppearance._parse_entries(
                reader, field="creation_appearance.visible_entries"
            ),
            masked_entries=CharacterListAppearance._parse_entries(
                reader, field="creation_appearance.masked_entries"
            ),
            cash_weapon_id=reader.u32("creation_appearance.cash_weapon_id"),
            opaque_style_values=tuple(
                reader.u32(f"creation_appearance.opaque_style_values[{index}]")
                for index in range(3)
            ),
        )
        appearance._validate()
        return appearance

    @property
    def hair_id(self) -> int | None:
        return next(
            (entry.item_id for entry in self.visible_entries if entry.slot == 0),
            None,
        )

    def request_fingerprint(self) -> tuple[int, ...]:
        equipment_ids = tuple(
            entry.item_id for entry in self.visible_entries if entry.slot != 0
        )
        return (self.gender, self.face_id, self.hair_id or 0, *equipment_ids)

    def _validate(self) -> None:
        if self.gender not in (0, 1):
            raise PacketShapeError(
                "character creation appearance gender must be zero or one"
            )
        if not 0 <= self.skin <= 0xFF:
            raise PacketShapeError(
                "character creation appearance skin must fit u8"
            )
        if not 1 <= self.face_id <= 0xFFFF_FFFF:
            raise PacketShapeError(
                "character creation appearance face id must be nonzero u32"
            )
        if len(self.opaque_style_values) != 3:
            raise PacketShapeError(
                "character creation appearance must contain three style values"
            )
        for entries in (self.visible_entries, self.masked_entries):
            slots = [entry.slot for entry in entries]
            if len(slots) != len(set(slots)):
                raise PacketShapeError(
                    "character creation appearance slots repeat"
                )

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return b"".join(
                (
                    struct.pack("<BBI", self.gender, self.skin, self.face_id),
                    *(entry.to_bytes() for entry in self.visible_entries),
                    b"\xff",
                    *(entry.to_bytes() for entry in self.masked_entries),
                    b"\xff",
                    struct.pack("<I", self.cash_weapon_id),
                    struct.pack("<3I", *self.opaque_style_values),
                )
            )
        except struct.error as error:
            raise PacketShapeError(
                f"character creation appearance field is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode7CharacterCreationResponse:
    """Generated-branch-backed character-creation response."""

    result: int
    snapshot: InitialCharacterSnapshot | None = None
    appearance: CharacterCreationAppearance | None = None
    failure_payload: bytes = field(default=b"", repr=False)
    opcode: int = 7

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode7CharacterCreationResponse":
        reader = PacketReader(payload, packet_name="character_creation_response")
        _expect_opcode(reader, 7)
        result = reader.u8("result")
        if result != 0:
            response = cls(
                result=result,
                failure_payload=reader.bytes(reader.remaining, "failure_payload"),
            )
            reader.finish()
            return response
        response = cls(
            result=result,
            snapshot=InitialCharacterSnapshot.parse_from(reader),
            appearance=CharacterCreationAppearance.parse_from(reader),
        )
        reader.finish()
        response._validate()
        return response

    def _validate(self) -> None:
        if not 0 <= self.result <= 0xFF:
            raise PacketShapeError("character creation response result must fit u8")
        if self.result != 0:
            if self.snapshot is not None or self.appearance is not None:
                raise PacketShapeError(
                    "failed character creation response cannot carry a record"
                )
            return
        if self.failure_payload:
            raise PacketShapeError(
                "successful character creation response cannot carry failure bytes"
            )
        if self.snapshot is None or self.appearance is None:
            raise PacketShapeError(
                "successful character creation response requires a record"
            )
        expected = (
            self.snapshot.gender,
            self.snapshot.skin,
            self.snapshot.face_id,
            self.snapshot.hair_id,
        )
        actual = (
            self.appearance.gender,
            self.appearance.skin,
            self.appearance.face_id,
            self.appearance.hair_id,
        )
        if actual != expected:
            raise PacketShapeError(
                "character creation appearance does not match its snapshot"
            )

    def safe_dict(self) -> dict[str, object]:
        details: dict[str, object] = {
            "result": self.result,
            "success": self.result == 0,
        }
        if self.result != 0:
            details["failure_payload_bytes"] = len(self.failure_payload)
            return details
        assert self.snapshot is not None
        assert self.appearance is not None
        details.update(
            {
                "character_id_present": True,
                "name_code_units": len(self.snapshot.name.encode("utf-16-le")) // 2,
                "name_redacted": True,
                "level": self.snapshot.level,
                "job_id": self.snapshot.job_id,
                "visible_equipment_count": len(
                    self.appearance.visible_entries
                ),
                "masked_equipment_count": len(
                    self.appearance.masked_entries
                ),
                "style_values_redacted": True,
            }
        )
        return details

    def to_bytes(self) -> bytes:
        self._validate()
        if self.opcode != 7:
            raise PacketShapeError(
                "character creation response opcode must be 7"
            )
        prefix = struct.pack("<HB", self.opcode, self.result)
        if self.result != 0:
            return prefix + self.failure_payload
        assert self.snapshot is not None
        assert self.appearance is not None
        return prefix + self.snapshot.to_bytes() + self.appearance.to_bytes()


@dataclass(frozen=True)
class ClientOpcode16CreatedCharacterSelection:
    """Capture-correlated selection of the newly created character."""

    character_id: int = field(repr=False)
    opcode: int = 16

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode16CreatedCharacterSelection":
        reader = PacketReader(payload, packet_name="created_character_selection")
        _expect_opcode(reader, 16)
        if reader.u8("reserved_zero") != 0:
            raise PacketShapeError(
                "created character selection reserved byte must be zero"
            )
        selection = cls(character_id=reader.u32("character_id"))
        reader.finish()
        if selection.character_id == 0:
            raise PacketShapeError(
                "created character selection id cannot be zero"
            )
        return selection

    def safe_dict(self) -> dict[str, object]:
        return {
            "reserved_zero": True,
            "character_id_present": True,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 16:
            raise PacketShapeError(
                "created character selection opcode must be 16"
            )
        if not 1 <= self.character_id <= 0xFFFF_FFFF:
            raise PacketShapeError(
                "created character selection id must be nonzero u32"
            )
        return struct.pack("<HBI", self.opcode, 0, self.character_id)


INITIAL_ITEM_SENTINEL_TICKS = 94_354_848_000_000_000
PERMANENT_ITEM_EXPIRATION_TICKS = 150_842_304_000_000_000


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

    @classmethod
    def captured_permanent_stack(
        cls, *, slot: int, item_id: int, quantity: int
    ) -> "InitialInventoryItem":
        """Build the zero-owner permanent stack shape observed in opcode 39."""

        if not 1 <= slot <= 0xFF:
            raise PacketShapeError(
                f"permanent stack item slot is out of range: {slot}"
            )
        if not 1 <= item_id <= 0xFFFF_FFFF:
            raise PacketShapeError(
                f"permanent stack item id is out of range: {item_id}"
            )
        if not 1 <= quantity <= 0xFFFF:
            raise PacketShapeError(
                f"permanent stack quantity is out of range: {quantity}"
            )
        raw_record = b"".join(
            (
                struct.pack(
                    "<BIBqH",
                    2,
                    item_id,
                    0,
                    PERMANENT_ITEM_EXPIRATION_TICKS,
                    quantity,
                ),
                b"\x00\x00\x00",
                b"\x00" * 10,
                struct.pack("<qI", INITIAL_ITEM_SENTINEL_TICKS, 0),
            )
        )
        return cls(
            slot=slot,
            record_type=2,
            item_id=item_id,
            cash_item=False,
            expires_at_ticks=PERMANENT_ITEM_EXPIRATION_TICKS,
            quantity=quantity,
            raw_record=raw_record,
        )

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
    """Marker-specific final trailer of the initial field packet."""

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

    @property
    def text_code_unit_lengths(self) -> tuple[int, ...]:
        return tuple(
            len(value.encode("utf-16-le")) // 2
            for value in self.opaque_texts
        )

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
        text_lengths = self.text_code_unit_lengths
        full_text_lengths = (0, 1, 1, 16, 0)
        compact_text_lengths = (0, 0, 0, 0, 0)
        if text_lengths not in (full_text_lengths, compact_text_lengths):
            raise PacketShapeError(
                "initial field trailer text lengths must match the full or "
                "compact captured shape"
            )
        expected_constant = 2 if text_lengths == full_text_lengths else 0
        if self.constant_u8 != expected_constant:
            raise PacketShapeError(
                "initial field trailer constant byte does not match its "
                "text variant"
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
        if self.trailer.text_code_unit_lengths != (0, 1, 1, 16, 0):
            raise PacketShapeError(
                "keyed-property initial progression requires the full trailer"
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
class CompactInitialProgressionSnapshot:
    """Marker-26 progression variant with a compact neutral trailer header."""

    reserved_flag: int
    skill_levels: tuple[tuple[int, int], ...]
    reserved_u16_1: int
    string_properties: tuple[tuple[int, str], ...]
    timestamp_properties: tuple[tuple[int, int], ...]
    reserved_i64: int
    saved_map_ids: tuple[int, ...]
    opaque_variant_header: bytes
    trailer: InitialFieldTrailer

    @classmethod
    def parse(cls, payload: bytes) -> "CompactInitialProgressionSnapshot":
        reader = PacketReader(
            payload, packet_name="compact_initial_progression_snapshot"
        )
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
        opaque_variant_header = reader.bytes(7, "opaque_variant_header")
        snapshot = cls(
            reserved_flag=reserved_flag,
            skill_levels=skill_levels,
            reserved_u16_1=reserved_u16_1,
            string_properties=string_properties,
            timestamp_properties=timestamp_properties,
            reserved_i64=reserved_i64,
            saved_map_ids=saved_map_ids,
            opaque_variant_header=opaque_variant_header,
            trailer=InitialFieldTrailer.parse_from(reader),
        )
        reader.finish()
        snapshot._validate()
        return snapshot

    def _validate(self) -> None:
        if self.reserved_flag != 0 or self.reserved_u16_1 != 0:
            raise PacketShapeError(
                "compact initial progression reserved fields must be zero"
            )
        if self.reserved_i64 != 0:
            raise PacketShapeError(
                "compact initial progression reserved int64 must be zero"
            )
        if len(self.saved_map_ids) != 16:
            raise PacketShapeError(
                "compact initial progression must contain 16 saved map ids"
            )
        if len(self.opaque_variant_header) != 7:
            raise PacketShapeError(
                "compact initial progression variant header must be 7 bytes"
            )
        if self.trailer.text_code_unit_lengths != (0, 0, 0, 0, 0):
            raise PacketShapeError(
                "compact initial progression requires the compact trailer"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        for field, values in (
            ("skill levels", self.skill_levels),
            ("string properties", self.string_properties),
            ("timestamp properties", self.timestamp_properties),
        ):
            if len(values) > 0xFFFF:
                raise PacketShapeError(
                    f"compact initial progression has too many {field}"
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
                    InitialProgressionSnapshot._encode_keyed_strings(
                        self.string_properties
                    ),
                    struct.pack("<H", len(self.timestamp_properties)),
                    b"".join(
                        struct.pack("<Iq", key, ticks)
                        for key, ticks in self.timestamp_properties
                    ),
                    struct.pack("<q", self.reserved_i64),
                    struct.pack("<16I", *self.saved_map_ids),
                    self.opaque_variant_header,
                    self.trailer.to_bytes(),
                )
            )
        except struct.error as error:
            raise PacketShapeError(
                f"compact initial progression field is out of range: {error}"
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

    def parse_progression(
        self,
    ) -> InitialProgressionSnapshot | CompactInitialProgressionSnapshot:
        payload = self.parse_inventory().opaque_remainder
        if self.marker == 26:
            return CompactInitialProgressionSnapshot.parse(payload)
        return InitialProgressionSnapshot.parse(payload)

    def _validate(self) -> None:
        if self.marker not in {23, 26}:
            raise PacketShapeError(
                f"initial field snapshot marker is {self.marker}, expected 23 or 26"
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
class TypedInitialFieldSnapshot:
    """Initial field packet materialized through every decoded nested shape."""

    marker: int
    reserved_flag: int
    contains_character_data: int
    character_data_mode: int
    reserved_u16: int
    opaque_session_u32s: tuple[int, int, int]
    sentinel_i64: int
    character_record_prefix: int
    character: InitialCharacterSnapshot
    inventory_opaque_prefix: bytes
    inventory_groups: tuple[InitialInventoryGroup, ...]
    progression: InitialProgressionSnapshot | CompactInitialProgressionSnapshot
    opcode: int = 157

    @classmethod
    def parse(cls, payload: bytes) -> "TypedInitialFieldSnapshot":
        envelope = InitialFieldSnapshot.parse(payload)
        inventory = envelope.parse_inventory()
        progression = envelope.parse_progression()
        snapshot = cls(
            marker=envelope.marker,
            reserved_flag=envelope.reserved_flag,
            contains_character_data=envelope.contains_character_data,
            character_data_mode=envelope.character_data_mode,
            reserved_u16=envelope.reserved_u16,
            opaque_session_u32s=envelope.opaque_session_u32s,
            sentinel_i64=envelope.sentinel_i64,
            character_record_prefix=envelope.character_record_prefix,
            character=envelope.character,
            inventory_opaque_prefix=inventory.opaque_prefix,
            inventory_groups=inventory.groups,
            progression=progression,
            opcode=envelope.opcode,
        )
        snapshot._validate()
        return snapshot

    @property
    def inventory_item_count(self) -> int:
        return sum(len(group.items) for group in self.inventory_groups)

    def _validate(self) -> None:
        envelope = InitialFieldSnapshot(
            marker=self.marker,
            reserved_flag=self.reserved_flag,
            contains_character_data=self.contains_character_data,
            character_data_mode=self.character_data_mode,
            reserved_u16=self.reserved_u16,
            opaque_session_u32s=self.opaque_session_u32s,
            sentinel_i64=self.sentinel_i64,
            character_record_prefix=self.character_record_prefix,
            character=self.character,
            opaque_tail=b"\x00",
            opcode=self.opcode,
        )
        envelope._validate()
        if self.marker == 26:
            if not isinstance(
                self.progression, CompactInitialProgressionSnapshot
            ):
                raise PacketShapeError(
                    "marker-26 initial field snapshot requires compact "
                    "progression"
                )
        elif not isinstance(self.progression, InitialProgressionSnapshot):
            raise PacketShapeError(
                "marker-23 initial field snapshot requires keyed-property "
                "progression"
            )
        InitialInventorySnapshot(
            opaque_prefix=self.inventory_opaque_prefix,
            groups=self.inventory_groups,
            opaque_remainder=self.progression.to_bytes(),
        ).to_bytes()

    def to_snapshot(self) -> InitialFieldSnapshot:
        self._validate()
        inventory = InitialInventorySnapshot(
            opaque_prefix=self.inventory_opaque_prefix,
            groups=self.inventory_groups,
            opaque_remainder=self.progression.to_bytes(),
        )
        return InitialFieldSnapshot(
            marker=self.marker,
            reserved_flag=self.reserved_flag,
            contains_character_data=self.contains_character_data,
            character_data_mode=self.character_data_mode,
            reserved_u16=self.reserved_u16,
            opaque_session_u32s=self.opaque_session_u32s,
            sentinel_i64=self.sentinel_i64,
            character_record_prefix=self.character_record_prefix,
            character=self.character,
            opaque_tail=inventory.to_bytes(),
            opcode=self.opcode,
        )

    def to_bytes(self) -> bytes:
        return self.to_snapshot().to_bytes()


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
    facing_value: int
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
        facing_value = reader.u8("facing_value")
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
            facing_value=facing_value,
            foothold_id=foothold_id,
            range_left=range_left,
            range_right=range_right,
            hidden=bool(hidden_raw),
        )

    def to_bytes(self) -> bytes:
        if not 0 <= self.facing_value <= 0xFF:
            raise PacketShapeError("NPC spawn facing value must fit in one byte")
        if not isinstance(self.hidden, bool):
            raise PacketShapeError("NPC spawn hidden value must be boolean")
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
            self.facing_value,
            self.foothold_id,
            self.range_left,
            self.range_right,
            int(self.hidden),
        )


@dataclass(frozen=True)
class NpcLifecycleControl:
    """Opcode-302 NPC-manager spawn/removal control."""

    object_id: int = field(repr=False)
    control_value: int
    spawn: NpcSpawn | None = None
    opcode: int = 302

    SPAWN = 1
    REMOVE = 0

    @classmethod
    def parse(cls, payload: bytes) -> "NpcLifecycleControl":
        reader = PacketReader(payload, packet_name="npc_lifecycle_control")
        _expect_opcode(reader, 302)
        control_value = reader.u8("control_value")
        object_id = reader.u32("object_id")
        if control_value == cls.SPAWN:
            spawn_body = reader.bytes(16, "spawn_body")
            spawn = NpcSpawn.parse(
                struct.pack("<HI", 300, object_id) + spawn_body
            )
        elif control_value == cls.REMOVE:
            spawn = None
        else:
            raise PacketShapeError(
                "NPC lifecycle control must be captured spawn value 1 or "
                f"handler-backed removal value 0, got {control_value}"
            )
        reader.finish()
        return cls(
            object_id=object_id,
            control_value=control_value,
            spawn=spawn,
        )

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "object_id_redacted": True,
            "control_value": self.control_value,
            "spawn_present": self.spawn is not None,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 302:
            raise PacketShapeError("NPC lifecycle control opcode must be 302")
        try:
            prefix = struct.pack(
                "<HBI", self.opcode, self.control_value, self.object_id
            )
        except struct.error as error:
            raise PacketShapeError(
                f"NPC lifecycle control value is out of range: {error}"
            ) from error
        if self.control_value == self.SPAWN:
            if self.spawn is None:
                raise PacketShapeError(
                    "NPC lifecycle spawn control requires spawn data"
                )
            if self.spawn.opcode != 300:
                raise PacketShapeError("nested NPC spawn opcode must be 300")
            if self.spawn.object_id != self.object_id:
                raise PacketShapeError(
                    "NPC lifecycle object id does not match nested spawn"
                )
            return prefix + self.spawn.to_bytes()[6:]
        if self.control_value == self.REMOVE:
            if self.spawn is not None:
                raise PacketShapeError(
                    "NPC lifecycle removal control cannot include spawn data"
                )
            return prefix
        raise PacketShapeError(
            "NPC lifecycle control must be spawn value 1 or removal value 0"
        )


@dataclass(frozen=True)
class NpcStateUpdate:
    object_id: int
    action: int
    parameter: int
    opaque_tail: bytes = b""
    opcode: int = 303

    @classmethod
    def parse(cls, payload: bytes) -> "NpcStateUpdate":
        reader = PacketReader(payload, packet_name="npc_state_update")
        _expect_opcode(reader, 303)
        object_id = reader.u32("object_id")
        action = reader.u8("action")
        parameter = reader.u8("parameter")
        opaque_tail = reader.bytes(reader.remaining, "opaque_tail")
        reader.finish()
        return cls(
            object_id=object_id,
            action=action,
            parameter=parameter,
            opaque_tail=opaque_tail,
        )

    def to_bytes(self) -> bytes:
        return struct.pack(
            "<HIBB", self.opcode, self.object_id, self.action, self.parameter
        ) + self.opaque_tail


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
class MobTemporaryStatSet:
    """Capture-bounded opcode-285 single-stat record."""

    object_id: int = field(repr=False)
    value: int
    source_skill_id: int
    source_level: int
    duration_value: int
    flag: int = 1
    mask_words: tuple[int, int, int, int] = (0, 0, 0, 0x80)
    opcode: int = 285

    CAPTURED_MASK_WORDS = (0, 0, 0, 0x80)
    CAPTURED_VALUE = 1
    CAPTURED_FLAG = 1

    @classmethod
    def is_captured_shape(cls, payload: bytes) -> bool:
        if len(payload) != 33:
            return False
        opcode, _, *mask_words = struct.unpack_from("<HI4I", payload)
        value = struct.unpack_from("<H", payload, 22)[0]
        flag = payload[-1]
        return (
            opcode == 285
            and tuple(mask_words) == cls.CAPTURED_MASK_WORDS
            and value == cls.CAPTURED_VALUE
            and flag == cls.CAPTURED_FLAG
        )

    @property
    def enabled_bit_indices(self) -> tuple[int, ...]:
        return tuple(
            word_index * 32 + bit_index
            for word_index, word in enumerate(self.mask_words)
            for bit_index in range(32)
            if word & (1 << bit_index)
        )

    @property
    def mask_pattern(self) -> str:
        return ":".join(f"{word:08x}" for word in self.mask_words)

    @classmethod
    def parse(cls, payload: bytes) -> "MobTemporaryStatSet":
        reader = PacketReader(payload, packet_name="mob_temporary_stat_set")
        _expect_opcode(reader, 285)
        record = cls(
            object_id=reader.u32("object_id"),
            mask_words=tuple(
                reader.u32(f"mask_word_{word_index}")
                for word_index in range(4)
            ),
            value=reader.u16("value"),
            source_skill_id=reader.u32("source_skill_id"),
            source_level=reader.u16("source_level"),
            duration_value=reader.u16("duration_value"),
            flag=reader.u8("flag"),
        )
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode != 285:
            raise PacketShapeError("mob temporary-stat set opcode must be 285")
        if self.mask_words != self.CAPTURED_MASK_WORDS:
            raise PacketShapeError(
                "mob temporary-stat set mask is not the captured single-bit shape"
            )
        if self.value != self.CAPTURED_VALUE:
            raise PacketShapeError(
                "mob temporary-stat set value must be captured value one"
            )
        if self.flag != self.CAPTURED_FLAG:
            raise PacketShapeError(
                "mob temporary-stat set flag must be captured value one"
            )

    def safe_dict(self) -> dict[str, object]:
        return {
            "object_id_redacted": True,
            "mask_words": list(self.mask_words),
            "mask_pattern": self.mask_pattern,
            "enabled_bit_indices": list(self.enabled_bit_indices),
            "value": self.value,
            "source_skill_id": self.source_skill_id,
            "source_level": self.source_level,
            "duration_value": self.duration_value,
            "flag": self.flag,
        }

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack(
                "<HI4IHIHHB",
                self.opcode,
                self.object_id,
                *self.mask_words,
                self.value,
                self.source_skill_id,
                self.source_level,
                self.duration_value,
                self.flag,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"mob temporary-stat set field is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class MobTemporaryStatReset:
    """Capture-bounded opcode-286 single-stat reset."""

    object_id: int = field(repr=False)
    flag: int = 1
    mask_words: tuple[int, int, int, int] = (0, 0, 0, 0x80)
    opcode: int = 286

    CAPTURED_MASK_WORDS = MobTemporaryStatSet.CAPTURED_MASK_WORDS
    CAPTURED_FLAG = 1

    @classmethod
    def is_captured_shape(cls, payload: bytes) -> bool:
        if len(payload) != 23:
            return False
        opcode, _, *mask_words = struct.unpack_from("<HI4I", payload)
        return (
            opcode == 286
            and tuple(mask_words) == cls.CAPTURED_MASK_WORDS
            and payload[-1] == cls.CAPTURED_FLAG
        )

    @property
    def enabled_bit_indices(self) -> tuple[int, ...]:
        return tuple(
            word_index * 32 + bit_index
            for word_index, word in enumerate(self.mask_words)
            for bit_index in range(32)
            if word & (1 << bit_index)
        )

    @property
    def mask_pattern(self) -> str:
        return ":".join(f"{word:08x}" for word in self.mask_words)

    @classmethod
    def parse(cls, payload: bytes) -> "MobTemporaryStatReset":
        reader = PacketReader(payload, packet_name="mob_temporary_stat_reset")
        _expect_opcode(reader, 286)
        record = cls(
            object_id=reader.u32("object_id"),
            mask_words=tuple(
                reader.u32(f"mask_word_{word_index}")
                for word_index in range(4)
            ),
            flag=reader.u8("flag"),
        )
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode != 286:
            raise PacketShapeError(
                "mob temporary-stat reset opcode must be 286"
            )
        if self.mask_words != self.CAPTURED_MASK_WORDS:
            raise PacketShapeError(
                "mob temporary-stat reset mask is not the captured single-bit shape"
            )
        if self.flag != self.CAPTURED_FLAG:
            raise PacketShapeError(
                "mob temporary-stat reset flag must be captured value one"
            )

    def safe_dict(self) -> dict[str, object]:
        return {
            "object_id_redacted": True,
            "mask_words": list(self.mask_words),
            "mask_pattern": self.mask_pattern,
            "enabled_bit_indices": list(self.enabled_bit_indices),
            "flag": self.flag,
        }

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack(
                "<HI4IB",
                self.opcode,
                self.object_id,
                *self.mask_words,
                self.flag,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"mob temporary-stat reset field is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class MobHealthPercentageUpdate:
    object_id: int
    health_percentage: int
    opcode: int = 293

    @classmethod
    def parse(cls, payload: bytes) -> "MobHealthPercentageUpdate":
        reader = PacketReader(
            payload, packet_name="mob_health_percentage_update"
        )
        _expect_opcode(reader, 293)
        object_id = reader.u32("object_id")
        health_percentage = reader.u8("health_percentage")
        reader.finish()
        if health_percentage > 100:
            raise PacketShapeError(
                "mob health percentage must be between zero and 100"
            )
        return cls(
            object_id=object_id,
            health_percentage=health_percentage,
        )

    def to_bytes(self) -> bytes:
        if not 0 <= self.health_percentage <= 100:
            raise PacketShapeError(
                "mob health percentage must be between zero and 100"
            )
        return struct.pack(
            "<HIB", self.opcode, self.object_id, self.health_percentage
        )


@dataclass(frozen=True)
class SkillRecordEntry:
    skill_id: int
    level: int
    auxiliary_value: int

    def _validate(self) -> None:
        if not 0 <= self.skill_id <= 0x7FFF_FFFF:
            raise PacketShapeError("skill record id must fit a non-negative int32")
        for name, value in (
            ("level", self.level),
            ("auxiliary_value", self.auxiliary_value),
        ):
            if not -0x8000_0000 <= value <= 0x7FFF_FFFF:
                raise PacketShapeError(f"skill record {name} must fit int32")

    def to_bytes(self) -> bytes:
        self._validate()
        return struct.pack(
            "<iii", self.skill_id, self.level, self.auxiliary_value
        )


@dataclass(frozen=True)
class SkillRecordUpdate:
    flag_a: bool
    flag_b: bool
    records: tuple[SkillRecordEntry, ...]
    trailing_value: int
    opcode: int = 46

    @classmethod
    def parse(cls, payload: bytes) -> "SkillRecordUpdate":
        reader = PacketReader(payload, packet_name="skill_record_update")
        _expect_opcode(reader, 46)
        flag_a_raw = reader.u8("flag_a")
        flag_b_raw = reader.u8("flag_b")
        for name, value in (("flag_a", flag_a_raw), ("flag_b", flag_b_raw)):
            if value not in {0, 1}:
                raise PacketShapeError(
                    f"skill_record_update.{name} is {value}, expected boolean 0 or 1"
                )
        record_count = reader.i16("record_count")
        if record_count < 0:
            raise PacketShapeError(
                "skill_record_update.record_count must be non-negative"
            )
        records = tuple(
            SkillRecordEntry(
                skill_id=reader.i32(f"records[{index}].skill_id"),
                level=reader.i32(f"records[{index}].level"),
                auxiliary_value=reader.i32(
                    f"records[{index}].auxiliary_value"
                ),
            )
            for index in range(record_count)
        )
        trailing_value = reader.u8("trailing_value")
        reader.finish()
        update = cls(
            flag_a=bool(flag_a_raw),
            flag_b=bool(flag_b_raw),
            records=records,
            trailing_value=trailing_value,
        )
        update._validate()
        return update

    def _validate(self) -> None:
        if len(self.records) > 0x7FFF:
            raise PacketShapeError(
                "skill record update has more than 32767 records"
            )
        if not 0 <= self.trailing_value <= 0xFF:
            raise PacketShapeError(
                "skill record update trailing value must fit uint8"
            )
        for record in self.records:
            record._validate()

    def safe_dict(self) -> dict[str, object]:
        return {
            "flag_a": self.flag_a,
            "flag_b": self.flag_b,
            "record_count": len(self.records),
            "records": [
                {
                    "skill_id": record.skill_id,
                    "level": record.level,
                    "auxiliary_value": record.auxiliary_value,
                }
                for record in self.records
            ],
            "trailing_value": self.trailing_value,
        }

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return b"".join(
                (
                    struct.pack(
                        "<HBBh",
                        self.opcode,
                        int(self.flag_a),
                        int(self.flag_b),
                        len(self.records),
                    ),
                    *(record.to_bytes() for record in self.records),
                    struct.pack("<B", self.trailing_value),
                )
            )
        except struct.error as error:
            raise PacketShapeError(
                f"skill record update field is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class CharacterStatUpdate:
    request_flag: int
    stat_mask: int
    character_level: int | None = None
    job_id: int | None = None
    strength: int | None = None
    dexterity: int | None = None
    intelligence: int | None = None
    luck: int | None = None
    current_hp: int | None = None
    max_hp: int | None = None
    current_mp: int | None = None
    max_mp: int | None = None
    ability_points: int | None = None
    skill_points: int | None = None
    experience: int | None = None
    mesos: int | None = None
    opaque_tail: bytes = b"\x00"
    opcode: int = 41

    CHARACTER_LEVEL = 0x0000_0010
    JOB_ID = 0x0000_0020
    STRENGTH = 0x0000_0040
    DEXTERITY = 0x0000_0080
    INTELLIGENCE = 0x0000_0100
    LUCK = 0x0000_0200
    CURRENT_HP = 0x0000_0400
    MAX_HP = 0x0000_0800
    CURRENT_MP = 0x0000_1000
    MAX_MP = 0x0000_2000
    ABILITY_POINTS = 0x0000_4000
    SKILL_POINTS = 0x0000_8000
    EXPERIENCE = 0x0001_0000
    MESOS = 0x0004_0000
    _FIELD_SPECS = (
        (CHARACTER_LEVEL, "character_level", "<B", 1),
        (JOB_ID, "job_id", "<H", 2),
        (STRENGTH, "strength", "<H", 2),
        (DEXTERITY, "dexterity", "<H", 2),
        (INTELLIGENCE, "intelligence", "<H", 2),
        (LUCK, "luck", "<H", 2),
        (CURRENT_HP, "current_hp", "<H", 2),
        (MAX_HP, "max_hp", "<H", 2),
        (CURRENT_MP, "current_mp", "<H", 2),
        (MAX_MP, "max_mp", "<H", 2),
        (ABILITY_POINTS, "ability_points", "<H", 2),
        (SKILL_POINTS, "skill_points", "<H", 2),
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
        elif not (
            opaque_tail == b"\x00"
            or (len(opaque_tail) == 2 and opaque_tail[0] == 1)
        ):
            raise PacketShapeError(
                "zero-mask character stat update tail must be 00 or 01xx"
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
        elif not (
            self.opaque_tail == b"\x00"
            or (len(self.opaque_tail) == 2 and self.opaque_tail[0] == 1)
        ):
            raise PacketShapeError(
                "zero-mask character stat update tail must be 00 or 01xx"
            )
        return (
            struct.pack("<HBI", self.opcode, self.request_flag, self.stat_mask)
            + b"".join(encoded_values)
            + self.opaque_tail
        )


@dataclass(frozen=True)
class LocalTemporaryStatSetHeader:
    """Structurally decoded prefix of server opcode 42.

    The official client reads four 32-bit mask words before any conditional
    temporary-stat records.  The all-zero-mask branch then reads two bytes and
    one signed 16-bit value.  Non-zero record bodies and the semantic roles of
    the zero-mask suffix remain intentionally opaque.
    """

    mask_words: tuple[int, int, int, int]
    zero_mask_flag_a: int | None = None
    zero_mask_flag_b: int | None = None
    zero_mask_trailing_i16: int | None = None
    opaque_tail: bytes = b""
    opcode: int = 42

    @property
    def zero_mask(self) -> bool:
        return not any(self.mask_words)

    @property
    def enabled_bit_indices(self) -> tuple[int, ...]:
        return tuple(
            word_index * 32 + bit_index
            for word_index, word in enumerate(self.mask_words)
            for bit_index in range(32)
            if word & (1 << bit_index)
        )

    @classmethod
    def parse(cls, payload: bytes) -> "LocalTemporaryStatSetHeader":
        reader = PacketReader(
            payload, packet_name="local_temporary_stat_set_header"
        )
        _expect_opcode(reader, 42)
        mask_words = tuple(
            reader.u32(f"mask_word_{word_index}") for word_index in range(4)
        )
        if any(mask_words):
            return cls(
                mask_words=mask_words,
                opaque_tail=reader.bytes(reader.remaining, "opaque_tail"),
            )
        flag_a = reader.u8("zero_mask_flag_a")
        flag_b = reader.u8("zero_mask_flag_b")
        trailing_i16 = reader.i16("zero_mask_trailing_i16")
        return cls(
            mask_words=mask_words,
            zero_mask_flag_a=flag_a,
            zero_mask_flag_b=flag_b,
            zero_mask_trailing_i16=trailing_i16,
            opaque_tail=reader.bytes(reader.remaining, "opaque_tail"),
        )

    def safe_dict(self) -> dict[str, object]:
        return {
            "mask_words": list(self.mask_words),
            "enabled_bit_indices": list(self.enabled_bit_indices),
            "enabled_bit_count": len(self.enabled_bit_indices),
            "zero_mask": self.zero_mask,
            "zero_mask_flag_a": self.zero_mask_flag_a,
            "zero_mask_flag_b": self.zero_mask_flag_b,
            "zero_mask_trailing_i16": self.zero_mask_trailing_i16,
            "opaque_tail_length": len(self.opaque_tail),
        }

    def to_bytes(self) -> bytes:
        if len(self.mask_words) != 4:
            raise PacketShapeError(
                "local temporary stat set header needs four mask words"
            )
        if any(not 0 <= word <= 0xFFFF_FFFF for word in self.mask_words):
            raise PacketShapeError(
                "local temporary stat set mask words must be uint32 values"
            )
        suffix_values = (
            self.zero_mask_flag_a,
            self.zero_mask_flag_b,
            self.zero_mask_trailing_i16,
        )
        if self.zero_mask:
            if any(value is None for value in suffix_values):
                raise PacketShapeError(
                    "zero-mask local temporary stat set requires its two "
                    "flags and trailing i16"
                )
            flag_a = self.zero_mask_flag_a
            flag_b = self.zero_mask_flag_b
            trailing_i16 = self.zero_mask_trailing_i16
            if flag_a is None or flag_b is None or trailing_i16 is None:
                raise AssertionError("validated zero-mask suffix is incomplete")
            try:
                suffix = struct.pack("<BBh", flag_a, flag_b, trailing_i16)
            except struct.error as error:
                raise PacketShapeError(
                    "zero-mask local temporary stat suffix values are out of range"
                ) from error
        else:
            if any(value is not None for value in suffix_values):
                raise PacketShapeError(
                    "nonzero local temporary stat records remain opaque and "
                    "do not allow zero-mask suffix fields"
                )
            suffix = b""
        return (
            struct.pack("<H4I", self.opcode, *self.mask_words)
            + suffix
            + self.opaque_tail
        )


@dataclass(frozen=True)
class ServerOpcode77Envelope:
    """Redacted structural envelope for server opcode 77.

    The three text fields are retained for exact round trips but deliberately
    omitted from ``safe_dict`` because capture samples contain player-visible
    and user-derived strings.  Variant 8 and unknown variants retain their
    post-text/body bytes as opaque.
    """

    variant: int
    primary_text: str | None = field(default=None, repr=False)
    secondary_text: str | None = field(default=None, repr=False)
    tertiary_text: str | None = field(default=None, repr=False)
    control_bytes: tuple[int, ...] = ()
    terminal_u32: int | None = None
    opaque_tail: bytes = field(default=b"", repr=False)
    opcode: int = 77

    FULLY_BOUNDED_VARIANTS = frozenset({3, 4, 5})
    VARIANT_5_CONTROLS = (3, 10, 10, 2)

    @property
    def text_code_unit_counts(self) -> tuple[int, ...]:
        return tuple(
            len(text.encode("utf-16-le")) // 2
            for text in (
                self.primary_text,
                self.secondary_text,
                self.tertiary_text,
            )
            if text is not None
        )

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode77Envelope":
        reader = PacketReader(payload, packet_name="server_opcode_77_envelope")
        _expect_opcode(reader, 77)
        variant = reader.u8("variant")
        primary_text = None
        secondary_text = None
        tertiary_text = None
        control_bytes: tuple[int, ...] = ()
        terminal_u32 = None
        opaque_tail = b""
        if variant == 3:
            primary_text = reader.utf16_string(
                "primary_text", trailing_byte=False
            )
            control_bytes = tuple(reader.bytes(3, "control_bytes"))
        elif variant == 4:
            enabled = reader.u8("text_present")
            if enabled not in {0, 1}:
                raise PacketShapeError(
                    "server_opcode_77_envelope.text_present is "
                    f"{enabled}, expected boolean 0 or 1"
                )
            control_bytes = (enabled,)
            if enabled:
                primary_text = reader.utf16_string(
                    "primary_text", trailing_byte=True
                )
        elif variant == 5:
            primary_text = reader.utf16_string(
                "primary_text", trailing_byte=False
            )
            prefix_a = reader.u8("prefix_a")
            prefix_b = reader.u8("prefix_b")
            secondary_text = reader.utf16_string(
                "secondary_text", trailing_byte=True
            )
            separator = reader.u8("separator")
            tertiary_text = reader.utf16_string(
                "tertiary_text", trailing_byte=True
            )
            terminal_tag = reader.u8("terminal_tag")
            control_bytes = (prefix_a, prefix_b, separator, terminal_tag)
            if control_bytes != cls.VARIANT_5_CONTROLS:
                raise PacketShapeError(
                    "server_opcode_77_envelope variant 5 control bytes are "
                    f"{control_bytes}, expected {cls.VARIANT_5_CONTROLS}"
                )
            terminal_u32 = reader.u32("terminal_u32")
        elif variant == 8:
            primary_text = reader.utf16_string(
                "primary_text", trailing_byte=False
            )
            opaque_tail = reader.bytes(reader.remaining, "opaque_tail")
        else:
            opaque_tail = reader.bytes(reader.remaining, "opaque_body")
        reader.finish()
        return cls(
            variant=variant,
            primary_text=primary_text,
            secondary_text=secondary_text,
            tertiary_text=tertiary_text,
            control_bytes=control_bytes,
            terminal_u32=terminal_u32,
            opaque_tail=opaque_tail,
        )

    def safe_dict(self) -> dict[str, object]:
        return {
            "variant": self.variant,
            "text_field_count": len(self.text_code_unit_counts),
            "text_code_unit_counts": list(self.text_code_unit_counts),
            "control_bytes": list(self.control_bytes),
            "terminal_u32": self.terminal_u32,
            "opaque_tail_length": len(self.opaque_tail),
            "text_redacted": bool(self.text_code_unit_counts),
        }

    def to_bytes(self) -> bytes:
        try:
            header = struct.pack("<HB", self.opcode, self.variant)
            encoded_controls = bytes(self.control_bytes)
        except (struct.error, TypeError, ValueError) as error:
            raise PacketShapeError(
                "server opcode-77 opcode, variant, and controls must fit "
                "their unsigned integer widths"
            ) from error
        texts = (self.primary_text, self.secondary_text, self.tertiary_text)
        if self.variant == 3:
            if self.primary_text is None or any(
                text is not None for text in texts[1:]
            ):
                raise PacketShapeError(
                    "server opcode-77 variant 3 requires only primary_text"
                )
            if len(self.control_bytes) != 3:
                raise PacketShapeError(
                    "server opcode-77 variant 3 needs three control bytes"
                )
            if self.terminal_u32 is not None or self.opaque_tail:
                raise PacketShapeError(
                    "server opcode-77 variant 3 has no terminal value or "
                    "opaque tail"
                )
            return (
                header
                + encode_utf16_string(self.primary_text, trailing_byte=False)
                + encoded_controls
            )
        if self.variant == 4:
            if (
                len(self.control_bytes) != 1
                or self.control_bytes[0] not in {0, 1}
            ):
                raise PacketShapeError(
                    "server opcode-77 variant 4 needs one boolean control byte"
                )
            enabled = self.control_bytes[0]
            if bool(self.primary_text is not None) != bool(enabled):
                raise PacketShapeError(
                    "server opcode-77 variant 4 text must match its presence flag"
                )
            if any(text is not None for text in texts[1:]):
                raise PacketShapeError(
                    "server opcode-77 variant 4 allows only primary_text"
                )
            if self.terminal_u32 is not None or self.opaque_tail:
                raise PacketShapeError(
                    "server opcode-77 variant 4 has no terminal value or "
                    "opaque tail"
                )
            body = bytes((enabled,))
            if self.primary_text is not None:
                body += encode_utf16_string(
                    self.primary_text, trailing_byte=True
                )
            return header + body
        if self.variant == 5:
            if any(text is None for text in texts):
                raise PacketShapeError(
                    "server opcode-77 variant 5 requires three text fields"
                )
            if self.control_bytes != self.VARIANT_5_CONTROLS:
                raise PacketShapeError(
                    "server opcode-77 variant 5 needs control bytes "
                    f"{self.VARIANT_5_CONTROLS}"
                )
            if self.terminal_u32 is None:
                raise PacketShapeError(
                    "server opcode-77 variant 5 requires terminal_u32"
                )
            if self.opaque_tail:
                raise PacketShapeError(
                    "server opcode-77 variant 5 has no opaque tail"
                )
            primary_text = self.primary_text
            secondary_text = self.secondary_text
            tertiary_text = self.tertiary_text
            if (
                primary_text is None
                or secondary_text is None
                or tertiary_text is None
            ):
                raise AssertionError("validated opcode-77 texts are incomplete")
            try:
                terminal = struct.pack("<I", self.terminal_u32)
            except struct.error as error:
                raise PacketShapeError(
                    "server opcode-77 terminal_u32 must fit uint32"
                ) from error
            return b"".join(
                (
                    header,
                    encode_utf16_string(primary_text, trailing_byte=False),
                    encoded_controls[:2],
                    encode_utf16_string(secondary_text, trailing_byte=True),
                    encoded_controls[2:3],
                    encode_utf16_string(tertiary_text, trailing_byte=True),
                    encoded_controls[3:4],
                    terminal,
                )
            )
        if self.variant == 8:
            if self.primary_text is None or any(
                text is not None for text in texts[1:]
            ):
                raise PacketShapeError(
                    "server opcode-77 variant 8 requires only primary_text"
                )
            if self.control_bytes or self.terminal_u32 is not None:
                raise PacketShapeError(
                    "server opcode-77 variant 8 retains only an opaque tail"
                )
            return (
                header
                + encode_utf16_string(self.primary_text, trailing_byte=False)
                + self.opaque_tail
            )
        if any(text is not None for text in texts):
            raise PacketShapeError(
                "unknown server opcode-77 variants cannot contain typed text"
            )
        if self.control_bytes or self.terminal_u32 is not None:
            raise PacketShapeError(
                "unknown server opcode-77 variants retain only an opaque body"
            )
        return header + self.opaque_tail


@dataclass(frozen=True)
class InventoryModification:
    operation: int
    inventory_type: int
    slot: int
    quantity: int | None = None
    item: InitialInventoryItem | None = None
    destination_slot: int | None = None
    move_flag: int | None = None

    ADD = 0
    UPDATE_QUANTITY = 1
    MOVE = 2
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
        MOVE: "move",
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
        if inventory_type not in {1, 2, 3, 4, 5}:
            raise PacketShapeError(
                "inventory add record supports captured inventory types "
                "one through five"
            )
        record_start = reader.offset
        record_type = reader.u8(f"{field_prefix}.item.record_type")
        allowed_record_types = (
            {1}
            if inventory_type == 1
            else ({2, 3} if inventory_type == 5 else {2})
        )
        if record_type not in allowed_record_types:
            raise PacketShapeError(
                f"inventory type {inventory_type} add record type is "
                f"{record_type}, expected one of {sorted(allowed_record_types)}"
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
        if record_type == 1:
            sentinel_bytes = INITIAL_ITEM_SENTINEL_TICKS.to_bytes(
                8, "little", signed=True
            )
            first_sentinel = reader.payload.find(sentinel_bytes, reader.offset)
            if first_sentinel < 0:
                raise PacketShapeError(
                    "inventory equipment item lacks its first sentinel"
                )
            second_sentinel = reader.payload.find(
                sentinel_bytes, first_sentinel + len(sentinel_bytes)
            )
            if second_sentinel < 0:
                raise PacketShapeError(
                    "inventory equipment item lacks its second sentinel"
                )
            record_end = second_sentinel + len(sentinel_bytes) + 4
            if record_end > len(reader.payload):
                raise PacketShapeError(
                    "inventory equipment item tail is truncated"
                )
            if (
                reader.payload[first_sentinel + 8 : first_sentinel + 12]
                != b"\xff" * 4
            ):
                raise PacketShapeError(
                    "inventory equipment first sentinel tail is not -1"
                )
            if (
                reader.payload[second_sentinel + 8 : record_end]
                != b"\x00" * 4
            ):
                raise PacketShapeError(
                    "inventory equipment second sentinel tail is not zero"
                )
            reader.bytes(
                record_end - reader.offset,
                f"{field_prefix}.item.equipment_metadata",
            )
        elif record_type == 2:
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
        destination_slot = None
        move_flag = None
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
        elif operation == cls.MOVE:
            destination_slot = reader.i16(f"{field}.destination_slot")
            move_flag = reader.u8(f"{field}.move_flag")
        return cls(
            operation=operation,
            inventory_type=inventory_type,
            slot=slot,
            quantity=quantity,
            item=item,
            destination_slot=destination_slot,
            move_flag=move_flag,
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
        if self.destination_slot is not None:
            details["destination_slot"] = self.destination_slot
            details["move_flag"] = self.move_flag
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
            if (
                self.quantity is not None
                or self.item is None
                or self.destination_slot is not None
                or self.move_flag is not None
            ):
                raise PacketShapeError(
                    "inventory add requires an item and no separate quantity"
                )
            if self.item.slot != self.slot:
                raise PacketShapeError(
                    "inventory add slot does not match the item slot"
                )
            allowed_record_types = (
                {1}
                if self.inventory_type == 1
                else ({2, 3} if self.inventory_type == 5 else {2})
            )
            if self.inventory_type not in {1, 2, 3, 4, 5}:
                raise PacketShapeError(
                    "inventory add record supports captured inventory types "
                    "one through five"
                )
            if self.item.record_type not in allowed_record_types:
                raise PacketShapeError(
                    "inventory add item record type does not match inventory"
                )
            return body + self.item.to_bytes()[1:]
        if self.operation == self.MOVE:
            if self.quantity is not None or self.item is not None:
                raise PacketShapeError(
                    "inventory move cannot carry quantity or item data"
                )
            if self.destination_slot is None or self.move_flag is None:
                raise PacketShapeError(
                    "inventory move requires destination slot and move flag"
                )
            if not -0x8000 <= self.destination_slot <= 0x7FFF:
                raise PacketShapeError(
                    "inventory destination slot must fit in a signed short"
                )
            if not 0 <= self.move_flag <= 0xFF:
                raise PacketShapeError("inventory move flag must fit in one byte")
            return body + struct.pack(
                "<hB", self.destination_slot, self.move_flag
            )
        if (
            self.quantity is not None
            or self.item is not None
            or self.destination_slot is not None
            or self.move_flag is not None
        ):
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
class InventoryMoveRequest:
    """Client request to move one inventory entry between signed slots."""

    client_tick: int
    inventory_type: int
    source_slot: int
    destination_slot: int
    trailing_count: int
    opcode: int = 79

    @classmethod
    def parse(cls, payload: bytes) -> "InventoryMoveRequest":
        reader = PacketReader(payload, packet_name="inventory_move_request")
        _expect_opcode(reader, 79)
        client_tick = reader.u32("client_tick")
        inventory_type = reader.u8("inventory_type")
        if inventory_type not in InventoryModification.INVENTORY_NAMES:
            raise PacketShapeError(
                f"inventory move request type is {inventory_type}, expected "
                "one through five"
            )
        source_slot = reader.i16("source_slot")
        destination_slot = reader.i16("destination_slot")
        trailing_count = reader.i16("trailing_count")
        reader.finish()
        if source_slot == destination_slot:
            raise PacketShapeError(
                "inventory move request source and destination must differ"
            )
        return cls(
            client_tick=client_tick,
            inventory_type=inventory_type,
            source_slot=source_slot,
            destination_slot=destination_slot,
            trailing_count=trailing_count,
        )

    @property
    def inventory_name(self) -> str:
        return InventoryModification.INVENTORY_NAMES[self.inventory_type]

    def safe_dict(self) -> dict[str, int | str]:
        return {
            "client_tick": self.client_tick,
            "inventory": self.inventory_name,
            "source_slot": self.source_slot,
            "destination_slot": self.destination_slot,
            "trailing_count": self.trailing_count,
        }

    def to_bytes(self) -> bytes:
        if not 0 <= self.client_tick <= 0xFFFF_FFFF:
            raise PacketShapeError("inventory-move client tick must fit in u32")
        if self.inventory_type not in InventoryModification.INVENTORY_NAMES:
            raise PacketShapeError(
                "inventory move request type must be between one and five"
            )
        for name, value in (
            ("source", self.source_slot),
            ("destination", self.destination_slot),
            ("trailing count", self.trailing_count),
        ):
            if not -0x8000 <= value <= 0x7FFF:
                raise PacketShapeError(
                    f"inventory move request {name} must fit in a signed short"
                )
        if self.source_slot == self.destination_slot:
            raise PacketShapeError(
                "inventory move request source and destination must differ"
            )
        return struct.pack(
            "<HIBhhh",
            self.opcode,
            self.client_tick,
            self.inventory_type,
            self.source_slot,
            self.destination_slot,
            self.trailing_count,
        )


@dataclass(frozen=True)
class ItemUseRequest:
    """Client request to consume one stack item from a Use-inventory slot."""

    client_tick: int
    slot: int
    item_id: int
    opcode: int = 80

    @classmethod
    def parse(cls, payload: bytes) -> "ItemUseRequest":
        reader = PacketReader(payload, packet_name="item_use_request")
        _expect_opcode(reader, 80)
        client_tick = reader.u32("client_tick")
        slot = reader.i16("slot")
        item_id = reader.u32("item_id")
        reader.finish()
        return cls(client_tick=client_tick, slot=slot, item_id=item_id)

    def safe_dict(self) -> dict[str, int]:
        return {
            "client_tick": self.client_tick,
            "slot": self.slot,
            "item_id": self.item_id,
        }

    def to_bytes(self) -> bytes:
        if not 0 <= self.client_tick <= 0xFFFF_FFFF:
            raise PacketShapeError("item-use client tick must fit in u32")
        if not 1 <= self.slot <= 0x7FFF:
            raise PacketShapeError(
                "item-use inventory slot must be between 1 and 32767"
            )
        if not 0 <= self.item_id <= 0xFFFF_FFFF:
            raise PacketShapeError("item-use template id must fit in u32")
        return struct.pack(
            "<HIhI", self.opcode, self.client_tick, self.slot, self.item_id
        )


@dataclass(frozen=True)
class ChairSitRequest:
    """Client request to sit on one Setup-inventory chair item."""

    item_id: int
    opcode: int = 49

    @classmethod
    def parse(cls, payload: bytes) -> "ChairSitRequest":
        reader = PacketReader(payload, packet_name="chair_sit_request")
        _expect_opcode(reader, 49)
        item_id = reader.u32("item_id")
        reader.finish()
        return cls(item_id=item_id)

    def safe_dict(self) -> dict[str, int]:
        return {"item_id": self.item_id}

    def _validate(self) -> None:
        if self.opcode != 49:
            raise PacketShapeError("chair-sit request opcode must be 49")
        if not 0 <= self.item_id <= 0xFFFF_FFFF:
            raise PacketShapeError("chair-sit item id must fit in u32")

    def to_bytes(self) -> bytes:
        self._validate()
        return struct.pack("<HI", self.opcode, self.item_id)


@dataclass(frozen=True)
class ChairStandRequest:
    """Captured client request to leave a chair, carrying marker -1."""

    marker: int = -1
    opcode: int = 48

    @classmethod
    def parse(cls, payload: bytes) -> "ChairStandRequest":
        reader = PacketReader(payload, packet_name="chair_stand_request")
        _expect_opcode(reader, 48)
        marker = reader.i16("marker")
        reader.finish()
        request = cls(marker=marker)
        request._validate()
        return request

    def _validate(self) -> None:
        if self.opcode != 48:
            raise PacketShapeError("chair-stand request opcode must be 48")
        if self.marker != -1:
            raise PacketShapeError("chair-stand marker must be captured -1")

    def safe_dict(self) -> dict[str, int]:
        return {"marker": self.marker}

    def to_bytes(self) -> bytes:
        self._validate()
        return struct.pack("<Hh", self.opcode, self.marker)


@dataclass(frozen=True)
class ChairRecoveryRequest:
    """Empty client request observed 20 seconds after sitting on a chair."""

    opcode: int = 82

    @classmethod
    def parse(cls, payload: bytes) -> "ChairRecoveryRequest":
        reader = PacketReader(payload, packet_name="chair_recovery_request")
        _expect_opcode(reader, 82)
        reader.finish()
        return cls()

    def to_bytes(self) -> bytes:
        if self.opcode != 82:
            raise PacketShapeError("chair-recovery request opcode must be 82")
        return struct.pack("<H", self.opcode)


@dataclass(frozen=True)
class ItemPickupRequest:
    """Client request to collect one field drop in full or compact form."""

    control_value: int | None
    field_epoch: int
    client_tick: int
    position_x: int
    position_y: int
    drop_object_id: int
    item_validation_token: int
    optional_proof: bytes = b""
    opcode: int = 185

    @classmethod
    def parse(cls, payload: bytes) -> "ItemPickupRequest":
        reader = PacketReader(payload, packet_name="item_pickup_request")
        opcode = reader.u16("opcode")
        if opcode not in {185, 222}:
            raise PacketShapeError(
                f"item-pickup opcode is {opcode}, expected 185 or 222"
            )
        control_value = (
            reader.u32("control_value") if opcode == 185 else None
        )
        field_epoch = reader.u8("field_epoch")
        client_tick = reader.u32("client_tick")
        position_x = reader.i16("position_x")
        position_y = reader.i16("position_y")
        drop_object_id = reader.u32("drop_object_id")
        item_validation_token = reader.u32("item_validation_token")
        allowed_proof_lengths = {0, 12} if opcode == 185 else {0}
        if reader.remaining not in allowed_proof_lengths:
            message = (
                "item-pickup optional proof must be absent or 12 bytes"
                if opcode == 185
                else "compact item-pickup request cannot include optional proof"
            )
            raise PacketShapeError(message)
        optional_proof = reader.bytes(reader.remaining, "optional_proof")
        reader.finish()
        return cls(
            control_value=control_value,
            field_epoch=field_epoch,
            client_tick=client_tick,
            position_x=position_x,
            position_y=position_y,
            drop_object_id=drop_object_id,
            item_validation_token=item_validation_token,
            optional_proof=optional_proof,
            opcode=opcode,
        )

    @property
    def shape_name(self) -> str:
        if self.opcode == 222:
            return "compact"
        return "extended" if self.optional_proof else "base"

    def safe_dict(self) -> dict[str, object]:
        return {
            "control_value": self.control_value,
            "field_epoch": self.field_epoch,
            "client_tick": self.client_tick,
            "position_x": self.position_x,
            "position_y": self.position_y,
            "item_validation_token_present": bool(self.item_validation_token),
            "optional_proof_bytes": len(self.optional_proof),
        }

    def to_bytes(self) -> bytes:
        if self.opcode not in {185, 222}:
            raise PacketShapeError("item-pickup opcode must be 185 or 222")
        if self.opcode == 185:
            if self.control_value is None or not (
                0 <= self.control_value <= 0xFFFF_FFFF
            ):
                raise PacketShapeError(
                    "full item-pickup control value must fit in u32"
                )
        elif self.control_value is not None:
            raise PacketShapeError(
                "compact item-pickup request cannot include a control value"
            )
        if not 0 <= self.field_epoch <= 0xFF:
            raise PacketShapeError("item-pickup field epoch must fit in u8")
        if not 0 <= self.client_tick <= 0xFFFF_FFFF:
            raise PacketShapeError("item-pickup client tick must fit in u32")
        for name, value in (
            ("position x", self.position_x),
            ("position y", self.position_y),
        ):
            if not -0x8000 <= value <= 0x7FFF:
                raise PacketShapeError(f"item-pickup {name} must fit in i16")
        for name, value in (
            ("drop object id", self.drop_object_id),
            ("item validation token", self.item_validation_token),
        ):
            if not 0 <= value <= 0xFFFF_FFFF:
                raise PacketShapeError(f"item-pickup {name} must fit in u32")
        allowed_proof_lengths = {0, 12} if self.opcode == 185 else {0}
        if len(self.optional_proof) not in allowed_proof_lengths:
            message = (
                "item-pickup optional proof must be absent or 12 bytes"
                if self.opcode == 185
                else "compact item-pickup request cannot include optional proof"
            )
            raise PacketShapeError(message)
        prefix = struct.pack("<H", self.opcode)
        if self.control_value is not None:
            prefix += struct.pack("<I", self.control_value)
        return prefix + struct.pack(
            "<BIhhII",
            self.field_epoch,
            self.client_tick,
            self.position_x,
            self.position_y,
            self.drop_object_id,
            self.item_validation_token,
        ) + bytes(self.optional_proof)


@dataclass(frozen=True)
class ServerOpcode49Envelope:
    """Non-pickup server opcode-49 variants with redacted text fields.

    Variant zero belongs to :class:`PickupGainNotice`.  The remaining
    capture-observed variants share this neutral envelope but have distinct
    keyed-text, numeric, and partially opaque record bodies.
    """

    variant: int
    key: int | None = None
    value_kind: int | None = None
    text_value: str | None = field(default=None, repr=False)
    numeric_value: int | None = None
    record_marker: int | None = None
    record_value: int | None = None
    reserved_value: int | None = None
    opaque_tail: bytes = field(default=b"", repr=False)
    opcode: int = 49

    TEXT_VALUE = 1
    U64_VALUE = 2
    FULLY_BOUNDED_VARIANTS = frozenset({6, 10, 12})

    @property
    def text_code_unit_count(self) -> int | None:
        if self.text_value is None:
            return None
        return len(self.text_value.encode("utf-16-le")) // 2

    @property
    def fully_bounded(self) -> bool:
        return (
            self.variant in self.FULLY_BOUNDED_VARIANTS
            or (
                self.variant == 1
                and self.value_kind in {self.TEXT_VALUE, self.U64_VALUE}
                and not self.opaque_tail
            )
        )

    @property
    def shape_name(self) -> str:
        if self.variant == 1:
            if self.value_kind == self.TEXT_VALUE:
                return "keyed_text"
            if self.value_kind == self.U64_VALUE:
                return "keyed_u64"
            return "keyed_opaque"
        return {
            3: "numeric_record_opaque",
            4: "opaque_record",
            6: "u64",
            10: "text",
            12: "keyed_text",
        }.get(self.variant, "unknown_opaque")

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode49Envelope":
        reader = PacketReader(payload, packet_name="server_opcode_49_envelope")
        _expect_opcode(reader, 49)
        variant = reader.u8("variant")
        if variant == 0:
            raise PacketShapeError(
                "server_opcode_49_envelope variant 0 is a pickup gain notice"
            )
        values: dict[str, int | str | bytes] = {}
        if variant == 1:
            values["key"] = reader.u32("key")
            value_kind = reader.u8("value_kind")
            values["value_kind"] = value_kind
            if value_kind == cls.TEXT_VALUE:
                values["text_value"] = reader.utf16_string(
                    "text_value", trailing_byte=True
                )
            elif value_kind == cls.U64_VALUE:
                values["numeric_value"] = reader.u64("numeric_value")
            else:
                values["opaque_tail"] = reader.bytes(
                    reader.remaining, "opaque_value"
                )
        elif variant == 3:
            values["record_marker"] = reader.u8("record_marker")
            values["record_value"] = reader.u32("record_value")
            values["opaque_tail"] = reader.bytes(
                reader.remaining, "opaque_tail"
            )
        elif variant == 4:
            values["opaque_tail"] = reader.bytes(
                reader.remaining, "opaque_body"
            )
        elif variant == 6:
            values["numeric_value"] = reader.u64("numeric_value")
        elif variant == 10:
            reserved_value = reader.u8("reserved_value")
            if reserved_value != 0:
                raise PacketShapeError(
                    "server_opcode_49_envelope variant 10 reserved value is "
                    f"{reserved_value}, expected 0"
                )
            values["reserved_value"] = reserved_value
            values["text_value"] = reader.utf16_string(
                "text_value", trailing_byte=True
            )
        elif variant == 12:
            values["key"] = reader.u32("key")
            values["text_value"] = reader.utf16_string(
                "text_value", trailing_byte=True
            )
        else:
            values["opaque_tail"] = reader.bytes(
                reader.remaining, "opaque_body"
            )
        reader.finish()
        return cls(variant=variant, **values)

    def safe_dict(self) -> dict[str, int | str | bool | None]:
        return {
            "variant": self.variant,
            "shape": self.shape_name,
            "key": self.key,
            "value_kind": self.value_kind,
            "numeric_value": self.numeric_value,
            "record_marker": self.record_marker,
            "record_value": self.record_value,
            "reserved_value": self.reserved_value,
            "text_present": self.text_value is not None,
            "text_code_units": self.text_code_unit_count,
            "text_redacted": self.text_value is not None,
            "opaque_tail_length": len(self.opaque_tail),
        }

    def to_bytes(self) -> bytes:
        typed_values = {
            "key": self.key,
            "value_kind": self.value_kind,
            "text_value": self.text_value,
            "numeric_value": self.numeric_value,
            "record_marker": self.record_marker,
            "record_value": self.record_value,
            "reserved_value": self.reserved_value,
        }

        def reject_fields(*allowed: str) -> None:
            foreign = sorted(
                name
                for name, value in typed_values.items()
                if name not in allowed and value is not None
            )
            if foreign:
                raise PacketShapeError(
                    "server opcode-49 variant "
                    f"{self.variant} has foreign fields {foreign}"
                )

        try:
            header = struct.pack("<HB", self.opcode, self.variant)
            if self.variant == 0:
                raise PacketShapeError(
                    "server opcode-49 variant 0 must use PickupGainNotice"
                )
            if self.variant == 1:
                reject_fields("key", "value_kind", "text_value", "numeric_value")
                if self.key is None or self.value_kind is None:
                    raise PacketShapeError(
                        "server opcode-49 variant 1 requires key and value_kind"
                    )
                body = struct.pack("<IB", self.key, self.value_kind)
                if self.value_kind == self.TEXT_VALUE:
                    if self.text_value is None or self.numeric_value is not None:
                        raise PacketShapeError(
                            "server opcode-49 keyed text requires only text_value"
                        )
                    if self.opaque_tail:
                        raise PacketShapeError(
                            "server opcode-49 keyed text cannot retain opaque bytes"
                        )
                    return header + body + encode_utf16_string(
                        self.text_value, trailing_byte=True
                    )
                if self.value_kind == self.U64_VALUE:
                    if self.numeric_value is None or self.text_value is not None:
                        raise PacketShapeError(
                            "server opcode-49 keyed u64 requires only numeric_value"
                        )
                    if self.opaque_tail:
                        raise PacketShapeError(
                            "server opcode-49 keyed u64 cannot retain opaque bytes"
                        )
                    return header + body + struct.pack("<Q", self.numeric_value)
                if self.text_value is not None or self.numeric_value is not None:
                    raise PacketShapeError(
                        "unmodeled opcode-49 keyed kinds retain only opaque bytes"
                    )
                return header + body + bytes(self.opaque_tail)
            if self.variant == 3:
                reject_fields("record_marker", "record_value")
                if self.record_marker is None or self.record_value is None:
                    raise PacketShapeError(
                        "server opcode-49 variant 3 requires marker and value"
                    )
                return header + struct.pack(
                    "<BI", self.record_marker, self.record_value
                ) + bytes(self.opaque_tail)
            if self.variant == 4:
                reject_fields()
                return header + bytes(self.opaque_tail)
            if self.variant == 6:
                reject_fields("numeric_value")
                if self.numeric_value is None:
                    raise PacketShapeError(
                        "server opcode-49 variant 6 requires numeric_value"
                    )
                if self.opaque_tail:
                    raise PacketShapeError(
                        "server opcode-49 variant 6 has no opaque tail"
                    )
                return header + struct.pack("<Q", self.numeric_value)
            if self.variant == 10:
                reject_fields("text_value", "reserved_value")
                if self.reserved_value != 0 or self.text_value is None:
                    raise PacketShapeError(
                        "server opcode-49 variant 10 requires reserved zero and text"
                    )
                if self.opaque_tail:
                    raise PacketShapeError(
                        "server opcode-49 variant 10 has no opaque tail"
                    )
                return header + bytes((self.reserved_value,)) + encode_utf16_string(
                    self.text_value, trailing_byte=True
                )
            if self.variant == 12:
                reject_fields("key", "text_value")
                if self.key is None or self.text_value is None:
                    raise PacketShapeError(
                        "server opcode-49 variant 12 requires key and text"
                    )
                if self.opaque_tail:
                    raise PacketShapeError(
                        "server opcode-49 variant 12 has no opaque tail"
                    )
                return header + struct.pack("<I", self.key) + encode_utf16_string(
                    self.text_value, trailing_byte=True
                )
            reject_fields()
            return header + bytes(self.opaque_tail)
        except (struct.error, TypeError, ValueError) as error:
            raise PacketShapeError(
                "server opcode-49 numeric fields must fit their unsigned widths"
            ) from error


@dataclass(frozen=True)
class PickupGainNotice:
    """Server confirmation describing the value collected from a field drop."""

    result_flag: int
    kind: int
    item_id: int | None = None
    quantity: int | None = None
    mesos_subkind: int | None = None
    mesos_amount: int | None = None
    mesos_tail: int | None = None
    special_value: int | None = None
    opcode: int = 49

    ITEM = 0
    MESOS = 1
    SPECIAL = 2
    KIND_NAMES = {ITEM: "item", MESOS: "mesos", SPECIAL: "special"}

    @classmethod
    def parse(cls, payload: bytes) -> "PickupGainNotice":
        reader = PacketReader(payload, packet_name="pickup_gain_notice")
        _expect_opcode(reader, 49)
        result_flag = reader.u8("result_flag")
        kind = reader.u8("kind")
        values: dict[str, int] = {}
        if kind == cls.ITEM:
            values["item_id"] = reader.u32("item_id")
            values["quantity"] = reader.u32("quantity")
        elif kind == cls.MESOS:
            values["mesos_subkind"] = reader.u8("mesos_subkind")
            values["mesos_amount"] = reader.u64("mesos_amount")
            values["mesos_tail"] = reader.u16("mesos_tail")
        elif kind == cls.SPECIAL:
            values["special_value"] = reader.u32("special_value")
        else:
            raise PacketShapeError(
                f"pickup_gain_notice kind {kind} is not capture-modeled"
            )
        reader.finish()
        return cls(result_flag=result_flag, kind=kind, **values)

    @property
    def kind_name(self) -> str:
        return self.KIND_NAMES[self.kind]

    def safe_dict(self) -> dict[str, int | str | None]:
        details: dict[str, int | str | None] = {
            "result_flag": self.result_flag,
            "kind": self.kind_name,
        }
        if self.kind == self.ITEM:
            details.update(item_id=self.item_id, quantity=self.quantity)
        elif self.kind == self.MESOS:
            details.update(
                mesos_subkind=self.mesos_subkind,
                mesos_amount=self.mesos_amount,
                mesos_tail=self.mesos_tail,
            )
        else:
            details["special_value"] = self.special_value
        return details

    def to_bytes(self) -> bytes:
        if not 0 <= self.result_flag <= 0xFF:
            raise PacketShapeError("pickup result flag must fit in u8")
        if self.kind not in self.KIND_NAMES:
            raise PacketShapeError(
                f"pickup notice kind {self.kind} is unsupported"
            )
        body = struct.pack("<HBB", self.opcode, self.result_flag, self.kind)
        if self.kind == self.ITEM:
            if self.item_id is None or self.quantity is None:
                raise PacketShapeError("item pickup notice requires item and quantity")
            if any(
                value is not None
                for value in (
                    self.mesos_subkind,
                    self.mesos_amount,
                    self.mesos_tail,
                    self.special_value,
                )
            ):
                raise PacketShapeError("item pickup notice has foreign fields")
            if not 0 <= self.item_id <= 0xFFFF_FFFF:
                raise PacketShapeError("pickup item id must fit in u32")
            if not 0 <= self.quantity <= 0xFFFF_FFFF:
                raise PacketShapeError("pickup item quantity must fit in u32")
            return body + struct.pack("<II", self.item_id, self.quantity)
        if self.kind == self.MESOS:
            if (
                self.mesos_subkind is None
                or self.mesos_amount is None
                or self.mesos_tail is None
            ):
                raise PacketShapeError("mesos pickup notice requires all fields")
            if (
                self.item_id is not None
                or self.quantity is not None
                or self.special_value is not None
            ):
                raise PacketShapeError("mesos pickup notice has foreign fields")
            if not 0 <= self.mesos_subkind <= 0xFF:
                raise PacketShapeError("mesos pickup subkind must fit in u8")
            if not 0 <= self.mesos_amount <= 0xFFFF_FFFF_FFFF_FFFF:
                raise PacketShapeError("mesos pickup amount must fit in u64")
            if not 0 <= self.mesos_tail <= 0xFFFF:
                raise PacketShapeError("mesos pickup tail must fit in u16")
            return body + struct.pack(
                "<BQH", self.mesos_subkind, self.mesos_amount, self.mesos_tail
            )
        if self.kind == self.SPECIAL:
            if self.special_value is None:
                raise PacketShapeError("special pickup notice requires a value")
            if any(
                value is not None
                for value in (
                    self.item_id,
                    self.quantity,
                    self.mesos_subkind,
                    self.mesos_amount,
                    self.mesos_tail,
                )
            ):
                raise PacketShapeError("special pickup notice has foreign fields")
            if not 0 <= self.special_value <= 0xFFFF_FFFF:
                raise PacketShapeError("special pickup value must fit in u32")
            return body + struct.pack("<I", self.special_value)
        raise PacketShapeError(f"pickup notice kind {self.kind} is unsupported")


@dataclass(frozen=True)
class FieldDropSpawn:
    """Server field-drop entry in an animated or field-load variant."""

    spawn_mode: int
    drop_object_id: int
    drop_kind: int
    value: int
    owner_value_1: int
    owner_value_2: int
    ownership_flag: int
    position_x: int
    position_y: int
    source_mob_object_id: int
    source_x: int | None = None
    source_y: int | None = None
    animation_duration_ms: int | None = None
    expiration_ticks: int | None = None
    final_flag: int = 0
    opcode: int = 311

    ITEM = 0
    MESOS = 1
    KIND_NAMES = {ITEM: "item", MESOS: "mesos"}
    ANIMATED_MODES = {0, 1}
    FIELD_LOAD_MODE = 2

    @classmethod
    def parse(cls, payload: bytes) -> "FieldDropSpawn":
        reader = PacketReader(payload, packet_name="field_drop_spawn")
        _expect_opcode(reader, 311)
        spawn_mode = reader.u8("spawn_mode")
        if spawn_mode not in cls.ANIMATED_MODES | {cls.FIELD_LOAD_MODE}:
            raise PacketShapeError(
                f"field_drop_spawn mode {spawn_mode} is not capture-modeled"
            )
        drop_object_id = reader.u32("drop_object_id")
        drop_kind = reader.u8("drop_kind")
        if drop_kind not in cls.KIND_NAMES:
            raise PacketShapeError(
                f"field_drop_spawn kind {drop_kind} is not capture-modeled"
            )
        value = reader.u32("value")
        owner_value_1 = reader.u32("owner_value_1")
        owner_value_2 = reader.u32("owner_value_2")
        ownership_flag = reader.u8("ownership_flag")
        position_x = reader.i16("position_x")
        position_y = reader.i16("position_y")
        source_mob_object_id = reader.u32("source_mob_object_id")
        source_x: int | None = None
        source_y: int | None = None
        animation_duration_ms: int | None = None
        if spawn_mode in cls.ANIMATED_MODES:
            source_x = reader.i16("source_x")
            source_y = reader.i16("source_y")
            animation_duration_ms = reader.u16("animation_duration_ms")
        expiration_ticks = (
            reader.i64("expiration_ticks") if drop_kind == cls.ITEM else None
        )
        final_flag = reader.u8("final_flag")
        reader.finish()
        return cls(
            spawn_mode=spawn_mode,
            drop_object_id=drop_object_id,
            drop_kind=drop_kind,
            value=value,
            owner_value_1=owner_value_1,
            owner_value_2=owner_value_2,
            ownership_flag=ownership_flag,
            position_x=position_x,
            position_y=position_y,
            source_mob_object_id=source_mob_object_id,
            source_x=source_x,
            source_y=source_y,
            animation_duration_ms=animation_duration_ms,
            expiration_ticks=expiration_ticks,
            final_flag=final_flag,
        )

    @property
    def kind_name(self) -> str:
        return self.KIND_NAMES[self.drop_kind]

    @property
    def item_id(self) -> int | None:
        return self.value if self.drop_kind == self.ITEM else None

    @property
    def mesos_amount(self) -> int | None:
        return self.value if self.drop_kind == self.MESOS else None

    @property
    def animated(self) -> bool:
        return self.spawn_mode in self.ANIMATED_MODES

    def safe_dict(self) -> dict[str, int | str | bool | None]:
        details: dict[str, int | str | bool | None] = {
            "spawn_mode": self.spawn_mode,
            "variant": "animated" if self.animated else "field_load",
            "kind": self.kind_name,
            "owner_values_equal": self.owner_value_1 == self.owner_value_2,
            "ownership_flag": self.ownership_flag,
            "position_x": self.position_x,
            "position_y": self.position_y,
            "source_mob_present": bool(self.source_mob_object_id),
            "source_x": self.source_x,
            "source_y": self.source_y,
            "animation_duration_ms": self.animation_duration_ms,
            "expiration_ticks": self.expiration_ticks,
            "final_flag": self.final_flag,
        }
        if self.drop_kind == self.ITEM:
            details["item_id"] = self.value
        else:
            details["mesos_amount"] = self.value
        return details

    def to_bytes(self) -> bytes:
        if self.spawn_mode not in self.ANIMATED_MODES | {self.FIELD_LOAD_MODE}:
            raise PacketShapeError(
                f"field-drop spawn mode {self.spawn_mode} is unsupported"
            )
        if self.drop_kind not in self.KIND_NAMES:
            raise PacketShapeError(
                f"field-drop spawn kind {self.drop_kind} is unsupported"
            )
        for name, value, maximum in (
            ("drop object id", self.drop_object_id, 0xFFFF_FFFF),
            ("value", self.value, 0xFFFF_FFFF),
            ("owner value 1", self.owner_value_1, 0xFFFF_FFFF),
            ("owner value 2", self.owner_value_2, 0xFFFF_FFFF),
            ("ownership flag", self.ownership_flag, 0xFF),
            ("source mob object id", self.source_mob_object_id, 0xFFFF_FFFF),
            ("final flag", self.final_flag, 0xFF),
        ):
            if not 0 <= value <= maximum:
                raise PacketShapeError(f"field-drop {name} is out of range")
        for name, value in (
            ("position x", self.position_x),
            ("position y", self.position_y),
        ):
            if not -0x8000 <= value <= 0x7FFF:
                raise PacketShapeError(f"field-drop {name} must fit in i16")
        body = struct.pack(
            "<HBIBIIIBhhI",
            self.opcode,
            self.spawn_mode,
            self.drop_object_id,
            self.drop_kind,
            self.value,
            self.owner_value_1,
            self.owner_value_2,
            self.ownership_flag,
            self.position_x,
            self.position_y,
            self.source_mob_object_id,
        )
        if self.animated:
            if (
                self.source_x is None
                or self.source_y is None
                or self.animation_duration_ms is None
            ):
                raise PacketShapeError(
                    "animated field-drop spawn requires source position and duration"
                )
            for name, value in (
                ("source x", self.source_x),
                ("source y", self.source_y),
            ):
                if not -0x8000 <= value <= 0x7FFF:
                    raise PacketShapeError(f"field-drop {name} must fit in i16")
            if not 0 <= self.animation_duration_ms <= 0xFFFF:
                raise PacketShapeError(
                    "field-drop animation duration must fit in u16"
                )
            body += struct.pack(
                "<hhH",
                self.source_x,
                self.source_y,
                self.animation_duration_ms,
            )
        elif any(
            value is not None
            for value in (
                self.source_x,
                self.source_y,
                self.animation_duration_ms,
            )
        ):
            raise PacketShapeError(
                "field-load drop spawn cannot carry animation fields"
            )
        if self.drop_kind == self.ITEM:
            if self.expiration_ticks is None:
                raise PacketShapeError(
                    "item field-drop spawn requires expiration ticks"
                )
            if not -(1 << 63) <= self.expiration_ticks < (1 << 63):
                raise PacketShapeError(
                    "field-drop expiration ticks must fit in i64"
                )
            body += struct.pack("<q", self.expiration_ticks)
        elif self.expiration_ticks is not None:
            raise PacketShapeError(
                "mesos field-drop spawn cannot carry expiration ticks"
            )
        return body + struct.pack("<B", self.final_flag)


@dataclass(frozen=True)
class FieldDropRemoval:
    """Server field-drop removal in one of the three capture-observed widths."""

    reason: int
    drop_object_id: int
    actor_id: int | None = None
    trailing_value: int | None = None
    opcode: int = 312

    @classmethod
    def parse(cls, payload: bytes) -> "FieldDropRemoval":
        if len(payload) not in {7, 11, 15}:
            raise PacketShapeError(
                "field_drop_removal must be exactly 7, 11, or 15 bytes"
            )
        reader = PacketReader(payload, packet_name="field_drop_removal")
        _expect_opcode(reader, 312)
        reason = reader.u8("reason")
        drop_object_id = reader.u32("drop_object_id")
        actor_id = reader.u32("actor_id") if reader.remaining else None
        trailing_value = (
            reader.u32("trailing_value") if reader.remaining else None
        )
        reader.finish()
        return cls(
            reason=reason,
            drop_object_id=drop_object_id,
            actor_id=actor_id,
            trailing_value=trailing_value,
        )

    @property
    def variant(self) -> str:
        if self.actor_id is None:
            return "drop_only"
        if self.trailing_value is None:
            return "with_actor"
        return "with_actor_and_tail"

    def safe_dict(self) -> dict[str, int | str | bool]:
        details: dict[str, int | str | bool] = {
            "reason": self.reason,
            "variant": self.variant,
            "actor_present": self.actor_id is not None,
        }
        if self.trailing_value is not None:
            details["trailing_value"] = self.trailing_value
        return details

    def to_bytes(self) -> bytes:
        for name, value, maximum in (
            ("reason", self.reason, 0xFF),
            ("drop object id", self.drop_object_id, 0xFFFF_FFFF),
        ):
            if not 0 <= value <= maximum:
                raise PacketShapeError(f"field-drop {name} is out of range")
        if self.actor_id is None:
            if self.trailing_value is not None:
                raise PacketShapeError(
                    "field-drop trailing value requires an actor id"
                )
            return struct.pack(
                "<HBI", self.opcode, self.reason, self.drop_object_id
            )
        if not 0 <= self.actor_id <= 0xFFFF_FFFF:
            raise PacketShapeError("field-drop actor id must fit in u32")
        body = struct.pack(
            "<HBII",
            self.opcode,
            self.reason,
            self.drop_object_id,
            self.actor_id,
        )
        if self.trailing_value is None:
            return body
        if not 0 <= self.trailing_value <= 0xFFFF_FFFF:
            raise PacketShapeError("field-drop trailing value must fit in u32")
        return body + struct.pack("<I", self.trailing_value)


@dataclass(frozen=True)
class ClientAttackAction:
    opcode: int
    local_object_index: int
    variant: int
    client_token: int
    control_value: int
    opaque_common_state: bytes
    value_1: int
    value_2: int
    opaque_suffix: bytes

    _SUFFIX_LENGTHS = {
        50: {1: 0, 17: 26},
        52: {1: 1, 2: 1, 17: 27, 18: 31},
    }

    @property
    def target_count(self) -> int:
        return self.variant >> 4

    @property
    def hit_count(self) -> int:
        return self.variant & 0x0F

    @property
    def target_object_id(self) -> int | None:
        if (self.opcode, self.variant) in {
            (50, 17),
            (52, 17),
            (52, 18),
        }:
            return self.value_2
        return None

    def _split_target_suffix(
        self,
    ) -> tuple[bytes, tuple[int, ...], bytes]:
        if self.target_object_id is None:
            return b"", (), self.opaque_suffix

        prefix_length = 14
        tail_length = 8 if self.opcode == 50 else 9
        expected_length = prefix_length + 4 * self.hit_count + tail_length
        if len(self.opaque_suffix) != expected_length:
            raise PacketShapeError(
                f"client opcode-{self.opcode} targeted attack variant "
                f"{self.variant} needs {expected_length} suffix bytes for "
                f"{self.hit_count} hits, got {len(self.opaque_suffix)}"
            )
        reader = PacketReader(
            self.opaque_suffix, packet_name="client_attack_target_suffix"
        )
        opaque_prefix = reader.bytes(prefix_length, "opaque_target_prefix")
        raw_damage_values = tuple(
            reader.u32(f"damage_values[{hit_index}]")
            for hit_index in range(self.hit_count)
        )
        opaque_tail = reader.bytes(tail_length, "opaque_target_tail")
        reader.finish()
        return opaque_prefix, raw_damage_values, opaque_tail

    @property
    def raw_damage_values(self) -> tuple[int, ...]:
        return self._split_target_suffix()[1]

    @property
    def damage_values(self) -> tuple[int, ...]:
        return tuple(value & 0x7FFF_FFFF for value in self.raw_damage_values)

    @property
    def high_bit_markers(self) -> tuple[bool, ...]:
        return tuple(
            bool(value & 0x8000_0000) for value in self.raw_damage_values
        )

    @classmethod
    def parse(cls, payload: bytes) -> "ClientAttackAction":
        reader = PacketReader(payload, packet_name="client_attack_action")
        opcode = reader.u16("opcode")
        suffix_lengths = cls._SUFFIX_LENGTHS.get(opcode)
        if suffix_lengths is None:
            raise PacketShapeError(
                f"client attack opcode is {opcode}, expected 50 or 52"
            )
        local_object_index = reader.u8("local_object_index")
        variant = reader.u8("variant")
        suffix_length = suffix_lengths.get(variant)
        if suffix_length is None:
            expected = ", ".join(str(value) for value in suffix_lengths)
            raise PacketShapeError(
                f"client opcode-{opcode} variant is {variant}, "
                f"expected one of {expected}"
            )
        action = cls(
            opcode=opcode,
            local_object_index=local_object_index,
            variant=variant,
            client_token=reader.u32("client_token"),
            control_value=reader.u32("control_value"),
            opaque_common_state=reader.bytes(5, "opaque_common_state"),
            value_1=reader.u32("value_1"),
            value_2=reader.u32("value_2"),
            opaque_suffix=reader.bytes(suffix_length, "opaque_suffix"),
        )
        reader.finish()
        action._split_target_suffix()
        return action

    def safe_dict(self) -> dict[str, object]:
        details: dict[str, object] = {
            "local_object_index": self.local_object_index,
            "variant": self.variant,
            "target_count": self.target_count,
            "hit_count": self.hit_count,
            "client_token_bytes": 4,
            "control_value": self.control_value,
            "opaque_common_state_bytes": len(self.opaque_common_state),
            "value_1": self.value_1,
            "has_target": self.target_object_id is not None,
            "opaque_suffix_bytes": len(self.opaque_suffix),
        }
        if self.target_object_id is None:
            details["value_2"] = self.value_2
        else:
            opaque_prefix, _, opaque_tail = self._split_target_suffix()
            details.update(
                {
                    "opaque_target_prefix_bytes": len(opaque_prefix),
                    "damage_values": list(self.damage_values),
                    "high_bit_markers": list(self.high_bit_markers),
                    "opaque_target_tail_bytes": len(opaque_tail),
                }
            )
        return details

    def to_bytes(self) -> bytes:
        suffix_lengths = self._SUFFIX_LENGTHS.get(self.opcode)
        if suffix_lengths is None:
            raise PacketShapeError(
                f"client attack opcode is {self.opcode}, expected 50 or 52"
            )
        suffix_length = suffix_lengths.get(self.variant)
        if suffix_length is None:
            expected = ", ".join(str(value) for value in suffix_lengths)
            raise PacketShapeError(
                f"client opcode-{self.opcode} variant is {self.variant}, "
                f"expected one of {expected}"
            )
        if len(self.opaque_common_state) != 5:
            raise PacketShapeError(
                "client attack common state must contain exactly 5 bytes"
            )
        if len(self.opaque_suffix) != suffix_length:
            raise PacketShapeError(
                f"client opcode-{self.opcode} variant {self.variant} suffix "
                f"needs {suffix_length} bytes, got {len(self.opaque_suffix)}"
            )
        self._split_target_suffix()
        for name, value, maximum in (
            ("local_object_index", self.local_object_index, 0xFF),
            ("client_token", self.client_token, 0xFFFF_FFFF),
            ("control_value", self.control_value, 0xFFFF_FFFF),
            ("value_1", self.value_1, 0xFFFF_FFFF),
            ("value_2", self.value_2, 0xFFFF_FFFF),
        ):
            if not 0 <= value <= maximum:
                raise PacketShapeError(
                    f"client attack {name} must fit in "
                    f"u{maximum.bit_length()}"
                )
        return (
            struct.pack(
                "<HBBII",
                self.opcode,
                self.local_object_index,
                self.variant,
                self.client_token,
                self.control_value,
            )
            + self.opaque_common_state
            + struct.pack("<II", self.value_1, self.value_2)
            + self.opaque_suffix
        )


@dataclass(frozen=True)
class ClientOpcode54AttackAction:
    control_value: int
    flag_1: int
    flag_2: int
    value_1: int
    value_2: int
    target_object_id: int
    tail_value: int
    opcode: int = 54

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode54AttackAction":
        reader = PacketReader(payload, packet_name="client_opcode_54")
        _expect_opcode(reader, 54)
        record = cls(
            control_value=reader.u32("control_value"),
            flag_1=reader.u8("flag_1"),
            flag_2=reader.u8("flag_2"),
            value_1=reader.u32("value_1"),
            value_2=reader.u32("value_2"),
            target_object_id=reader.u32("target_object_id"),
            tail_value=reader.u32("tail_value"),
        )
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, int]:
        return {
            "control_value": self.control_value,
            "flag_1": self.flag_1,
            "flag_2": self.flag_2,
            "value_1": self.value_1,
            "value_2": self.value_2,
            "tail_value": self.tail_value,
        }

    def to_bytes(self) -> bytes:
        for name, value, maximum in (
            ("control_value", self.control_value, 0xFFFF_FFFF),
            ("flag_1", self.flag_1, 0xFF),
            ("flag_2", self.flag_2, 0xFF),
            ("value_1", self.value_1, 0xFFFF_FFFF),
            ("value_2", self.value_2, 0xFFFF_FFFF),
            ("target_object_id", self.target_object_id, 0xFFFF_FFFF),
            ("tail_value", self.tail_value, 0xFFFF_FFFF),
        ):
            if not 0 <= value <= maximum:
                raise PacketShapeError(
                    f"client opcode-54 {name} must fit in "
                    f"u{maximum.bit_length()}"
                )
        return struct.pack(
            "<HIBBIIII",
            self.opcode,
            self.control_value,
            self.flag_1,
            self.flag_2,
            self.value_1,
            self.value_2,
            self.target_object_id,
            self.tail_value,
        )


@dataclass(frozen=True)
class ServerAttackRelayTarget:
    object_id: int
    hit_action: int
    raw_damage_values: tuple[int, ...]

    @property
    def damage_values(self) -> tuple[int, ...]:
        return tuple(value & 0x7FFF_FFFF for value in self.raw_damage_values)

    @property
    def high_bit_markers(self) -> tuple[bool, ...]:
        return tuple(
            bool(value & 0x8000_0000) for value in self.raw_damage_values
        )

    def safe_dict(self) -> dict[str, object]:
        return {
            "hit_action": self.hit_action,
            "damage_values": list(self.damage_values),
            "high_bit_markers": list(self.high_bit_markers),
        }


@dataclass(frozen=True)
class ServerMeleeAttackRelayMetadata:
    relay_tag: int
    skill_level: int
    unknown_value: int
    display: int
    facing_flags: int
    attack_speed: int
    mastery: int | None
    auxiliary_value: int | None
    short_zero_target_form: bool

    def safe_dict(self) -> dict[str, int | bool | None]:
        return {
            "relay_tag": self.relay_tag,
            "skill_level": self.skill_level,
            "unknown_value": self.unknown_value,
            "display": self.display,
            "facing_flags": self.facing_flags,
            "attack_speed": self.attack_speed,
            "mastery": self.mastery,
            "auxiliary_value": self.auxiliary_value,
            "short_zero_target_form": self.short_zero_target_form,
        }


@dataclass(frozen=True)
class ServerRangedAttackRelayMetadata:
    relay_tag: int
    skill_level: int
    skill_id: int | None
    unknown_value: int
    display: int
    facing_flags: int
    attack_speed: int
    mastery: int
    projectile_id: int
    position_x: int
    position_y: int

    def safe_dict(self) -> dict[str, int | None]:
        return {
            "relay_tag": self.relay_tag,
            "skill_level": self.skill_level,
            "skill_id": self.skill_id,
            "unknown_value": self.unknown_value,
            "display": self.display,
            "facing_flags": self.facing_flags,
            "attack_speed": self.attack_speed,
            "mastery": self.mastery,
            "projectile_id": self.projectile_id,
            "position_x": self.position_x,
            "position_y": self.position_y,
        }


@dataclass(frozen=True)
class ServerAttackRelay:
    object_id: int
    packed_counts: int
    opaque_body: bytes
    opcode: int

    _TOTAL_LENGTHS = {
        218: {18, 22, 27},
        219: {22, 26, 31, 35, 39, 44, 53, 62},
    }

    @property
    def target_count(self) -> int:
        return self.packed_counts >> 4

    @property
    def hit_count(self) -> int:
        return self.packed_counts & 0x0F

    def _split_body(
        self,
    ) -> tuple[bytes, tuple[ServerAttackRelayTarget, ...], bytes]:
        tail_length = 4 if self.opcode == 219 else 0
        target_record_length = 5 + 4 * self.hit_count
        prefix_length = (
            len(self.opaque_body)
            - tail_length
            - self.target_count * target_record_length
        )
        expected_prefix_lengths = {218: {6, 11}, 219: {11, 15}}.get(
            self.opcode
        )
        if expected_prefix_lengths is None:
            raise PacketShapeError(
                f"server attack relay opcode is {self.opcode}, "
                "expected 218 or 219"
            )
        if prefix_length not in expected_prefix_lengths:
            expected = ", ".join(
                str(value) for value in sorted(expected_prefix_lengths)
            )
            raise PacketShapeError(
                f"server opcode-{self.opcode} attack relay packed counts "
                f"0x{self.packed_counts:02x} imply a {prefix_length}-byte "
                f"prefix, expected one of {expected}"
            )

        reader = PacketReader(
            self.opaque_body, packet_name="server_attack_relay_body"
        )
        opaque_prefix = reader.bytes(prefix_length, "opaque_prefix")
        targets: list[ServerAttackRelayTarget] = []
        for target_index in range(self.target_count):
            targets.append(
                ServerAttackRelayTarget(
                    object_id=reader.u32(f"targets[{target_index}].object_id"),
                    hit_action=reader.u8(f"targets[{target_index}].hit_action"),
                    raw_damage_values=tuple(
                        reader.u32(
                            f"targets[{target_index}].damage_values[{hit_index}]"
                        )
                        for hit_index in range(self.hit_count)
                    ),
                )
            )
        opaque_tail = reader.bytes(tail_length, "opaque_tail")
        reader.finish()
        return opaque_prefix, tuple(targets), opaque_tail

    @property
    def opaque_prefix(self) -> bytes:
        return self._split_body()[0]

    @property
    def targets(self) -> tuple[ServerAttackRelayTarget, ...]:
        return self._split_body()[1]

    @property
    def opaque_tail(self) -> bytes:
        return self._split_body()[2]

    @property
    def melee_metadata(self) -> ServerMeleeAttackRelayMetadata | None:
        if self.opcode != 218:
            return None
        opaque_prefix, targets, _ = self._split_body()
        reader = PacketReader(
            opaque_prefix, packet_name="server_melee_attack_relay_prefix"
        )
        relay_tag = reader.u8("relay_tag")
        skill_level = reader.u8("skill_level")
        if skill_level != 0:
            raise PacketShapeError(
                "server opcode-218 attack relay skill level is "
                f"{skill_level}, expected captured value 0"
            )
        unknown_value = reader.u8("unknown_value")
        display = reader.u8("display")
        facing_flags = reader.u8("facing_flags")
        attack_speed = reader.u8("attack_speed")
        short_zero_target_form = len(opaque_prefix) == 6
        mastery = None
        auxiliary_value = None
        if short_zero_target_form:
            zero_target = targets[0] if len(targets) == 1 else None
            if not (
                self.target_count == 1
                and self.hit_count == 1
                and zero_target is not None
                and zero_target.object_id == 0
                and zero_target.hit_action == 0
                and zero_target.raw_damage_values == (0,)
            ):
                raise PacketShapeError(
                    "server opcode-218 short attack relay requires exactly "
                    "one all-zero target with one zero damage value"
                )
        else:
            mastery = reader.u8("mastery")
            auxiliary_value = reader.u32("auxiliary_value")
        reader.finish()
        return ServerMeleeAttackRelayMetadata(
            relay_tag=relay_tag,
            skill_level=skill_level,
            unknown_value=unknown_value,
            display=display,
            facing_flags=facing_flags,
            attack_speed=attack_speed,
            mastery=mastery,
            auxiliary_value=auxiliary_value,
            short_zero_target_form=short_zero_target_form,
        )

    @property
    def ranged_metadata(self) -> ServerRangedAttackRelayMetadata | None:
        if self.opcode != 219:
            return None
        opaque_prefix, _, opaque_tail = self._split_body()
        reader = PacketReader(
            opaque_prefix, packet_name="server_ranged_attack_relay_prefix"
        )
        relay_tag = reader.u8("relay_tag")
        skill_level = reader.u8("skill_level")
        expected_prefix_length = 15 if skill_level else 11
        if len(opaque_prefix) != expected_prefix_length:
            raise PacketShapeError(
                "server opcode-219 attack relay skill level "
                f"{skill_level} requires a {expected_prefix_length}-byte "
                f"prefix, got {len(opaque_prefix)}"
            )
        skill_id = reader.u32("skill_id") if skill_level else None
        unknown_value = reader.u8("unknown_value")
        display = reader.u8("display")
        facing_flags = reader.u8("facing_flags")
        attack_speed = reader.u8("attack_speed")
        mastery = reader.u8("mastery")
        projectile_id = reader.u32("projectile_id")
        reader.finish()
        position_reader = PacketReader(
            opaque_tail, packet_name="server_ranged_attack_relay_position"
        )
        position_x = position_reader.i16("x")
        position_y = position_reader.i16("y")
        position_reader.finish()
        return ServerRangedAttackRelayMetadata(
            relay_tag=relay_tag,
            skill_level=skill_level,
            skill_id=skill_id,
            unknown_value=unknown_value,
            display=display,
            facing_flags=facing_flags,
            attack_speed=attack_speed,
            mastery=mastery,
            projectile_id=projectile_id,
            position_x=position_x,
            position_y=position_y,
        )

    @classmethod
    def parse(cls, payload: bytes) -> "ServerAttackRelay":
        reader = PacketReader(payload, packet_name="server_attack_relay")
        opcode = reader.u16("opcode")
        total_lengths = cls._TOTAL_LENGTHS.get(opcode)
        if total_lengths is None:
            raise PacketShapeError(
                f"server attack relay opcode is {opcode}, expected 218 or 219"
            )
        if len(payload) not in total_lengths:
            expected = ", ".join(str(value) for value in sorted(total_lengths))
            raise PacketShapeError(
                f"server opcode-{opcode} attack relay has {len(payload)} bytes, "
                f"expected one of {expected}"
            )
        relay = cls(
            opcode=opcode,
            object_id=reader.u32("object_id"),
            packed_counts=reader.u8("packed_counts"),
            opaque_body=reader.bytes(reader.remaining, "opaque_body"),
        )
        reader.finish()
        relay._split_body()
        _ = relay.melee_metadata
        _ = relay.ranged_metadata
        return relay

    def safe_dict(self) -> dict[str, object]:
        opaque_prefix, targets, opaque_tail = self._split_body()
        details: dict[str, object] = {
            "target_count": self.target_count,
            "hit_count": self.hit_count,
            "opaque_body_bytes": len(self.opaque_body),
            "opaque_prefix_bytes": len(opaque_prefix),
            "target_records": len(targets),
            "damage_values": sum(
                len(target.raw_damage_values) for target in targets
            ),
            "high_bit_markers": sum(
                sum(target.high_bit_markers) for target in targets
            ),
            "opaque_tail_bytes": len(opaque_tail),
        }
        attack_metadata = self.melee_metadata or self.ranged_metadata
        if attack_metadata is not None:
            details.update(attack_metadata.safe_dict())
        return details

    def to_bytes(self) -> bytes:
        total_lengths = self._TOTAL_LENGTHS.get(self.opcode)
        if total_lengths is None:
            raise PacketShapeError(
                f"server attack relay opcode is {self.opcode}, "
                "expected 218 or 219"
            )
        total_length = 7 + len(self.opaque_body)
        if total_length not in total_lengths:
            expected = ", ".join(str(value) for value in sorted(total_lengths))
            raise PacketShapeError(
                f"server opcode-{self.opcode} attack relay has {total_length} "
                f"bytes, expected one of {expected}"
            )
        for name, value, maximum in (
            ("object_id", self.object_id, 0xFFFF_FFFF),
            ("packed_counts", self.packed_counts, 0xFF),
        ):
            if not 0 <= value <= maximum:
                raise PacketShapeError(
                    f"server attack relay {name} must fit in "
                    f"u{maximum.bit_length()}"
                )
        self._split_body()
        _ = self.melee_metadata
        _ = self.ranged_metadata
        return (
            struct.pack("<HIB", self.opcode, self.object_id, self.packed_counts)
            + self.opaque_body
        )


@dataclass(frozen=True)
class SkillLevelChangeRequest:
    client_tick: int
    skill_id: int
    opcode: int = 103

    @classmethod
    def parse(cls, payload: bytes) -> "SkillLevelChangeRequest":
        reader = PacketReader(payload, packet_name="skill_level_change_request")
        _expect_opcode(reader, 103)
        request = cls(
            client_tick=reader.u32("client_tick"),
            skill_id=reader.u32("skill_id"),
        )
        reader.finish()
        return request

    def safe_dict(self) -> dict[str, int]:
        return {
            "client_tick": self.client_tick,
            "skill_id": self.skill_id,
        }

    def to_bytes(self) -> bytes:
        try:
            return struct.pack("<HII", self.opcode, self.client_tick, self.skill_id)
        except struct.error as error:
            raise PacketShapeError(
                f"skill level change request field is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ClientSkillUseRequest:
    client_tick: int
    skill_id: int
    skill_level: int
    trailing_value: int
    opcode: int = 104

    @classmethod
    def parse(cls, payload: bytes) -> "ClientSkillUseRequest":
        reader = PacketReader(payload, packet_name="client_skill_use_request")
        _expect_opcode(reader, 104)
        request = cls(
            client_tick=reader.u32("client_tick"),
            skill_id=reader.u32("skill_id"),
            skill_level=reader.u8("skill_level"),
            trailing_value=reader.u16("trailing_value"),
        )
        reader.finish()
        return request

    def safe_dict(self) -> dict[str, int]:
        return {
            "client_tick": self.client_tick,
            "skill_id": self.skill_id,
            "skill_level": self.skill_level,
            "trailing_value": self.trailing_value,
        }

    def to_bytes(self) -> bytes:
        for name, value, maximum in (
            ("client_tick", self.client_tick, 0xFFFF_FFFF),
            ("skill_id", self.skill_id, 0xFFFF_FFFF),
            ("skill_level", self.skill_level, 0xFF),
            ("trailing_value", self.trailing_value, 0xFFFF),
        ):
            if not 0 <= value <= maximum:
                raise PacketShapeError(
                    f"client skill-use {name} must fit in "
                    f"u{maximum.bit_length()}"
                )
        return struct.pack(
            "<HIIBH",
            self.opcode,
            self.client_tick,
            self.skill_id,
            self.skill_level,
            self.trailing_value,
        )


@dataclass(frozen=True)
class ClientOpcode43Envelope:
    """Capture-bounded neutral envelopes for client opcode 43."""

    sequence: int
    opaque_identifier: int | None = field(default=None, repr=False)
    opaque_text: str | None = field(default=None, repr=False)
    opaque_tail: bytes = field(default=b"", repr=False)
    opaque_compact_body: bytes = field(default=b"", repr=False)
    opcode: int = 43

    @property
    def variant(self) -> str:
        return "compact" if self.opaque_identifier is None else "identified_text"

    @property
    def text_code_units(self) -> int:
        if self.opaque_text is None:
            return 0
        return len(self.opaque_text.encode("utf-16-le")) // 2

    @property
    def opaque_byte_count(self) -> int:
        return len(self.opaque_compact_body) + len(self.opaque_tail)

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode43Envelope":
        reader = PacketReader(payload, packet_name="client_opcode_43")
        _expect_opcode(reader, 43)
        sequence = reader.u8("sequence")
        if reader.remaining == 9:
            opaque_compact_body = reader.bytes(9, "opaque_compact_body")
            reader.finish()
            return cls(
                sequence=sequence,
                opaque_compact_body=opaque_compact_body,
            )

        opaque_identifier = reader.u32("opaque_identifier")
        opaque_text = reader.utf16_string("opaque_text", trailing_byte=True)
        opaque_tail = reader.bytes(6, "opaque_tail")
        reader.finish()
        return cls(
            sequence=sequence,
            opaque_identifier=opaque_identifier,
            opaque_text=opaque_text,
            opaque_tail=opaque_tail,
        )

    def safe_dict(self) -> dict[str, int | bool | str]:
        return {
            "sequence": self.sequence,
            "variant": self.variant,
            "identifier_present": self.opaque_identifier is not None,
            "text_code_units": self.text_code_units,
            "text_redacted": self.opaque_text is not None,
            "opaque_bytes": self.opaque_byte_count,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 43:
            raise PacketShapeError("client opcode-43 envelope opcode must be 43")
        if not 0 <= self.sequence <= 0xFF:
            raise PacketShapeError("client opcode-43 sequence must fit in u8")

        prefix = struct.pack("<HB", self.opcode, self.sequence)
        if self.opaque_identifier is None:
            if self.opaque_text is not None or self.opaque_tail:
                raise PacketShapeError(
                    "client opcode-43 compact envelope cannot contain text "
                    "or a tail"
                )
            if len(self.opaque_compact_body) != 9:
                raise PacketShapeError(
                    "client opcode-43 compact envelope needs 9 opaque bytes"
                )
            return prefix + self.opaque_compact_body

        if not 0 <= self.opaque_identifier <= 0xFFFF_FFFF:
            raise PacketShapeError(
                "client opcode-43 identifier must fit in u32"
            )
        if self.opaque_text is None:
            raise PacketShapeError(
                "client opcode-43 identified-text envelope needs text"
            )
        if len(self.opaque_tail) != 6:
            raise PacketShapeError(
                "client opcode-43 identified-text envelope needs a "
                "6-byte tail"
            )
        if self.opaque_compact_body:
            raise PacketShapeError(
                "client opcode-43 identified-text envelope cannot contain "
                "a compact body"
            )
        return (
            prefix
            + struct.pack("<I", self.opaque_identifier)
            + encode_utf16_string(self.opaque_text, trailing_byte=True)
            + self.opaque_tail
        )


@dataclass(frozen=True)
class ServerOpcode43Envelope:
    """Capture-bounded neutral fixed server response for opcode 43."""

    message_type: int
    opaque_body: bytes = field(repr=False)
    opcode: int = 43

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode43Envelope":
        reader = PacketReader(payload, packet_name="server_opcode_43")
        _expect_opcode(reader, 43)
        envelope = cls(
            message_type=reader.u8("message_type"),
            opaque_body=reader.bytes(16, "opaque_body"),
        )
        reader.finish()
        return envelope

    def safe_dict(self) -> dict[str, int]:
        return {
            "message_type": self.message_type,
            "opaque_bytes": len(self.opaque_body),
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 43:
            raise PacketShapeError("server opcode-43 envelope opcode must be 43")
        if not 0 <= self.message_type <= 0xFF:
            raise PacketShapeError("server opcode-43 message type must fit in u8")
        if len(self.opaque_body) != 16:
            raise PacketShapeError(
                "server opcode-43 envelope needs a 16-byte opaque body"
            )
        return struct.pack("<HB", self.opcode, self.message_type) + self.opaque_body


@dataclass(frozen=True)
class ClientNpcInteractionRequest:
    """Request to interact with one active field NPC at the player position."""

    npc_object_id: int
    position_x: int
    position_y: int
    opcode: int = 64

    @classmethod
    def parse(cls, payload: bytes) -> "ClientNpcInteractionRequest":
        reader = PacketReader(payload, packet_name="npc_interaction_request")
        _expect_opcode(reader, 64)
        request = cls(
            npc_object_id=reader.u32("npc_object_id"),
            position_x=reader.i16("position_x"),
            position_y=reader.i16("position_y"),
        )
        reader.finish()
        return request

    def safe_dict(self) -> dict[str, int]:
        return {
            "npc_object_id": self.npc_object_id,
            "position_x": self.position_x,
            "position_y": self.position_y,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 64:
            raise PacketShapeError("NPC interaction request opcode must be 64")
        if not 0 <= self.npc_object_id <= 0xFFFF_FFFF:
            raise PacketShapeError(
                "NPC interaction request object id must fit in u32"
            )
        for name, value in (
            ("position x", self.position_x),
            ("position y", self.position_y),
        ):
            if not -0x8000 <= value <= 0x7FFF:
                raise PacketShapeError(
                    f"client opcode-64 {name} must fit in i16"
                )
        return struct.pack(
            "<HIhh",
            self.opcode,
            self.npc_object_id,
            self.position_x,
            self.position_y,
        )


@dataclass(frozen=True)
class ClientOpcode111CashSlotAction:
    """Capture-bounded client action correlated with a Cash-slot update."""

    neutral_value: int
    slot: int
    opcode: int = 111

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode111CashSlotAction":
        reader = PacketReader(
            payload, packet_name="client_opcode_111_cash_slot_action"
        )
        _expect_opcode(reader, 111)
        action = cls(
            neutral_value=reader.u32("neutral_value"),
            slot=reader.i16("slot"),
        )
        reader.finish()
        return action

    def safe_dict(self) -> dict[str, int | str]:
        return {
            "neutral_value": self.neutral_value,
            "inventory": "cash",
            "slot": self.slot,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 111:
            raise PacketShapeError("client Cash-slot action opcode must be 111")
        if not 0 <= self.neutral_value <= 0xFFFF_FFFF:
            raise PacketShapeError(
                "client opcode-111 neutral value must fit in u32"
            )
        if not -0x8000 <= self.slot <= 0x7FFF:
            raise PacketShapeError("client opcode-111 slot must fit in i16")
        return struct.pack("<HIh", self.opcode, self.neutral_value, self.slot)


@dataclass(frozen=True)
class ClientOpcode66Acknowledgement:
    """Capture-bounded acknowledgement for server opcode 348."""

    selector: int
    status_value: int
    optional_value: int | None = field(default=None, repr=False)
    opcode: int = 66

    _CAPTURED_SHORT_PAIRS = frozenset(
        {
            (0, 1),
            (0, 0xFF),
            (3, 1),
            (6, 0),
            (17, 1),
        }
    )
    _CAPTURED_VALUE_PAIR = (6, 1)

    @property
    def shape(self) -> str:
        suffix = "value" if self.optional_value is not None else "short"
        return f"selector={self.selector}:status={self.status_value}:{suffix}"

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode66Acknowledgement":
        reader = PacketReader(payload, packet_name="client_opcode_66")
        _expect_opcode(reader, 66)
        selector = reader.u8("selector")
        status_value = reader.u8("status_value")
        pair = (selector, status_value)
        if reader.remaining == 0:
            if pair not in cls._CAPTURED_SHORT_PAIRS:
                raise PacketShapeError(
                    "client opcode-66 selector/status pair is not a captured "
                    f"short shape: {selector}/{status_value}"
                )
            return cls(selector=selector, status_value=status_value)
        if pair != cls._CAPTURED_VALUE_PAIR or reader.remaining != 4:
            raise PacketShapeError(
                "client opcode-66 optional-value shape requires selector 6, "
                "status 1, and one u32"
            )
        optional_value = reader.u32("optional_value")
        reader.finish()
        return cls(
            selector=selector,
            status_value=status_value,
            optional_value=optional_value,
        )

    def safe_dict(self) -> dict[str, int | bool | str]:
        return {
            "selector": self.selector,
            "status_value": self.status_value,
            "shape": self.shape,
            "optional_value_present": self.optional_value is not None,
            "optional_value_redacted": self.optional_value is not None,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 66:
            raise PacketShapeError(
                "client opcode-66 acknowledgement opcode must be 66"
            )
        pair = (self.selector, self.status_value)
        try:
            prefix = struct.pack("<HBB", self.opcode, *pair)
        except struct.error as error:
            raise PacketShapeError(
                f"client opcode-66 selector/status is out of range: {error}"
            ) from error
        if self.optional_value is None:
            if pair not in self._CAPTURED_SHORT_PAIRS:
                raise PacketShapeError(
                    "client opcode-66 selector/status pair is not a captured "
                    f"short shape: {self.selector}/{self.status_value}"
                )
            return prefix
        if pair != self._CAPTURED_VALUE_PAIR:
            raise PacketShapeError(
                "client opcode-66 optional value requires selector 6 and "
                "status 1"
            )
        if not 0 <= self.optional_value <= 0xFFFF_FFFF:
            raise PacketShapeError(
                "client opcode-66 optional value must fit in u32"
            )
        return prefix + struct.pack("<I", self.optional_value)


@dataclass(frozen=True)
class ClientOpcode114TextEnvelope:
    """Capture-bounded redacted text envelope for client opcode 114."""

    control_value: int
    opaque_text: str = field(repr=False)
    opaque_value: int = field(repr=False)
    opcode: int = 114

    @property
    def text_code_units(self) -> int:
        return len(self.opaque_text.encode("utf-16-le")) // 2

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode114TextEnvelope":
        reader = PacketReader(payload, packet_name="client_opcode_114")
        _expect_opcode(reader, 114)
        envelope = cls(
            control_value=reader.u8("control_value"),
            opaque_text=reader.utf16_string(
                "opaque_text", trailing_byte=True
            ),
            opaque_value=reader.u32("opaque_value"),
        )
        reader.finish()
        return envelope

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "control_value": self.control_value,
            "text_code_units": self.text_code_units,
            "text_redacted": True,
            "opaque_value_redacted": True,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 114:
            raise PacketShapeError(
                "client opcode-114 envelope opcode must be 114"
            )
        if not 0 <= self.control_value <= 0xFF:
            raise PacketShapeError(
                "client opcode-114 control value must fit in u8"
            )
        if not 0 <= self.opaque_value <= 0xFFFF_FFFF:
            raise PacketShapeError(
                "client opcode-114 opaque value must fit in u32"
            )
        return (
            struct.pack("<HB", self.opcode, self.control_value)
            + encode_utf16_string(self.opaque_text, trailing_byte=True)
            + struct.pack("<I", self.opaque_value)
        )


@dataclass(frozen=True)
class ClientInnerPortalRequest:
    """Capture-backed same-field portal traversal request."""

    field_epoch: int
    portal_name: str = field(repr=False)
    source_x: int
    source_y: int
    destination_x: int
    destination_y: int
    opcode: int = 115

    @property
    def portal_name_code_units(self) -> int:
        return len(self.portal_name.encode("utf-16-le")) // 2

    @classmethod
    def parse(cls, payload: bytes) -> "ClientInnerPortalRequest":
        reader = PacketReader(payload, packet_name="client_inner_portal_request")
        _expect_opcode(reader, 115)
        request = cls(
            field_epoch=reader.u8("field_epoch"),
            portal_name=reader.utf16_string(
                "portal_name", trailing_byte=True
            ),
            source_x=reader.i16("source_x"),
            source_y=reader.i16("source_y"),
            destination_x=reader.i16("destination_x"),
            destination_y=reader.i16("destination_y"),
        )
        reader.finish()
        return request

    def safe_dict(self) -> dict[str, object]:
        return {
            "field_epoch": self.field_epoch,
            "portal_name_code_units": self.portal_name_code_units,
            "portal_name_redacted": True,
            "source": {"x": self.source_x, "y": self.source_y},
            "destination": {
                "x": self.destination_x,
                "y": self.destination_y,
            },
            "delta": {
                "x": self.destination_x - self.source_x,
                "y": self.destination_y - self.source_y,
            },
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 115:
            raise PacketShapeError(
                "client inner-portal request opcode must be 115"
            )
        if not 0 <= self.field_epoch <= 0xFF:
            raise PacketShapeError(
                "client inner-portal field epoch must fit in u8"
            )
        for name, value in (
            ("source x", self.source_x),
            ("source y", self.source_y),
            ("destination x", self.destination_x),
            ("destination y", self.destination_y),
        ):
            if not -0x8000 <= value <= 0x7FFF:
                raise PacketShapeError(
                    f"client inner-portal {name} must fit in i16"
                )
        return (
            struct.pack("<HB", self.opcode, self.field_epoch)
            + encode_utf16_string(self.portal_name, trailing_byte=True)
            + struct.pack(
                "<hhhh",
                self.source_x,
                self.source_y,
                self.destination_x,
                self.destination_y,
            )
        )


@dataclass(frozen=True)
class ClientRecoveryRequest:
    """Natural HP or MP recovery request with one non-zero amount."""

    hp_recovery: int
    mp_recovery: int
    opcode: int = 101
    REQUEST_TYPE = 20

    @classmethod
    def parse(cls, payload: bytes) -> "ClientRecoveryRequest":
        reader = PacketReader(payload, packet_name="client_recovery_request")
        _expect_opcode(reader, 101)
        if reader.u8("reserved_prefix") != 0:
            raise PacketShapeError(
                "client recovery request reserved prefix must be zero"
            )
        request_type = reader.u8("request_type")
        if request_type != cls.REQUEST_TYPE:
            raise PacketShapeError(
                "client recovery request type must be 20"
            )
        if reader.u16("reserved_value") != 0:
            raise PacketShapeError(
                "client recovery request reserved u16 must be zero"
            )
        request = cls(
            hp_recovery=reader.u16("hp_recovery"),
            mp_recovery=reader.u16("mp_recovery"),
        )
        if reader.u8("reserved_tail") != 0:
            raise PacketShapeError(
                "client recovery request reserved tail must be zero"
            )
        reader.finish()
        request._validate()
        return request

    @property
    def stat_name(self) -> str:
        return "current_hp" if self.hp_recovery else "current_mp"

    @property
    def recovery_amount(self) -> int:
        return self.hp_recovery or self.mp_recovery

    def safe_dict(self) -> dict[str, int | str]:
        return {
            "stat": self.stat_name,
            "amount": self.recovery_amount,
            "hp_recovery": self.hp_recovery,
            "mp_recovery": self.mp_recovery,
        }

    def _validate(self) -> None:
        if self.opcode != 101:
            raise PacketShapeError(
                "client recovery request opcode must be 101"
            )
        for name, value in (
            ("HP recovery", self.hp_recovery),
            ("MP recovery", self.mp_recovery),
        ):
            if not 0 <= value <= 0xFFFF:
                raise PacketShapeError(
                    f"client recovery request {name} must fit in u16"
                )
        if (self.hp_recovery > 0) == (self.mp_recovery > 0):
            raise PacketShapeError(
                "client recovery request needs exactly one non-zero amount"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        return struct.pack(
            "<HBBHHHB",
            self.opcode,
            0,
            self.REQUEST_TYPE,
            0,
            self.hp_recovery,
            self.mp_recovery,
            0,
        )


@dataclass(frozen=True)
class ClientOpcode122Envelope:
    """Capture-bounded selector/word variants of client opcode 122."""

    selector: int
    opaque_values: tuple[int, ...] = field(default=(), repr=False)
    opcode: int = 122

    _CAPTURED_VALUE_COUNTS = {
        1: frozenset({2, 3}),
        2: frozenset({3, 4}),
        4: frozenset({3}),
        5: frozenset({3}),
    }
    _TERMINAL_SENTINEL_SELECTOR = 2
    _TERMINAL_SENTINEL = 0xFFFF_FFFF

    @classmethod
    def is_captured_shape(cls, payload: bytes) -> bool:
        if len(payload) < 3 or len(payload) % 4 != 3:
            return False
        opcode, selector = struct.unpack_from("<HB", payload)
        if opcode != 122:
            return False
        value_count = (len(payload) - 3) // 4
        return value_count in cls._CAPTURED_VALUE_COUNTS.get(
            selector, frozenset()
        )

    @property
    def value_count(self) -> int:
        return len(self.opaque_values)

    @property
    def terminal_sentinel_present(self) -> bool:
        return (
            self.selector == self._TERMINAL_SENTINEL_SELECTOR
            and bool(self.opaque_values)
            and self.opaque_values[-1] == self._TERMINAL_SENTINEL
        )

    @property
    def shape(self) -> str:
        return f"selector={self.selector}:values={self.value_count}"

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode122Envelope":
        reader = PacketReader(payload, packet_name="client_opcode_122_envelope")
        _expect_opcode(reader, 122)
        selector = reader.u8("selector")
        if reader.remaining % 4:
            raise PacketShapeError(
                "client opcode-122 body must contain complete u32 values"
            )
        value_count = reader.remaining // 4
        captured_counts = cls._CAPTURED_VALUE_COUNTS.get(selector)
        if captured_counts is None or value_count not in captured_counts:
            raise PacketShapeError(
                "client opcode-122 selector/value count is not a captured "
                f"shape: selector {selector}, values {value_count}"
            )
        values = tuple(
            reader.u32(f"opaque_values[{index}]")
            for index in range(value_count)
        )
        reader.finish()
        envelope = cls(selector=selector, opaque_values=values)
        if (
            selector == cls._TERMINAL_SENTINEL_SELECTOR
            and not envelope.terminal_sentinel_present
        ):
            raise PacketShapeError(
                "client opcode-122 selector 2 requires terminal 0xffffffff"
            )
        return envelope

    def safe_dict(self) -> dict[str, int | bool | str]:
        return {
            "selector": self.selector,
            "value_count": self.value_count,
            "shape": self.shape,
            "values_redacted": bool(self.opaque_values),
            "terminal_sentinel_present": self.terminal_sentinel_present,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 122:
            raise PacketShapeError("client opcode-122 envelope opcode must be 122")
        captured_counts = self._CAPTURED_VALUE_COUNTS.get(self.selector)
        if captured_counts is None or self.value_count not in captured_counts:
            raise PacketShapeError(
                "client opcode-122 selector/value count is not a captured "
                f"shape: selector {self.selector}, values {self.value_count}"
            )
        if (
            self.selector == self._TERMINAL_SENTINEL_SELECTOR
            and not self.terminal_sentinel_present
        ):
            raise PacketShapeError(
                "client opcode-122 selector 2 requires terminal 0xffffffff"
            )
        try:
            return struct.pack(
                f"<HB{self.value_count}I",
                self.opcode,
                self.selector,
                *self.opaque_values,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"client opcode-122 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ClientOpcode217RecordSet:
    opaque_prefix: bytes
    record_format: int | None = None
    records: tuple[bytes, ...] = ()
    opaque_trailer: bytes = b""
    opcode: int = 217

    _RECORD_LENGTHS = {0: 14, 2: 11}

    @property
    def variant(self) -> str:
        return "compact" if self.record_format is None else "record_set"

    @property
    def record_count(self) -> int:
        return len(self.records)

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode217RecordSet":
        reader = PacketReader(payload, packet_name="client_opcode_217")
        _expect_opcode(reader, 217)
        if reader.remaining == 6:
            opaque_prefix = reader.bytes(6, "opaque_compact_body")
            reader.finish()
            return cls(opaque_prefix=opaque_prefix)

        opaque_prefix = reader.bytes(10, "opaque_prefix")
        record_count = reader.u8("record_count")
        if record_count == 0:
            raise PacketShapeError(
                "client_opcode_217.record_count is zero, expected 1..255"
            )
        record_format = reader.u8("record_format")
        record_length = cls._RECORD_LENGTHS.get(record_format)
        if record_length is None:
            expected = ", ".join(str(value) for value in cls._RECORD_LENGTHS)
            raise PacketShapeError(
                f"client_opcode_217.record_format is {record_format}, "
                f"expected one of {expected}"
            )
        records = tuple(
            reader.bytes(record_length, f"records[{index}]")
            for index in range(record_count)
        )
        opaque_trailer = reader.bytes(8, "opaque_trailer")
        reader.finish()
        return cls(
            opaque_prefix=opaque_prefix,
            record_format=record_format,
            records=records,
            opaque_trailer=opaque_trailer,
        )

    def safe_dict(self) -> dict[str, object]:
        details: dict[str, object] = {
            "variant": self.variant,
            "opaque_prefix_bytes": len(self.opaque_prefix),
        }
        if self.record_format is not None:
            details.update(
                {
                    "record_count": self.record_count,
                    "record_format": self.record_format,
                    "record_bytes": self._RECORD_LENGTHS[self.record_format],
                    "opaque_trailer_bytes": len(self.opaque_trailer),
                }
            )
        return details

    def to_bytes(self) -> bytes:
        if self.record_format is None:
            if len(self.opaque_prefix) != 6:
                raise PacketShapeError(
                    "client opcode-217 compact variant needs 6 opaque bytes"
                )
            if self.records or self.opaque_trailer:
                raise PacketShapeError(
                    "client opcode-217 compact variant cannot contain records "
                    "or a trailer"
                )
            return struct.pack("<H", self.opcode) + self.opaque_prefix

        if len(self.opaque_prefix) != 10:
            raise PacketShapeError(
                "client opcode-217 record-set prefix needs 10 opaque bytes"
            )
        if not self.records:
            raise PacketShapeError(
                "client opcode-217 record set must contain a record"
            )
        if len(self.records) > 255:
            raise PacketShapeError(
                "client opcode-217 record set cannot exceed 255 records"
            )
        record_length = self._RECORD_LENGTHS.get(self.record_format)
        if record_length is None:
            expected = ", ".join(str(value) for value in self._RECORD_LENGTHS)
            raise PacketShapeError(
                f"client opcode-217 record format is {self.record_format}, "
                f"expected one of {expected}"
            )
        for index, record in enumerate(self.records):
            if len(record) != record_length:
                raise PacketShapeError(
                    f"client opcode-217 format {self.record_format} record "
                    f"{index} needs {record_length} bytes, got {len(record)}"
                )
        if len(self.opaque_trailer) != 8:
            raise PacketShapeError(
                "client opcode-217 record-set trailer needs 8 opaque bytes"
            )
        return (
            struct.pack("<H", self.opcode)
            + self.opaque_prefix
            + bytes((len(self.records), self.record_format))
            + b"".join(self.records)
            + self.opaque_trailer
        )


@dataclass(frozen=True)
class ClientOpcode225PositionedEffectAction:
    """Client action referencing a positioned-effect primary key."""

    primary_value: int = field(repr=False)
    value_1: int
    value_2: int
    trailing_value: int
    opcode: int = 225

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode225PositionedEffectAction":
        reader = PacketReader(
            payload, packet_name="client_opcode_225_positioned_effect_action"
        )
        _expect_opcode(reader, 225)
        action = cls(
            primary_value=reader.i32("primary_value"),
            value_1=reader.u32("value_1"),
            value_2=reader.u32("value_2"),
            trailing_value=reader.u16("trailing_value"),
        )
        reader.finish()
        return action

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "primary_value_redacted": True,
            "value_1": self.value_1,
            "value_2": self.value_2,
            "trailing_value": self.trailing_value,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 225:
            raise PacketShapeError(
                "client opcode-225 positioned-effect action opcode must be 225"
            )
        try:
            return struct.pack(
                "<HiIIH",
                self.opcode,
                self.primary_value,
                self.value_1,
                self.value_2,
                self.trailing_value,
            )
        except struct.error as error:
            raise PacketShapeError(
                "client opcode-225 positioned-effect action value is out of "
                f"range: {error}"
            ) from error


@dataclass(frozen=True)
class LifeMovementCommand:
    command_type: int
    opaque_payload: bytes

    _PAYLOAD_LENGTHS = {
        0: 13,
        1: 7,
        2: 7,
        3: 9,
        4: 9,
        5: 13,
        6: 7,
        7: 9,
        8: 9,
        9: 9,
        10: 1,
        11: 9,
        12: 7,
        13: 7,
        14: 9,
        15: 15,
        16: 7,
        17: 13,
        18: 7,
        19: 7,
        20: 3,
        21: 3,
        22: 7,
    }

    @classmethod
    def parse(
        cls,
        reader: PacketReader,
        *,
        command_index: int,
        field_prefix: str = "movement",
    ) -> "LifeMovementCommand":
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

    def safe_dict(self) -> dict[str, object]:
        return {
            "type": self.command_type,
            "opaque_payload_bytes": len(self.opaque_payload),
        }

    def to_bytes(self) -> bytes:
        expected_length = self._PAYLOAD_LENGTHS.get(self.command_type)
        if expected_length is None:
            expected = ", ".join(str(value) for value in self._PAYLOAD_LENGTHS)
            raise PacketShapeError(
                f"life movement command type is {self.command_type}, "
                f"expected one of {expected}"
            )
        if len(self.opaque_payload) != expected_length:
            raise PacketShapeError(
                f"life movement command type {self.command_type} needs "
                f"{expected_length} opaque bytes, got "
                f"{len(self.opaque_payload)}"
            )
        return bytes((self.command_type,)) + self.opaque_payload


@dataclass(frozen=True)
class LifeMovementPath:
    reference_x: int
    reference_y: int
    commands: tuple[LifeMovementCommand, ...]

    @classmethod
    def parse_from(
        cls, reader: PacketReader, *, field_prefix: str = "movement"
    ) -> "LifeMovementPath":
        reference_x = reader.i16(f"{field_prefix}.reference_x")
        reference_y = reader.i16(f"{field_prefix}.reference_y")
        command_count = reader.u8(f"{field_prefix}.command_count")
        if command_count == 0:
            raise PacketShapeError("life movement path has no commands")
        commands = tuple(
            LifeMovementCommand.parse(
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

    def safe_dict(self) -> dict[str, object]:
        return {
            "reference_x": self.reference_x,
            "reference_y": self.reference_y,
            "command_count": len(self.commands),
            "command_types": [
                command.command_type for command in self.commands
            ],
            "commands": [command.safe_dict() for command in self.commands],
        }

    def to_bytes(self) -> bytes:
        if not self.commands:
            raise PacketShapeError("life movement path must contain a command")
        if len(self.commands) > 255:
            raise PacketShapeError(
                "life movement path cannot contain more than 255 commands"
            )
        return (
            struct.pack(
                "<hhB", self.reference_x, self.reference_y, len(self.commands)
            )
            + b"".join(command.to_bytes() for command in self.commands)
        )


@dataclass(frozen=True)
class LifeMovementSubmission:
    local_object_index: int
    client_token: int
    control_value: int
    movement: LifeMovementPath
    tail_type: int
    opaque_tail_state: bytes
    tail_marker: int
    path_start_x: int
    path_start_y: int
    path_end_x: int
    path_end_y: int
    opcode: int = 47

    _TAIL_LENGTHS = {17: 8, 18: 8, 21: 10, 24: 11}

    @classmethod
    def parse(cls, payload: bytes) -> "LifeMovementSubmission":
        reader = PacketReader(payload, packet_name="life_movement_submission")
        _expect_opcode(reader, 47)
        local_object_index = reader.u8("local_object_index")
        client_token = reader.u32("client_token")
        control_value = reader.u32("control_value")
        movement = LifeMovementPath.parse_from(reader)
        tail_type = reader.u8("tail_type")
        tail_length = cls._TAIL_LENGTHS.get(tail_type)
        if tail_length is None:
            expected = ", ".join(str(value) for value in cls._TAIL_LENGTHS)
            raise PacketShapeError(
                f"life movement tail type is {tail_type}, expected one of "
                f"{expected}"
            )
        opaque_tail_state = reader.bytes(tail_length, "opaque_tail_state")
        tail_marker = reader.u8("tail_marker")
        path_start_x = reader.i16("path_start_x")
        path_start_y = reader.i16("path_start_y")
        path_end_x = reader.i16("path_end_x")
        path_end_y = reader.i16("path_end_y")
        reader.finish()
        return cls(
            local_object_index=local_object_index,
            client_token=client_token,
            control_value=control_value,
            movement=movement,
            tail_type=tail_type,
            opaque_tail_state=opaque_tail_state,
            tail_marker=tail_marker,
            path_start_x=path_start_x,
            path_start_y=path_start_y,
            path_end_x=path_end_x,
            path_end_y=path_end_y,
        )

    def to_bytes(self) -> bytes:
        if not 0 <= self.local_object_index <= 0xFF:
            raise PacketShapeError(
                "life movement local index must fit in one byte"
            )
        tail_length = self._TAIL_LENGTHS.get(self.tail_type)
        if tail_length is None:
            expected = ", ".join(str(value) for value in self._TAIL_LENGTHS)
            raise PacketShapeError(
                f"life movement tail type is {self.tail_type}, expected one of "
                f"{expected}"
            )
        if len(self.opaque_tail_state) != tail_length:
            raise PacketShapeError(
                f"life movement tail type {self.tail_type} needs "
                f"{tail_length} opaque bytes"
            )
        if not 0 <= self.tail_marker <= 0xFF:
            raise PacketShapeError(
                "life movement tail marker must fit in one byte"
            )
        return (
            struct.pack(
                "<HBII",
                self.opcode,
                self.local_object_index,
                self.client_token,
                self.control_value,
            )
            + self.movement.to_bytes()
            + bytes((self.tail_type,))
            + self.opaque_tail_state
            + struct.pack(
                "<Bhhhh",
                self.tail_marker,
                self.path_start_x,
                self.path_start_y,
                self.path_end_x,
                self.path_end_y,
            )
        )


@dataclass(frozen=True)
class LifeMovementBroadcast:
    object_id: int
    movement: LifeMovementPath
    opcode: int = 217

    @classmethod
    def parse(cls, payload: bytes) -> "LifeMovementBroadcast":
        reader = PacketReader(payload, packet_name="life_movement_broadcast")
        _expect_opcode(reader, 217)
        object_id = reader.u32("object_id")
        movement = LifeMovementPath.parse_from(reader)
        reader.finish()
        return cls(object_id=object_id, movement=movement)

    def to_bytes(self) -> bytes:
        return (
            struct.pack("<HI", self.opcode, self.object_id)
            + self.movement.to_bytes()
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
class RemotePlayerEnterField:
    """Opcode-189 remote-player prefix plus its version-specific body."""

    object_id: int = field(repr=False)
    level: int
    name: str = field(repr=False)
    opaque_body: bytes = field(repr=False)
    opcode: int = 189

    @classmethod
    def parse(cls, payload: bytes) -> "RemotePlayerEnterField":
        reader = PacketReader(payload, packet_name="remote_player_enter_field")
        _expect_opcode(reader, 189)
        record = cls(
            object_id=reader.u32("object_id"),
            level=reader.u8("level"),
            name=reader.utf16_string("name", trailing_byte=False),
            opaque_body=reader.bytes(reader.remaining, "opaque_body"),
        )
        reader.finish()
        record._validate()
        return record

    @property
    def name_code_units(self) -> int:
        return len(self.name.encode("utf-16-le")) // 2

    def _validate(self) -> None:
        if self.opcode != 189:
            raise PacketShapeError(
                "remote-player enter-field opcode must be 189"
            )
        if not self.opaque_body:
            raise PacketShapeError(
                "remote-player enter-field body cannot be empty"
            )

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "object_id_redacted": True,
            "level": self.level,
            "name_code_units": self.name_code_units,
            "opaque_body_length": len(self.opaque_body),
        }

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            prefix = struct.pack("<HIB", self.opcode, self.object_id, self.level)
        except struct.error as error:
            raise PacketShapeError(
                f"remote-player enter-field prefix is out of range: {error}"
            ) from error
        return (
            prefix
            + encode_utf16_string(self.name, trailing_byte=False)
            + bytes(self.opaque_body)
        )


@dataclass(frozen=True)
class RemotePlayerLeaveField:
    """Fully bounded opcode-190 remote-player removal."""

    object_id: int = field(repr=False)
    opcode: int = 190

    @classmethod
    def parse(cls, payload: bytes) -> "RemotePlayerLeaveField":
        reader = PacketReader(payload, packet_name="remote_player_leave_field")
        _expect_opcode(reader, 190)
        record = cls(object_id=reader.u32("object_id"))
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, bool]:
        return {"object_id_redacted": True}

    def to_bytes(self) -> bytes:
        if self.opcode != 190:
            raise PacketShapeError(
                "remote-player leave-field opcode must be 190"
            )
        try:
            return struct.pack("<HI", self.opcode, self.object_id)
        except struct.error as error:
            raise PacketShapeError(
                f"remote-player leave-field object id is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class RemotePlayerMobValueRecord:
    """Exact opcode-224 remote-player/mob-template value record."""

    object_id: int = field(repr=False)
    value: int
    mob_template_id: int
    flag: int
    repeated_value: int
    marker: int = 0xFF
    reserved_u16: int = 0
    opcode: int = 224

    @classmethod
    def parse(cls, payload: bytes) -> "RemotePlayerMobValueRecord":
        reader = PacketReader(
            payload, packet_name="remote_player_mob_value_record"
        )
        _expect_opcode(reader, 224)
        record = cls(
            object_id=reader.u32("object_id"),
            marker=reader.u8("marker"),
            value=reader.u32("value"),
            mob_template_id=reader.u32("mob_template_id"),
            flag=reader.u8("flag"),
            reserved_u16=reader.u16("reserved_u16"),
            repeated_value=reader.u32("repeated_value"),
        )
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode != 224:
            raise PacketShapeError(
                "remote-player mob-value record opcode must be 224"
            )
        if self.marker != 0xFF:
            raise PacketShapeError(
                "remote-player mob-value marker must be 0xff"
            )
        if self.flag not in {0, 1}:
            raise PacketShapeError(
                "remote-player mob-value flag must be zero or one"
            )
        if self.reserved_u16 != 0:
            raise PacketShapeError(
                "remote-player mob-value reserved u16 must be zero"
            )
        if self.repeated_value != self.value:
            raise PacketShapeError(
                "remote-player mob-value trailing value must repeat value"
            )

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "object_id_redacted": True,
            "marker": self.marker,
            "value": self.value,
            "mob_template_id": self.mob_template_id,
            "flag": self.flag,
            "reserved_u16": self.reserved_u16,
            "repeated_value_matches": self.repeated_value == self.value,
        }

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack(
                "<HIBIIBHI",
                self.opcode,
                self.object_id,
                self.marker,
                self.value,
                self.mob_template_id,
                self.flag,
                self.reserved_u16,
                self.repeated_value,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"remote-player mob-value field is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class TutorialUiInstruction:
    """Opcode-247 tutorial key with handler-bounded numeric controls."""

    text: str = field(repr=False)
    value_1: int
    value_2: int
    control_value: int
    extended_values: tuple[int, int] | None = None
    opcode: int = 247

    @classmethod
    def parse(cls, payload: bytes) -> "TutorialUiInstruction":
        reader = PacketReader(payload, packet_name="tutorial_ui_instruction")
        _expect_opcode(reader, 247)
        text = reader.utf16_string("text", trailing_byte=True)
        value_1 = reader.i16("value_1")
        value_2 = reader.i16("value_2")
        control_value = reader.u8("control_value")
        if reader.remaining == 0:
            extended_values = None
        elif reader.remaining == 8:
            extended_values = (
                reader.i32("extended_value_1"),
                reader.i32("extended_value_2"),
            )
        else:
            raise PacketShapeError(
                "tutorial UI instruction needs zero or eight extension bytes, "
                f"got {reader.remaining}"
            )
        reader.finish()
        return cls(
            text=text,
            value_1=value_1,
            value_2=value_2,
            control_value=control_value,
            extended_values=extended_values,
        )

    @property
    def text_code_units(self) -> int:
        return len(self.text.encode("utf-16-le")) // 2

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "text_redacted": True,
            "text_code_units": self.text_code_units,
            "value_1": self.value_1,
            "value_2": self.value_2,
            "control_value": self.control_value,
            "extended_values_present": self.extended_values is not None,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 247:
            raise PacketShapeError("tutorial UI instruction opcode must be 247")
        try:
            encoded = (
                struct.pack("<H", self.opcode)
                + encode_utf16_string(self.text, trailing_byte=True)
                + struct.pack(
                    "<hhB",
                    self.value_1,
                    self.value_2,
                    self.control_value,
                )
            )
            if self.extended_values is not None:
                encoded += struct.pack("<ii", *self.extended_values)
            return encoded
        except struct.error as error:
            raise PacketShapeError(
                f"tutorial UI instruction value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode239ValueRecord:
    """One redacted key/value member of opcode-239 selector 3."""

    key: int = field(repr=False)
    value: int


@dataclass(frozen=True)
class ServerOpcode239Envelope:
    """Capture-bounded selector variants of server opcode 239."""

    selector: int
    records: tuple[ServerOpcode239ValueRecord, ...] = field(
        default=(), repr=False
    )
    text: str | None = field(default=None, repr=False)
    trailing_value: int | None = None
    opcode: int = 239

    RECORD_SELECTOR = 3
    EMPTY_SELECTORS = frozenset({9, 13})
    TEXT_SELECTOR = 21

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode239Envelope":
        reader = PacketReader(payload, packet_name="server_opcode_239_envelope")
        _expect_opcode(reader, 239)
        selector = reader.u8("selector")
        if selector == cls.RECORD_SELECTOR:
            record_count = reader.u8("record_count")
            records = tuple(
                ServerOpcode239ValueRecord(
                    key=reader.u32(f"records[{index}].key"),
                    value=reader.i32(f"records[{index}].value"),
                )
                for index in range(record_count)
            )
            envelope = cls(selector=selector, records=records)
        elif selector in cls.EMPTY_SELECTORS:
            envelope = cls(selector=selector)
        elif selector == cls.TEXT_SELECTOR:
            envelope = cls(
                selector=selector,
                text=reader.utf16_string("text", trailing_byte=True),
                trailing_value=reader.u32("trailing_value"),
            )
        else:
            raise PacketShapeError(
                "server opcode-239 selector must be captured value "
                f"3, 9, 13, or 21, got {selector}"
            )
        reader.finish()
        return envelope

    @property
    def text_code_units(self) -> int:
        if self.text is None:
            return 0
        return len(self.text.encode("utf-16-le")) // 2

    def safe_dict(self) -> dict[str, int | bool | list[int] | None]:
        return {
            "selector": self.selector,
            "record_count": len(self.records),
            "record_keys_redacted": bool(self.records),
            "record_values": [record.value for record in self.records],
            "text_present": self.text is not None,
            "text_code_units": self.text_code_units,
            "trailing_value": self.trailing_value,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 239:
            raise PacketShapeError("server opcode-239 envelope opcode must be 239")
        try:
            encoded = struct.pack("<HB", self.opcode, self.selector)
            if self.selector == self.RECORD_SELECTOR:
                if any(
                    value is not None
                    for value in (
                        self.text,
                        self.trailing_value,
                    )
                ):
                    raise PacketShapeError(
                        "server opcode-239 selector 3 cannot include text fields"
                    )
                if len(self.records) > 0xFF:
                    raise PacketShapeError(
                        "server opcode-239 selector 3 has more than 255 records"
                    )
                encoded += struct.pack("<B", len(self.records))
                encoded += b"".join(
                    struct.pack("<Ii", record.key, record.value)
                    for record in self.records
                )
                return encoded
            if self.selector in self.EMPTY_SELECTORS:
                if self.records or any(
                    value is not None
                    for value in (
                        self.text,
                        self.trailing_value,
                    )
                ):
                    raise PacketShapeError(
                        "server opcode-239 empty selector cannot include a body"
                    )
                return encoded
            if self.selector == self.TEXT_SELECTOR:
                if self.records:
                    raise PacketShapeError(
                        "server opcode-239 selector 21 cannot include records"
                    )
                if self.text is None or self.trailing_value is None:
                    raise PacketShapeError(
                        "server opcode-239 selector 21 requires text and a "
                        "trailing value"
                    )
                return (
                    encoded
                    + encode_utf16_string(self.text, trailing_byte=True)
                    + struct.pack("<I", self.trailing_value)
                )
            raise PacketShapeError(
                "server opcode-239 selector must be captured value 3, 9, 13, "
                f"or 21, got {self.selector}"
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-239 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode244DialogueInstruction:
    """Live-validated selector-8 instructional-dialogue branch of opcode 244."""

    value_1: int
    value_2: int
    value_3: int
    selector: int = 8
    opcode: int = 244

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode244DialogueInstruction":
        reader = PacketReader(
            payload, packet_name="server_opcode_244_dialogue_instruction"
        )
        _expect_opcode(reader, 244)
        selector = reader.u8("selector")
        if selector != 8:
            raise PacketShapeError(
                "server opcode-244 modeled branch requires selector 8, "
                f"got {selector}"
            )
        record = cls(
            selector=selector,
            value_1=reader.i32("value_1"),
            value_2=reader.i32("value_2"),
            value_3=reader.i32("value_3"),
        )
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, int]:
        return {
            "selector": self.selector,
            "value_1": self.value_1,
            "value_2": self.value_2,
            "value_3": self.value_3,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 244:
            raise PacketShapeError(
                "server opcode-244 dialogue instruction opcode must be 244"
            )
        if self.selector != 8:
            raise PacketShapeError(
                "server opcode-244 modeled branch requires selector 8"
            )
        try:
            return struct.pack(
                "<HBiii",
                self.opcode,
                self.selector,
                self.value_1,
                self.value_2,
                self.value_3,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-244 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode320PositionedEffectRecord:
    """Handler-bounded opcode-320 record for an aliased positioned effect."""

    primary_value: int = field(repr=False)
    control_value: int
    x: int
    y: int
    numeric_value: int
    secondary_control_value: int
    trailing_value: int
    opcode: int = 320

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode320PositionedEffectRecord":
        reader = PacketReader(
            payload, packet_name="server_opcode_320_positioned_effect"
        )
        _expect_opcode(reader, 320)
        record = cls(
            primary_value=reader.i32("primary_value"),
            control_value=reader.u8("control_value"),
            x=reader.i16("x"),
            y=reader.i16("y"),
            numeric_value=reader.i16("numeric_value"),
            secondary_control_value=reader.u8("secondary_control_value"),
            trailing_value=reader.u8("trailing_value"),
        )
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "primary_value_redacted": True,
            "control_value": self.control_value,
            "x": self.x,
            "y": self.y,
            "numeric_value": self.numeric_value,
            "secondary_control_value": self.secondary_control_value,
            "trailing_value": self.trailing_value,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 320:
            raise PacketShapeError("server opcode-320 record opcode must be 320")
        try:
            return struct.pack(
                "<HiBhhhBB",
                self.opcode,
                self.primary_value,
                self.control_value,
                self.x,
                self.y,
                self.numeric_value,
                self.secondary_control_value,
                self.trailing_value,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-320 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode322PositionedEffectRecord:
    """Handler-bounded opcode-322 record for an aliased positioned effect."""

    primary_value: int = field(repr=False)
    numeric_value: int
    control_value: int
    x: int
    y: int
    trailing_value: int
    opcode: int = 322

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode322PositionedEffectRecord":
        reader = PacketReader(
            payload, packet_name="server_opcode_322_positioned_effect"
        )
        _expect_opcode(reader, 322)
        record = cls(
            primary_value=reader.i32("primary_value"),
            numeric_value=reader.i32("numeric_value"),
            control_value=reader.u8("control_value"),
            x=reader.i16("x"),
            y=reader.i16("y"),
            trailing_value=reader.u8("trailing_value"),
        )
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "primary_value_redacted": True,
            "numeric_value": self.numeric_value,
            "control_value": self.control_value,
            "x": self.x,
            "y": self.y,
            "trailing_value": self.trailing_value,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 322:
            raise PacketShapeError("server opcode-322 record opcode must be 322")
        try:
            return struct.pack(
                "<HiiBhhB",
                self.opcode,
                self.primary_value,
                self.numeric_value,
                self.control_value,
                self.x,
                self.y,
                self.trailing_value,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-322 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode323PositionedEffectRecord:
    """Handler-bounded opcode-323 position update for an aliased effect."""

    primary_value: int = field(repr=False)
    control_value: int
    x: int
    y: int
    opcode: int = 323

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode323PositionedEffectRecord":
        reader = PacketReader(
            payload, packet_name="server_opcode_323_positioned_effect"
        )
        _expect_opcode(reader, 323)
        record = cls(
            primary_value=reader.i32("primary_value"),
            control_value=reader.u8("control_value"),
            x=reader.i16("x"),
            y=reader.i16("y"),
        )
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "primary_value_redacted": True,
            "control_value": self.control_value,
            "x": self.x,
            "y": self.y,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 323:
            raise PacketShapeError("server opcode-323 record opcode must be 323")
        try:
            return struct.pack(
                "<HiBhh",
                self.opcode,
                self.primary_value,
                self.control_value,
                self.x,
                self.y,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-323 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode27IntegerLedgerEntry:
    """One identifier-safe entry from the opcode-27 integer/text ledger."""

    key: int = field(repr=False)
    value: int = field(repr=False)
    control: int = field(repr=False)
    text: str = field(repr=False)

    @classmethod
    def parse_from(
        cls, reader: PacketReader, *, index: int
    ) -> "ServerOpcode27IntegerLedgerEntry":
        return cls(
            key=reader.i32(f"entries[{index}].key"),
            value=reader.i32(f"entries[{index}].value"),
            control=reader.i32(f"entries[{index}].control"),
            text=reader.utf16_string(
                f"entries[{index}].text", trailing_byte=True
            ),
        )

    @property
    def text_code_units(self) -> int:
        return len(self.text.encode("utf-16-le")) // 2

    def to_bytes(self) -> bytes:
        try:
            prefix = struct.pack("<iii", self.key, self.value, self.control)
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-27 entry value is out of range: {error}"
            ) from error
        return prefix + encode_utf16_string(self.text, trailing_byte=True)


@dataclass(frozen=True)
class ServerOpcode27IntegerLedger:
    """Counted integer/text ledger consumed by server opcode 27."""

    entries: tuple[ServerOpcode27IntegerLedgerEntry, ...]
    opcode: int = 27

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode27IntegerLedger":
        reader = PacketReader(payload, packet_name="server_opcode_27")
        _expect_opcode(reader, 27)
        entry_count = reader.i32("entry_count")
        if entry_count < 0 or entry_count > reader.remaining // 15:
            raise PacketShapeError(
                "server opcode-27 entry count does not fit the packet: "
                f"{entry_count} with {reader.remaining} bytes remaining"
            )
        entries = tuple(
            ServerOpcode27IntegerLedgerEntry.parse_from(reader, index=index)
            for index in range(entry_count)
        )
        reader.finish()
        return cls(entries=entries)

    @property
    def text_code_units(self) -> int:
        return sum(entry.text_code_units for entry in self.entries)

    def safe_dict(self) -> dict[str, object]:
        return {
            "entry_count": len(self.entries),
            "text_code_units": self.text_code_units,
            "text_code_units_by_entry": [
                entry.text_code_units for entry in self.entries
            ],
            "numeric_values_redacted": bool(self.entries),
            "text_redacted": bool(self.entries),
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 27:
            raise PacketShapeError("server opcode-27 ledger opcode must be 27")
        if len(self.entries) > 0x7FFF_FFFF:
            raise PacketShapeError(
                "server opcode-27 entry count exceeds signed i32"
            )
        return (
            struct.pack("<Hi", self.opcode, len(self.entries))
            + b"".join(entry.to_bytes() for entry in self.entries)
        )


@dataclass(frozen=True)
class ServerOpcode28TextLedgerEntry:
    """One identifier-safe entry from the opcode-28 text ledger."""

    key: int = field(repr=False)
    value: int = field(repr=False)
    text_1: str = field(repr=False)
    text_2: str = field(repr=False)

    @classmethod
    def parse_from(
        cls, reader: PacketReader, *, index: int
    ) -> "ServerOpcode28TextLedgerEntry":
        return cls(
            key=reader.i32(f"entries[{index}].key"),
            value=reader.i32(f"entries[{index}].value"),
            text_1=reader.utf16_string(
                f"entries[{index}].text_1", trailing_byte=True
            ),
            text_2=reader.utf16_string(
                f"entries[{index}].text_2", trailing_byte=True
            ),
        )

    @property
    def text_1_code_units(self) -> int:
        return len(self.text_1.encode("utf-16-le")) // 2

    @property
    def text_2_code_units(self) -> int:
        return len(self.text_2.encode("utf-16-le")) // 2

    def to_bytes(self) -> bytes:
        try:
            prefix = struct.pack("<ii", self.key, self.value)
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-28 entry value is out of range: {error}"
            ) from error
        return b"".join(
            (
                prefix,
                encode_utf16_string(self.text_1, trailing_byte=True),
                encode_utf16_string(self.text_2, trailing_byte=True),
            )
        )


@dataclass(frozen=True)
class ServerOpcode28TextLedger:
    """Counted paired-text ledger consumed by server opcode 28."""

    entries: tuple[ServerOpcode28TextLedgerEntry, ...]
    opcode: int = 28

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode28TextLedger":
        reader = PacketReader(payload, packet_name="server_opcode_28")
        _expect_opcode(reader, 28)
        entry_count = reader.i32("entry_count")
        if entry_count < 0 or entry_count > reader.remaining // 14:
            raise PacketShapeError(
                "server opcode-28 entry count does not fit the packet: "
                f"{entry_count} with {reader.remaining} bytes remaining"
            )
        entries = tuple(
            ServerOpcode28TextLedgerEntry.parse_from(reader, index=index)
            for index in range(entry_count)
        )
        reader.finish()
        return cls(entries=entries)

    @property
    def text_1_code_units(self) -> int:
        return sum(entry.text_1_code_units for entry in self.entries)

    @property
    def text_2_code_units(self) -> int:
        return sum(entry.text_2_code_units for entry in self.entries)

    def safe_dict(self) -> dict[str, object]:
        return {
            "entry_count": len(self.entries),
            "text_1_code_units": self.text_1_code_units,
            "text_2_code_units": self.text_2_code_units,
            "text_redacted": bool(self.entries),
            "numeric_values_redacted": bool(self.entries),
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 28:
            raise PacketShapeError("server opcode-28 ledger opcode must be 28")
        if len(self.entries) > 0x7FFF_FFFF:
            raise PacketShapeError(
                "server opcode-28 entry count exceeds signed i32"
            )
        return (
            struct.pack("<Hi", self.opcode, len(self.entries))
            + b"".join(entry.to_bytes() for entry in self.entries)
        )


@dataclass(frozen=True)
class ServerOpcode29TextLedgerEntry:
    """One redacted record from the delegated opcode-29 parser."""

    key: int = field(repr=False)
    value_1: int = field(repr=False)
    text: str = field(repr=False)
    value_2: int = field(repr=False)
    short_value: int = field(repr=False)

    @classmethod
    def parse_from(
        cls, reader: PacketReader, *, index: int
    ) -> "ServerOpcode29TextLedgerEntry":
        return cls(
            key=reader.i32(f"entries[{index}].key"),
            value_1=reader.i32(f"entries[{index}].value_1"),
            text=reader.utf16_string(
                f"entries[{index}].text", trailing_byte=True
            ),
            value_2=reader.i32(f"entries[{index}].value_2"),
            short_value=reader.i16(f"entries[{index}].short_value"),
        )

    @property
    def text_code_units(self) -> int:
        return len(self.text.encode("utf-16-le")) // 2

    def to_bytes(self) -> bytes:
        try:
            prefix = struct.pack("<ii", self.key, self.value_1)
            suffix = struct.pack("<ih", self.value_2, self.short_value)
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-29 entry value is out of range: {error}"
            ) from error
        return b"".join(
            (
                prefix,
                encode_utf16_string(self.text, trailing_byte=True),
                suffix,
            )
        )


@dataclass(frozen=True)
class ServerOpcode29TextLedger:
    """Counted text ledger consumed by delegated server opcode 29."""

    entries: tuple[ServerOpcode29TextLedgerEntry, ...]
    opcode: int = 29

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode29TextLedger":
        reader = PacketReader(payload, packet_name="server_opcode_29")
        _expect_opcode(reader, 29)
        entry_count = reader.u8("entry_count")
        if entry_count > reader.remaining // 17:
            raise PacketShapeError(
                "server opcode-29 entry count does not fit the packet: "
                f"{entry_count} with {reader.remaining} bytes remaining"
            )
        entries = tuple(
            ServerOpcode29TextLedgerEntry.parse_from(reader, index=index)
            for index in range(entry_count)
        )
        reader.finish()
        return cls(entries=entries)

    @property
    def text_code_units(self) -> int:
        return sum(entry.text_code_units for entry in self.entries)

    @property
    def text_code_units_by_entry(self) -> list[int]:
        return [entry.text_code_units for entry in self.entries]

    def safe_dict(self) -> dict[str, object]:
        return {
            "entry_count": len(self.entries),
            "text_code_units": self.text_code_units,
            "text_code_units_by_entry": self.text_code_units_by_entry,
            "text_redacted": bool(self.entries),
            "numeric_values_redacted": bool(self.entries),
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 29:
            raise PacketShapeError("server opcode-29 ledger opcode must be 29")
        if len(self.entries) > 0xFF:
            raise PacketShapeError("server opcode-29 entry count exceeds u8")
        return (
            struct.pack("<HB", self.opcode, len(self.entries))
            + b"".join(entry.to_bytes() for entry in self.entries)
        )


@dataclass(frozen=True)
class ServerOpcode135SectionAEntry:
    """One flag-gated integer vector from opcode-135 section A."""

    enabled: bool
    value: int = field(repr=False)
    values: tuple[int, ...] = field(repr=False)
    raw_enabled: int | None = field(default=None, repr=False, compare=False)

    @classmethod
    def parse_from(
        cls, reader: PacketReader, *, index: int
    ) -> "ServerOpcode135SectionAEntry":
        raw_enabled = reader.u8(f"section_a[{index}].enabled")
        value = reader.i32(f"section_a[{index}].value")
        value_count = reader.i32(f"section_a[{index}].value_count")
        if value_count < 0 or value_count > reader.remaining // 4:
            raise PacketShapeError(
                "server opcode-135 section_a value count does not fit the "
                f"packet: {value_count} with {reader.remaining} bytes remaining"
            )
        return cls(
            enabled=bool(raw_enabled),
            value=value,
            values=tuple(
                reader.i32(f"section_a[{index}].values[{value_index}]")
                for value_index in range(value_count)
            ),
            raw_enabled=raw_enabled,
        )

    def to_bytes(self) -> bytes:
        if len(self.values) > 0x7FFF_FFFF:
            raise PacketShapeError(
                "server opcode-135 section_a value count exceeds signed i32"
            )
        encoded_enabled = _il2cpp_boolean_byte(
            self.enabled,
            self.raw_enabled,
            field_name="server opcode-135 section_a enabled",
        )
        try:
            return struct.pack(
                f"<Bii{len(self.values)}i",
                encoded_enabled,
                self.value,
                len(self.values),
                *self.values,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-135 section_a value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode135SectionBEntry:
    """One flag-gated pair ledger from opcode-135 section B."""

    enabled: bool
    value_1: int = field(repr=False)
    value_2: int = field(repr=False)
    pairs: tuple[tuple[int, int], ...] = field(repr=False)
    raw_enabled: int | None = field(default=None, repr=False, compare=False)

    @classmethod
    def parse_from(
        cls, reader: PacketReader, *, index: int
    ) -> "ServerOpcode135SectionBEntry":
        raw_enabled = reader.u8(f"section_b[{index}].enabled")
        value_1 = reader.i32(f"section_b[{index}].value_1")
        value_2 = reader.u8(f"section_b[{index}].value_2")
        pair_count = reader.i16(f"section_b[{index}].pair_count")
        if pair_count < 0 or pair_count > reader.remaining // 8:
            raise PacketShapeError(
                "server opcode-135 section_b pair count does not fit the "
                f"packet: {pair_count} with {reader.remaining} bytes remaining"
            )
        return cls(
            enabled=bool(raw_enabled),
            value_1=value_1,
            value_2=value_2,
            pairs=tuple(
                (
                    reader.i32(f"section_b[{index}].pairs[{pair_index}][0]"),
                    reader.i32(f"section_b[{index}].pairs[{pair_index}][1]"),
                )
                for pair_index in range(pair_count)
            ),
            raw_enabled=raw_enabled,
        )

    def to_bytes(self) -> bytes:
        if len(self.pairs) > 0x7FFF:
            raise PacketShapeError(
                "server opcode-135 section_b pair count exceeds signed i16"
            )
        encoded_enabled = _il2cpp_boolean_byte(
            self.enabled,
            self.raw_enabled,
            field_name="server opcode-135 section_b enabled",
        )
        try:
            parts = [
                struct.pack(
                    "<BiBh",
                    encoded_enabled,
                    self.value_1,
                    self.value_2,
                    len(self.pairs),
                )
            ]
            parts.extend(struct.pack("<ii", *pair) for pair in self.pairs)
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-135 section_b value is out of range: {error}"
            ) from error
        return b"".join(parts)


@dataclass(frozen=True)
class ServerOpcode135SectionDEntry:
    """One two-group integer/byte ledger from opcode-135 section D."""

    value: int = field(repr=False)
    group_1: tuple[tuple[int, int], ...] = field(repr=False)
    group_2: tuple[tuple[int, int], ...] = field(repr=False)

    @staticmethod
    def _read_group(
        reader: PacketReader, *, field_name: str
    ) -> tuple[tuple[int, int], ...]:
        count = reader.i16(f"{field_name}.count")
        if count < 0 or count > reader.remaining // 5:
            raise PacketShapeError(
                f"server opcode-135 {field_name} count does not fit the "
                f"packet: {count} with {reader.remaining} bytes remaining"
            )
        return tuple(
            (
                reader.i32(f"{field_name}[{index}].value_1"),
                reader.u8(f"{field_name}[{index}].value_2"),
            )
            for index in range(count)
        )

    @classmethod
    def parse_from(
        cls, reader: PacketReader, *, index: int
    ) -> "ServerOpcode135SectionDEntry":
        value = reader.i32(f"section_d[{index}].value")
        return cls(
            value=value,
            group_1=cls._read_group(
                reader, field_name=f"section_d[{index}].group_1"
            ),
            group_2=cls._read_group(
                reader, field_name=f"section_d[{index}].group_2"
            ),
        )

    @staticmethod
    def _encode_group(
        group: tuple[tuple[int, int], ...], *, field_name: str
    ) -> bytes:
        if len(group) > 0x7FFF:
            raise PacketShapeError(
                f"server opcode-135 {field_name} count exceeds signed i16"
            )
        try:
            return struct.pack("<h", len(group)) + b"".join(
                struct.pack("<iB", *entry) for entry in group
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-135 {field_name} value is out of range: {error}"
            ) from error

    def to_bytes(self) -> bytes:
        try:
            value = struct.pack("<i", self.value)
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-135 section_d value is out of range: {error}"
            ) from error
        return b"".join(
            (
                value,
                self._encode_group(self.group_1, field_name="section_d group_1"),
                self._encode_group(self.group_2, field_name="section_d group_2"),
            )
        )


@dataclass(frozen=True)
class ServerOpcode135BootstrapLedger:
    """Primitive-traced, fully consumed opcode-135 bootstrap ledger."""

    section_a: tuple[ServerOpcode135SectionAEntry, ...]
    section_b: tuple[ServerOpcode135SectionBEntry, ...]
    section_c_value: int = field(repr=False)
    section_c_pairs: tuple[tuple[int, int], ...] = field(repr=False)
    section_d: tuple[ServerOpcode135SectionDEntry, ...]
    opcode: int = 135

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode135BootstrapLedger":
        reader = PacketReader(payload, packet_name="server_opcode_135")
        _expect_opcode(reader, 135)
        section_a_count = reader.u8("section_a_count")
        if section_a_count > reader.remaining // 9:
            raise PacketShapeError(
                "server opcode-135 section_a count does not fit the packet: "
                f"{section_a_count} with {reader.remaining} bytes remaining"
            )
        section_a = tuple(
            ServerOpcode135SectionAEntry.parse_from(reader, index=index)
            for index in range(section_a_count)
        )
        section_b_count = reader.u8("section_b_count")
        if section_b_count > reader.remaining // 8:
            raise PacketShapeError(
                "server opcode-135 section_b count does not fit the packet: "
                f"{section_b_count} with {reader.remaining} bytes remaining"
            )
        section_b = tuple(
            ServerOpcode135SectionBEntry.parse_from(reader, index=index)
            for index in range(section_b_count)
        )
        section_c_value = reader.u8("section_c_value")
        section_c_pair_count = reader.i16("section_c_pair_count")
        if (
            section_c_pair_count < 0
            or section_c_pair_count > reader.remaining // 8
        ):
            raise PacketShapeError(
                "server opcode-135 section_c pair count does not fit the "
                f"packet: {section_c_pair_count} with {reader.remaining} "
                "bytes remaining"
            )
        section_c_pairs = tuple(
            (
                reader.i32(f"section_c_pairs[{index}][0]"),
                reader.i32(f"section_c_pairs[{index}][1]"),
            )
            for index in range(section_c_pair_count)
        )
        section_d_count = reader.i32("section_d_count")
        if section_d_count < 0 or section_d_count > reader.remaining // 8:
            raise PacketShapeError(
                "server opcode-135 section_d count does not fit the packet: "
                f"{section_d_count} with {reader.remaining} bytes remaining"
            )
        section_d = tuple(
            ServerOpcode135SectionDEntry.parse_from(reader, index=index)
            for index in range(section_d_count)
        )
        reader.finish()
        return cls(
            section_a=section_a,
            section_b=section_b,
            section_c_value=section_c_value,
            section_c_pairs=section_c_pairs,
            section_d=section_d,
        )

    @property
    def section_a_value_count(self) -> int:
        return sum(len(entry.values) for entry in self.section_a)

    @property
    def section_b_pair_count(self) -> int:
        return sum(len(entry.pairs) for entry in self.section_b)

    @property
    def section_d_group_1_count(self) -> int:
        return sum(len(entry.group_1) for entry in self.section_d)

    @property
    def section_d_group_2_count(self) -> int:
        return sum(len(entry.group_2) for entry in self.section_d)

    def safe_dict(self) -> dict[str, object]:
        return {
            "section_a_entry_count": len(self.section_a),
            "section_a_enabled_count": sum(
                entry.enabled for entry in self.section_a
            ),
            "section_a_value_count": self.section_a_value_count,
            "section_a_value_counts": [
                len(entry.values) for entry in self.section_a
            ],
            "section_b_entry_count": len(self.section_b),
            "section_b_enabled_count": sum(
                entry.enabled for entry in self.section_b
            ),
            "section_b_pair_count": self.section_b_pair_count,
            "section_b_pair_counts": [
                len(entry.pairs) for entry in self.section_b
            ],
            "section_c_pair_count": len(self.section_c_pairs),
            "section_d_entry_count": len(self.section_d),
            "section_d_group_1_count": self.section_d_group_1_count,
            "section_d_group_2_count": self.section_d_group_2_count,
            "section_d_group_1_sizes": [
                len(entry.group_1) for entry in self.section_d
            ],
            "section_d_group_2_sizes": [
                len(entry.group_2) for entry in self.section_d
            ],
            "numeric_values_redacted": True,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 135:
            raise PacketShapeError("server opcode-135 ledger opcode must be 135")
        if len(self.section_a) > 0xFF or len(self.section_b) > 0xFF:
            raise PacketShapeError(
                "server opcode-135 section_a/section_b count exceeds u8"
            )
        if len(self.section_c_pairs) > 0x7FFF:
            raise PacketShapeError(
                "server opcode-135 section_c pair count exceeds signed i16"
            )
        if len(self.section_d) > 0x7FFF_FFFF:
            raise PacketShapeError(
                "server opcode-135 section_d count exceeds signed i32"
            )
        try:
            parts = [struct.pack("<HB", self.opcode, len(self.section_a))]
            parts.extend(entry.to_bytes() for entry in self.section_a)
            parts.append(struct.pack("<B", len(self.section_b)))
            parts.extend(entry.to_bytes() for entry in self.section_b)
            parts.append(
                struct.pack(
                    "<Bh",
                    self.section_c_value,
                    len(self.section_c_pairs),
                )
            )
            parts.extend(
                struct.pack("<ii", *pair) for pair in self.section_c_pairs
            )
            parts.append(struct.pack("<i", len(self.section_d)))
            parts.extend(entry.to_bytes() for entry in self.section_d)
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-135 ledger value is out of range: {error}"
            ) from error
        return b"".join(parts)


@dataclass(frozen=True)
class ServerOpcode142TextLedgerEntry:
    """One identifier-safe entry from the enabled opcode-142 ledger."""

    key: int = field(repr=False)
    control: int = field(repr=False)
    text_1: str = field(repr=False)
    text_2: str = field(repr=False)
    flag_1: bool
    flag_2: bool
    value_1: int = field(repr=False)
    value_2: int = field(repr=False)
    raw_flag_1: int | None = field(default=None, repr=False, compare=False)
    raw_flag_2: int | None = field(default=None, repr=False, compare=False)

    @classmethod
    def parse_from(
        cls, reader: PacketReader, *, index: int
    ) -> "ServerOpcode142TextLedgerEntry":
        key = reader.i32(f"entries[{index}].key")
        control = reader.i32(f"entries[{index}].control")
        text_1 = reader.utf16_string(
            f"entries[{index}].text_1", trailing_byte=True
        )
        text_2 = reader.utf16_string(
            f"entries[{index}].text_2", trailing_byte=True
        )
        flag_values = (
            reader.u8(f"entries[{index}].flag_1"),
            reader.u8(f"entries[{index}].flag_2"),
        )
        return cls(
            key=key,
            control=control,
            text_1=text_1,
            text_2=text_2,
            flag_1=bool(flag_values[0]),
            flag_2=bool(flag_values[1]),
            value_1=reader.i32(f"entries[{index}].value_1"),
            value_2=reader.i32(f"entries[{index}].value_2"),
            raw_flag_1=flag_values[0],
            raw_flag_2=flag_values[1],
        )

    @property
    def text_code_units(self) -> int:
        return (
            len(self.text_1.encode("utf-16-le"))
            + len(self.text_2.encode("utf-16-le"))
        ) // 2

    def to_bytes(self) -> bytes:
        encoded_flag_1 = _il2cpp_boolean_byte(
            self.flag_1,
            self.raw_flag_1,
            field_name="server opcode-142 entry flag_1",
        )
        encoded_flag_2 = _il2cpp_boolean_byte(
            self.flag_2,
            self.raw_flag_2,
            field_name="server opcode-142 entry flag_2",
        )
        try:
            prefix = struct.pack("<ii", self.key, self.control)
            suffix = struct.pack(
                "<BBii",
                encoded_flag_1,
                encoded_flag_2,
                self.value_1,
                self.value_2,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-142 entry value is out of range: {error}"
            ) from error
        return b"".join(
            (
                prefix,
                encode_utf16_string(self.text_1, trailing_byte=True),
                encode_utf16_string(self.text_2, trailing_byte=True),
                suffix,
            )
        )


@dataclass(frozen=True)
class ServerOpcode142TextLedger:
    """Boolean-gated text ledger consumed by server opcode 142."""

    enabled: bool
    header_text: str | None = field(repr=False)
    entries: tuple[ServerOpcode142TextLedgerEntry, ...]
    opcode: int = 142
    raw_enabled: int | None = field(default=None, repr=False, compare=False)

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode142TextLedger":
        reader = PacketReader(payload, packet_name="server_opcode_142")
        _expect_opcode(reader, 142)
        enabled_value = reader.u8("enabled")
        if not enabled_value:
            reader.finish()
            return cls(
                enabled=False,
                header_text=None,
                entries=(),
                raw_enabled=enabled_value,
            )
        header_text = reader.utf16_string("header_text", trailing_byte=True)
        entry_count = reader.i32("entry_count")
        if entry_count < 0 or entry_count > reader.remaining // 24:
            raise PacketShapeError(
                "server opcode-142 entry count does not fit the packet: "
                f"{entry_count} with {reader.remaining} bytes remaining"
            )
        entries = tuple(
            ServerOpcode142TextLedgerEntry.parse_from(reader, index=index)
            for index in range(entry_count)
        )
        reader.finish()
        return cls(
            enabled=True,
            header_text=header_text,
            entries=entries,
            raw_enabled=enabled_value,
        )

    @property
    def header_text_code_units(self) -> int:
        if self.header_text is None:
            return 0
        return len(self.header_text.encode("utf-16-le")) // 2

    @property
    def entry_text_code_units(self) -> int:
        return sum(entry.text_code_units for entry in self.entries)

    def safe_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "entry_count": len(self.entries),
            "header_text_code_units": self.header_text_code_units,
            "entry_text_code_units": self.entry_text_code_units,
            "flag_1_true_count": sum(entry.flag_1 for entry in self.entries),
            "flag_2_true_count": sum(entry.flag_2 for entry in self.entries),
            "text_redacted": self.header_text is not None or bool(self.entries),
            "numeric_values_redacted": bool(self.entries),
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 142:
            raise PacketShapeError(
                "server opcode-142 ledger opcode must be 142"
            )
        encoded_enabled = _il2cpp_boolean_byte(
            self.enabled,
            self.raw_enabled,
            field_name="server opcode-142 enabled flag",
        )
        prefix = struct.pack("<HB", self.opcode, encoded_enabled)
        if not self.enabled:
            if self.header_text is not None or self.entries:
                raise PacketShapeError(
                    "disabled server opcode-142 ledger cannot contain data"
                )
            return prefix
        if self.header_text is None:
            raise PacketShapeError(
                "enabled server opcode-142 ledger requires header text"
            )
        if len(self.entries) > 0x7FFF_FFFF:
            raise PacketShapeError(
                "server opcode-142 entry count exceeds signed i32"
            )
        return b"".join(
            (
                prefix,
                encode_utf16_string(self.header_text, trailing_byte=True),
                struct.pack("<i", len(self.entries)),
                *(entry.to_bytes() for entry in self.entries),
            )
        )


@dataclass(frozen=True)
class ServerOpcode425ValueLedger:
    """Primitive-traced counted values and fixed trailer from opcode 425."""

    values: tuple[int, ...] = field(repr=False)
    trailer: tuple[int, int, int, int]
    opcode: int = 425

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode425ValueLedger":
        reader = PacketReader(payload, packet_name="server_opcode_425")
        _expect_opcode(reader, 425)
        value_count = reader.u16("value_count")
        if reader.remaining != value_count * 4 + 16:
            raise PacketShapeError(
                "server opcode-425 value count does not fit the packet: "
                f"{value_count} with {reader.remaining} bytes remaining"
            )
        values = tuple(
            reader.i32(f"values[{index}]") for index in range(value_count)
        )
        trailer = tuple(
            reader.i32(f"trailer[{index}]") for index in range(4)
        )
        reader.finish()
        return cls(values=values, trailer=trailer)  # type: ignore[arg-type]

    def safe_dict(self) -> dict[str, object]:
        return {
            "value_count": len(self.values),
            "trailer": list(self.trailer),
            "values_redacted": bool(self.values),
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 425:
            raise PacketShapeError(
                "server opcode-425 ledger opcode must be 425"
            )
        if len(self.values) > 0xFFFF:
            raise PacketShapeError(
                "server opcode-425 value count exceeds unsigned u16"
            )
        if len(self.trailer) != 4:
            raise PacketShapeError(
                "server opcode-425 trailer must contain four i32 values"
            )
        try:
            return struct.pack(
                f"<HH{len(self.values)}i4i",
                self.opcode,
                len(self.values),
                *self.values,
                *self.trailer,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-425 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode147BoundsLedger:
    """Handler-bounded rectangles and counted values from opcode 147."""

    rectangle_1: tuple[int, int, int, int]
    rectangle_2: tuple[int, int, int, int]
    values: tuple[int, ...] = field(repr=False)
    opcode: int = 147

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode147BoundsLedger":
        reader = PacketReader(payload, packet_name="server_opcode_147")
        _expect_opcode(reader, 147)
        rectangle_1 = tuple(
            reader.i32(f"rectangle_1[{index}]") for index in range(4)
        )
        rectangle_2 = tuple(
            reader.i32(f"rectangle_2[{index}]") for index in range(4)
        )
        value_count = reader.i32("value_count")
        if value_count < 0 or value_count > reader.remaining // 4:
            raise PacketShapeError(
                "server opcode-147 value count does not fit the packet: "
                f"{value_count} with {reader.remaining} bytes remaining"
            )
        values = tuple(
            reader.i32(f"values[{index}]") for index in range(value_count)
        )
        reader.finish()
        return cls(
            rectangle_1=rectangle_1,  # type: ignore[arg-type]
            rectangle_2=rectangle_2,  # type: ignore[arg-type]
            values=values,
        )

    def safe_dict(self) -> dict[str, object]:
        return {
            "rectangles": [list(self.rectangle_1), list(self.rectangle_2)],
            "value_count": len(self.values),
            "values_redacted": bool(self.values),
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 147:
            raise PacketShapeError("server opcode-147 ledger opcode must be 147")
        if len(self.rectangle_1) != 4 or len(self.rectangle_2) != 4:
            raise PacketShapeError(
                "server opcode-147 rectangles must contain four i32 values"
            )
        if len(self.values) > 0x7FFF_FFFF:
            raise PacketShapeError(
                "server opcode-147 value count exceeds signed i32"
            )
        try:
            prefix = struct.pack(
                "<H8ii",
                self.opcode,
                *self.rectangle_1,
                *self.rectangle_2,
                len(self.values),
            )
            return prefix + struct.pack(
                f"<{len(self.values)}i", *self.values
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-147 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode272LedgerEntry:
    """One counted, neutral opcode-272 ledger entry."""

    selector: int = field(repr=False)
    flag_1: bool
    flag_2: bool
    group_1: tuple[tuple[int, int, int], ...] = field(repr=False)
    group_2: tuple[tuple[int, int, int], ...] = field(repr=False)
    raw_flag_1: int | None = field(default=None, repr=False, compare=False)
    raw_flag_2: int | None = field(default=None, repr=False, compare=False)

    @staticmethod
    def _read_group(
        reader: PacketReader, *, field_name: str
    ) -> tuple[tuple[int, int, int], ...]:
        count = reader.i32(f"{field_name}.count")
        if count < 0 or count > reader.remaining // 12:
            raise PacketShapeError(
                f"server opcode-272 {field_name} count does not fit the "
                f"packet: {count} with {reader.remaining} bytes remaining"
            )
        return tuple(
            tuple(
                reader.i32(f"{field_name}[{index}][{member}]")
                for member in range(3)
            )
            for index in range(count)
        )  # type: ignore[return-value]

    @classmethod
    def parse_from(
        cls, reader: PacketReader, *, index: int
    ) -> "ServerOpcode272LedgerEntry":
        selector = reader.i32(f"entries[{index}].selector")
        flag_values = (
            reader.u8(f"entries[{index}].flag_1"),
            reader.u8(f"entries[{index}].flag_2"),
        )
        return cls(
            selector=selector,
            flag_1=bool(flag_values[0]),
            flag_2=bool(flag_values[1]),
            group_1=cls._read_group(
                reader, field_name=f"entries[{index}].group_1"
            ),
            group_2=cls._read_group(
                reader, field_name=f"entries[{index}].group_2"
            ),
            raw_flag_1=flag_values[0],
            raw_flag_2=flag_values[1],
        )

    def to_bytes(self) -> bytes:
        encoded_flag_1 = _il2cpp_boolean_byte(
            self.flag_1,
            self.raw_flag_1,
            field_name="server opcode-272 entry flag_1",
        )
        encoded_flag_2 = _il2cpp_boolean_byte(
            self.flag_2,
            self.raw_flag_2,
            field_name="server opcode-272 entry flag_2",
        )
        if len(self.group_1) > 0x7FFF_FFFF or len(self.group_2) > 0x7FFF_FFFF:
            raise PacketShapeError(
                "server opcode-272 group count exceeds signed i32"
            )
        parts: list[bytes] = []
        try:
            parts.append(
                struct.pack(
                    "<iBBi",
                    self.selector,
                    encoded_flag_1,
                    encoded_flag_2,
                    len(self.group_1),
                )
            )
            for group in self.group_1:
                if len(group) != 3:
                    raise PacketShapeError(
                        "server opcode-272 group members must contain three i32 values"
                    )
                parts.append(struct.pack("<3i", *group))
            parts.append(struct.pack("<i", len(self.group_2)))
            for group in self.group_2:
                if len(group) != 3:
                    raise PacketShapeError(
                        "server opcode-272 group members must contain three i32 values"
                    )
                parts.append(struct.pack("<3i", *group))
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-272 entry value is out of range: {error}"
            ) from error
        return b"".join(parts)


@dataclass(frozen=True)
class ServerOpcode272Ledger:
    """Primitive-traced, fully consumed opcode-272 field ledger."""

    header_value: int = field(repr=False)
    start_ticks: int = field(repr=False)
    end_ticks: int = field(repr=False)
    header_values: tuple[int, int, int, int, int] = field(repr=False)
    entries: tuple[ServerOpcode272LedgerEntry, ...]
    trailer_value: int
    opcode: int = 272

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode272Ledger":
        reader = PacketReader(payload, packet_name="server_opcode_272")
        _expect_opcode(reader, 272)
        header_value = reader.i32("header_value")
        start_ticks = reader.i64("start_ticks")
        end_ticks = reader.i64("end_ticks")
        header_values = tuple(
            reader.i32(f"header_values[{index}]") for index in range(5)
        )
        entry_count = reader.i32("entry_count")
        if entry_count < 0 or entry_count > max(0, (reader.remaining - 4) // 14):
            raise PacketShapeError(
                "server opcode-272 entry count does not fit the packet: "
                f"{entry_count} with {reader.remaining} bytes remaining"
            )
        entries = tuple(
            ServerOpcode272LedgerEntry.parse_from(reader, index=index)
            for index in range(entry_count)
        )
        trailer_value = reader.i32("trailer_value")
        reader.finish()
        return cls(
            header_value=header_value,
            start_ticks=start_ticks,
            end_ticks=end_ticks,
            header_values=header_values,  # type: ignore[arg-type]
            entries=entries,
            trailer_value=trailer_value,
        )

    @property
    def group_1_count(self) -> int:
        return sum(len(entry.group_1) for entry in self.entries)

    @property
    def group_2_count(self) -> int:
        return sum(len(entry.group_2) for entry in self.entries)

    def safe_dict(self) -> dict[str, object]:
        return {
            "entry_count": len(self.entries),
            "flag_1_true_count": sum(entry.flag_1 for entry in self.entries),
            "flag_2_true_count": sum(entry.flag_2 for entry in self.entries),
            "group_1_count": self.group_1_count,
            "group_2_count": self.group_2_count,
            "group_1_sizes": [len(entry.group_1) for entry in self.entries],
            "group_2_sizes": [len(entry.group_2) for entry in self.entries],
            "trailer_value": self.trailer_value,
            "datetime_values_redacted": True,
            "numeric_values_redacted": True,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 272:
            raise PacketShapeError("server opcode-272 ledger opcode must be 272")
        if len(self.header_values) != 5:
            raise PacketShapeError(
                "server opcode-272 header must contain five i32 values"
            )
        if len(self.entries) > 0x7FFF_FFFF:
            raise PacketShapeError(
                "server opcode-272 entry count exceeds signed i32"
            )
        try:
            prefix = struct.pack(
                "<Hiqq5ii",
                self.opcode,
                self.header_value,
                self.start_ticks,
                self.end_ticks,
                *self.header_values,
                len(self.entries),
            )
            trailer = struct.pack("<i", self.trailer_value)
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-272 value is out of range: {error}"
            ) from error
        return prefix + b"".join(entry.to_bytes() for entry in self.entries) + trailer


@dataclass(frozen=True)
class ServerOpcode348TextEnvelope:
    """Capture-bounded, identifier-safe text branches of server opcode 348."""

    category: int
    primary_value: int = field(repr=False)
    selector: int
    value: int
    text: str = field(repr=False)
    control_1: int | None = None
    control_2: int | None = None
    opcode: int = 348

    EXTENDED_SELECTOR = 0
    SIMPLE_SELECTORS = frozenset({3, 6, 17})

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode348TextEnvelope":
        reader = PacketReader(payload, packet_name="server_opcode_348_text")
        _expect_opcode(reader, 348)
        category = reader.u8("category")
        primary_value = reader.i32("primary_value")
        selector = reader.u8("selector")
        value = reader.i32("value")
        text = reader.utf16_string("text", trailing_byte=True)
        if selector == cls.EXTENDED_SELECTOR:
            record = cls(
                category=category,
                primary_value=primary_value,
                selector=selector,
                value=value,
                text=text,
                control_1=reader.u8("control_1"),
                control_2=reader.u8("control_2"),
            )
        elif selector in cls.SIMPLE_SELECTORS:
            record = cls(
                category=category,
                primary_value=primary_value,
                selector=selector,
                value=value,
                text=text,
            )
        else:
            raise PacketShapeError(
                "server opcode-348 selector must be captured value "
                f"0, 3, 6, or 17, got {selector}"
            )
        reader.finish()
        return record

    @property
    def text_code_units(self) -> int:
        return len(self.text.encode("utf-16-le")) // 2

    def safe_dict(self) -> dict[str, int | bool | None]:
        return {
            "category": self.category,
            "primary_value_redacted": True,
            "selector": self.selector,
            "value": self.value,
            "text_present": True,
            "text_code_units": self.text_code_units,
            "control_1": self.control_1,
            "control_2": self.control_2,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 348:
            raise PacketShapeError("server opcode-348 envelope opcode must be 348")
        try:
            encoded = struct.pack(
                "<HBiBi",
                self.opcode,
                self.category,
                self.primary_value,
                self.selector,
                self.value,
            ) + encode_utf16_string(self.text, trailing_byte=True)
            if self.selector == self.EXTENDED_SELECTOR:
                if self.control_1 is None or self.control_2 is None:
                    raise PacketShapeError(
                        "server opcode-348 selector 0 requires two controls"
                    )
                return encoded + struct.pack(
                    "<BB", self.control_1, self.control_2
                )
            if self.selector in self.SIMPLE_SELECTORS:
                if self.control_1 is not None or self.control_2 is not None:
                    raise PacketShapeError(
                        "server opcode-348 simple selector cannot include controls"
                    )
                return encoded
            raise PacketShapeError(
                "server opcode-348 selector must be captured value 0, 3, 6, "
                f"or 17, got {self.selector}"
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-348 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerU32OpaqueTailEnvelope:
    """Generated-handler u32 prefix plus a capture-bounded ignored tail."""

    primary_value: int = field(repr=False)
    opaque_tail: bytes = field(repr=False)
    opcode: int

    CAPTURED_TAIL_LENGTHS = {
        228: frozenset({4}),
        230: frozenset({1, 7}),
        231: frozenset({20}),
        232: frozenset({16}),
        234: frozenset({3}),
        235: frozenset({6}),
    }

    @classmethod
    def parse(cls, payload: bytes) -> "ServerU32OpaqueTailEnvelope":
        if len(payload) < 2:
            raise PacketShapeError(
                "server u32 opaque-tail envelope needs an opcode"
            )
        opcode = int.from_bytes(payload[:2], "little")
        reader = PacketReader(
            payload, packet_name=f"server_opcode_{opcode}_u32_envelope"
        )
        _expect_opcode(reader, opcode)
        envelope = cls(
            primary_value=reader.u32("primary_value"),
            opaque_tail=reader.bytes(reader.remaining, "opaque_tail"),
            opcode=opcode,
        )
        reader.finish()
        envelope._validate()
        return envelope

    def _validate(self) -> None:
        expected_lengths = self.CAPTURED_TAIL_LENGTHS.get(self.opcode)
        if expected_lengths is None:
            raise PacketShapeError(
                "server u32 opaque-tail envelope opcode must be one of "
                f"{sorted(self.CAPTURED_TAIL_LENGTHS)}, got {self.opcode}"
            )
        if len(self.opaque_tail) not in expected_lengths:
            raise PacketShapeError(
                f"server opcode-{self.opcode} opaque tail has "
                f"{len(self.opaque_tail)} bytes, expected one of "
                f"{sorted(expected_lengths)}"
            )

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "primary_value_redacted": True,
            "typed_value_count": 1,
            "opaque_tail_length": len(self.opaque_tail),
            "opaque_tail_redacted": bool(self.opaque_tail),
        }

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return (
                struct.pack("<HI", self.opcode, self.primary_value)
                + self.opaque_tail
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-{self.opcode} primary value is out of range: "
                f"{error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode137OpaqueTailEnvelope:
    """Generated i16/i32/i32 prefix plus a capture-bounded ignored tail."""

    first_value: int = field(repr=False)
    second_value: int = field(repr=False)
    third_value: int = field(repr=False)
    opaque_tail: bytes = field(repr=False)
    opcode: int = 137

    OPAQUE_TAIL_LENGTH = 72

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode137OpaqueTailEnvelope":
        reader = PacketReader(payload, packet_name="server_opcode_137_envelope")
        _expect_opcode(reader, 137)
        envelope = cls(
            first_value=reader.i16("first_value"),
            second_value=reader.i32("second_value"),
            third_value=reader.i32("third_value"),
            opaque_tail=reader.bytes(reader.remaining, "opaque_tail"),
        )
        reader.finish()
        envelope._validate()
        return envelope

    def _validate(self) -> None:
        if self.opcode != 137:
            raise PacketShapeError(
                "server opcode-137 envelope opcode must be 137"
            )
        if len(self.opaque_tail) != self.OPAQUE_TAIL_LENGTH:
            raise PacketShapeError(
                "server opcode-137 opaque tail must be exactly "
                f"{self.OPAQUE_TAIL_LENGTH} bytes"
            )

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "typed_values_redacted": True,
            "typed_value_count": 3,
            "opaque_tail_length": len(self.opaque_tail),
            "opaque_tail_redacted": bool(self.opaque_tail),
        }

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack(
                "<Hhii",
                self.opcode,
                self.first_value,
                self.second_value,
                self.third_value,
            ) + bytes(self.opaque_tail)
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-137 prefix value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode169TextInstruction:
    """Generated selector-3 branch carrying one redacted UTF-16 value."""

    selector: int
    text: str = field(repr=False)
    opcode: int = 169

    TEXT_SELECTOR = 3

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode169TextInstruction":
        reader = PacketReader(
            payload, packet_name="server_opcode_169_text_instruction"
        )
        _expect_opcode(reader, 169)
        selector = reader.u8("selector")
        if selector != cls.TEXT_SELECTOR:
            raise PacketShapeError(
                "server opcode-169 text instruction selector must be 3, "
                f"got {selector}"
            )
        instruction = cls(
            selector=selector,
            text=reader.utf16_string("text", trailing_byte=True),
        )
        reader.finish()
        return instruction

    @property
    def text_code_units(self) -> int:
        return len(self.text.encode("utf-16-le")) // 2

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "selector": self.selector,
            "text_present": True,
            "text_code_units": self.text_code_units,
            "text_redacted": True,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 169:
            raise PacketShapeError(
                "server opcode-169 text instruction opcode must be 169"
            )
        if self.selector != self.TEXT_SELECTOR:
            raise PacketShapeError(
                "server opcode-169 text instruction selector must be 3, "
                f"got {self.selector}"
            )
        try:
            return struct.pack("<HB", self.opcode, self.selector) + (
                encode_utf16_string(self.text, trailing_byte=True)
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-169 selector is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode69Record:
    """Opcode-69 numeric prefix followed by its capture-fixed opaque table."""

    header_value: int
    opaque_tail: bytes = field(repr=False)
    opcode: int = 69

    OPAQUE_TAIL_LENGTH = 263

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode69Record":
        reader = PacketReader(payload, packet_name="server_opcode_69_record")
        _expect_opcode(reader, 69)
        record = cls(
            header_value=reader.u32("header_value"),
            opaque_tail=reader.bytes(reader.remaining, "opaque_tail"),
        )
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode != 69:
            raise PacketShapeError("server opcode-69 record opcode must be 69")
        if len(self.opaque_tail) != self.OPAQUE_TAIL_LENGTH:
            raise PacketShapeError(
                "server opcode-69 opaque tail must be exactly "
                f"{self.OPAQUE_TAIL_LENGTH} bytes"
            )

    def safe_dict(self) -> dict[str, int]:
        return {
            "header_value": self.header_value,
            "typed_value_count": 1,
            "opaque_tail_length": len(self.opaque_tail),
        }

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack("<HI", self.opcode, self.header_value) + bytes(
                self.opaque_tail
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-69 header value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode93Record:
    """Opcode-93 counted uint32 vector with neutral element semantics."""

    values: tuple[int, ...]
    opcode: int = 93

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode93Record":
        reader = PacketReader(payload, packet_name="server_opcode_93_record")
        _expect_opcode(reader, 93)
        value_count = reader.u8("value_count")
        record = cls(
            values=tuple(
                reader.u32(f"values[{index}]")
                for index in range(value_count)
            )
        )
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, int]:
        return {
            "value_count": len(self.values),
            "unique_value_count": len(set(self.values)),
            "typed_value_count": len(self.values),
            "opaque_tail_length": 0,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 93:
            raise PacketShapeError("server opcode-93 record opcode must be 93")
        if len(self.values) > 0xFF:
            raise PacketShapeError(
                "server opcode-93 record cannot contain more than 255 values"
            )
        try:
            return struct.pack(
                f"<HB{len(self.values)}I",
                self.opcode,
                len(self.values),
                *self.values,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-93 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode94Record:
    """Fully bounded opcode-94 flag and signed integer pair."""

    flag: bool
    primary_value: int
    secondary_value: int
    opcode: int = 94
    raw_flag: int | None = field(default=None, repr=False, compare=False)

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode94Record":
        reader = PacketReader(payload, packet_name="server_opcode_94_record")
        _expect_opcode(reader, 94)
        raw_flag = reader.u8("flag")
        record = cls(
            flag=bool(raw_flag),
            primary_value=reader.i32("primary_value"),
            secondary_value=reader.i32("secondary_value"),
            raw_flag=raw_flag,
        )
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "flag": self.flag,
            "primary_value": self.primary_value,
            "secondary_value": self.secondary_value,
            "typed_value_count": 3,
            "opaque_tail_length": 0,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 94:
            raise PacketShapeError("server opcode-94 record opcode must be 94")
        encoded_flag = _il2cpp_boolean_byte(
            self.flag,
            self.raw_flag,
            field_name="server opcode-94 flag",
        )
        try:
            return struct.pack(
                "<HBii",
                self.opcode,
                encoded_flag,
                self.primary_value,
                self.secondary_value,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-94 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode148Envelope:
    """Opcode-148 list/control variants with a lossless legacy record body."""

    variant: int
    record_count: int | None = None
    primary_value: int | None = field(default=None, repr=False)
    secondary_value: int | None = field(default=None, repr=False)
    records_blob: bytes = field(default=b"", repr=False)
    opcode: int = 148

    RECORDS_VARIANT = 9
    EMPTY_VARIANT = 10
    PAIR_VARIANTS = frozenset({12, 13})
    CURRENT_IL2CPP_RECORD_MASK = 0x9

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode148Envelope":
        reader = PacketReader(payload, packet_name="server_opcode_148_envelope")
        _expect_opcode(reader, 148)
        variant = reader.u8("variant")
        if variant == cls.RECORDS_VARIANT:
            record = cls(
                variant=variant,
                record_count=reader.i32("record_count"),
                records_blob=reader.bytes(reader.remaining, "records_blob"),
            )
        elif variant == cls.EMPTY_VARIANT:
            record = cls(variant=variant)
        elif variant in cls.PAIR_VARIANTS:
            record = cls(
                variant=variant,
                primary_value=reader.i32("primary_value"),
                secondary_value=reader.i32("secondary_value"),
            )
        else:
            raise PacketShapeError(
                "server opcode-148 variant must be captured value 9, 10, "
                f"12, or 13, got {variant}"
            )
        reader.finish()
        record._validate()
        return record

    @property
    def fully_bounded(self) -> bool:
        return not self.records_blob

    def _validate(self) -> None:
        if self.opcode != 148:
            raise PacketShapeError("server opcode-148 envelope opcode must be 148")
        if self.variant == self.RECORDS_VARIANT:
            if self.record_count is None or self.record_count < 0:
                raise PacketShapeError(
                    "server opcode-148 record count must be non-negative"
                )
            if self.primary_value is not None or self.secondary_value is not None:
                raise PacketShapeError(
                    "server opcode-148 records variant cannot include pair values"
                )
            if self.record_count == 0 and self.records_blob:
                raise PacketShapeError(
                    "server opcode-148 zero-record variant cannot include a body"
                )
            if self.record_count > 0 and not self.records_blob:
                raise PacketShapeError(
                    "server opcode-148 non-empty record variant requires a body"
                )
            return
        if self.variant == self.EMPTY_VARIANT:
            if (
                self.record_count is not None
                or self.primary_value is not None
                or self.secondary_value is not None
                or self.records_blob
            ):
                raise PacketShapeError(
                    "server opcode-148 empty variant cannot include values or a body"
                )
            return
        if self.variant in self.PAIR_VARIANTS:
            if self.primary_value is None or self.secondary_value is None:
                raise PacketShapeError(
                    "server opcode-148 pair variant requires two signed integers"
                )
            if self.record_count is not None or self.records_blob:
                raise PacketShapeError(
                    "server opcode-148 pair variant cannot include records"
                )
            return
        raise PacketShapeError(
            "server opcode-148 variant must be captured value 9, 10, 12, or 13"
        )

    def safe_dict(self) -> dict[str, object]:
        details: dict[str, object] = {
            "variant": self.variant,
            "current_il2cpp_record_mask": self.CURRENT_IL2CPP_RECORD_MASK,
            "typed_value_count": 1,
            "opaque_tail_length": len(self.records_blob),
        }
        if self.variant == self.RECORDS_VARIANT:
            details["record_count"] = self.record_count
            details["typed_value_count"] = 2
        elif self.variant in self.PAIR_VARIANTS:
            details["pair_values_redacted"] = True
            details["typed_value_count"] = 3
        return details

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            encoded = struct.pack("<HB", self.opcode, self.variant)
            if self.variant == self.RECORDS_VARIANT:
                assert self.record_count is not None
                return (
                    encoded
                    + struct.pack("<i", self.record_count)
                    + bytes(self.records_blob)
                )
            if self.variant in self.PAIR_VARIANTS:
                assert self.primary_value is not None
                assert self.secondary_value is not None
                return encoded + struct.pack(
                    "<ii", self.primary_value, self.secondary_value
                )
            return encoded
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-148 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode201Record:
    """Opcode-201 typed prefix with a capture-fixed opaque suffix."""

    primary_value: int = field(repr=False)
    secondary_value: int = field(repr=False)
    flag_a: int
    flag_b: int
    opaque_tail: bytes = field(repr=False)
    opcode: int = 201

    OPAQUE_TAIL_LENGTH = 22

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode201Record":
        reader = PacketReader(payload, packet_name="server_opcode_201_record")
        _expect_opcode(reader, 201)
        record = cls(
            primary_value=reader.u32("primary_value"),
            secondary_value=reader.u32("secondary_value"),
            flag_a=reader.u8("flag_a"),
            flag_b=reader.u8("flag_b"),
            opaque_tail=reader.bytes(reader.remaining, "opaque_tail"),
        )
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode != 201:
            raise PacketShapeError("server opcode-201 record opcode must be 201")
        if len(self.opaque_tail) != self.OPAQUE_TAIL_LENGTH:
            raise PacketShapeError(
                "server opcode-201 opaque tail must be exactly "
                f"{self.OPAQUE_TAIL_LENGTH} bytes"
            )

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "primary_value_redacted": True,
            "secondary_value_redacted": True,
            "flag_a": self.flag_a,
            "flag_b": self.flag_b,
            "typed_value_count": 4,
            "opaque_tail_length": len(self.opaque_tail),
        }

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack(
                "<HIIBB",
                self.opcode,
                self.primary_value,
                self.secondary_value,
                self.flag_a,
                self.flag_b,
            ) + bytes(self.opaque_tail)
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-201 prefix is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode205Record:
    """Fully bounded opcode-205 numeric record with a redacted primary value."""

    primary_value: int = field(repr=False)
    secondary_value: int
    numeric_value: int
    trailing_value: int
    opcode: int = 205

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode205Record":
        reader = PacketReader(payload, packet_name="server_opcode_205_record")
        _expect_opcode(reader, 205)
        record = cls(
            primary_value=reader.u32("primary_value"),
            secondary_value=reader.u32("secondary_value"),
            numeric_value=reader.u64("numeric_value"),
            trailing_value=reader.u8("trailing_value"),
        )
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "primary_value_redacted": True,
            "secondary_value": self.secondary_value,
            "numeric_value": self.numeric_value,
            "trailing_value": self.trailing_value,
            "typed_value_count": 4,
            "opaque_tail_length": 0,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 205:
            raise PacketShapeError("server opcode-205 record opcode must be 205")
        try:
            return struct.pack(
                "<HIIQB",
                self.opcode,
                self.primary_value,
                self.secondary_value,
                self.numeric_value,
                self.trailing_value,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-205 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode276BooleanFlag:
    """Fully bounded opcode-276 IL2CPP boolean with its raw wire byte."""

    raw_flag: int
    opcode: int = 276

    @property
    def enabled(self) -> bool:
        """Match BitConverter.ToBoolean: every nonzero byte is true."""

        return self.raw_flag != 0

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode276BooleanFlag":
        reader = PacketReader(payload, packet_name="server_opcode_276_flag")
        _expect_opcode(reader, 276)
        record = cls(raw_flag=reader.u8("raw_flag"))
        reader.finish()
        return record

    def safe_dict(self) -> dict[str, int | bool]:
        return {
            "raw_flag": self.raw_flag,
            "enabled": self.enabled,
            "typed_value_count": 1,
            "opaque_tail_length": 0,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 276:
            raise PacketShapeError("server opcode-276 flag opcode must be 276")
        try:
            return struct.pack("<HB", self.opcode, self.raw_flag)
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-276 flag is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode379Record:
    """Opcode-379 discriminator with its optional four datetime values."""

    variant: int
    time_values: tuple[int, ...] = ()
    opcode: int = 379

    SHORT_VARIANT = 35
    TIMESTAMPS_VARIANT = 36

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode379Record":
        reader = PacketReader(payload, packet_name="server_opcode_379_record")
        _expect_opcode(reader, 379)
        variant = reader.u8("variant")
        time_values: tuple[int, ...] = ()
        if variant == cls.TIMESTAMPS_VARIANT:
            time_values = tuple(
                reader.i64(f"time_values[{index}]") for index in range(4)
            )
        elif variant != cls.SHORT_VARIANT:
            raise PacketShapeError(
                "server opcode-379 variant must be captured value 35 or 36"
            )
        record = cls(variant=variant, time_values=time_values)
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode != 379:
            raise PacketShapeError("server opcode-379 record opcode must be 379")
        expected_count = 4 if self.variant == self.TIMESTAMPS_VARIANT else 0
        if self.variant not in {self.SHORT_VARIANT, self.TIMESTAMPS_VARIANT}:
            raise PacketShapeError(
                "server opcode-379 variant must be captured value 35 or 36"
            )
        if len(self.time_values) != expected_count:
            raise PacketShapeError(
                f"server opcode-379 variant {self.variant} requires exactly "
                f"{expected_count} datetime values"
            )

    def safe_dict(self) -> dict[str, object]:
        return {
            "variant": self.variant,
            "time_values": list(self.time_values),
            "typed_value_count": 1 + len(self.time_values),
            "opaque_tail_length": 0,
        }

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack(
                f"<HB{len(self.time_values)}q",
                self.opcode,
                self.variant,
                *self.time_values,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"server opcode-379 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class FixedServerEmptyRecord:
    opcode: int

    SUPPORTED_OPCODES = {24, 45, 178}

    @classmethod
    def parse(cls, payload: bytes) -> "FixedServerEmptyRecord":
        reader = PacketReader(payload, packet_name="fixed_server_empty_record")
        record = cls(opcode=reader.u16("opcode"))
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode not in self.SUPPORTED_OPCODES:
            raise PacketShapeError(
                f"unsupported empty fixed-server opcode {self.opcode}"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        return struct.pack("<H", self.opcode)


@dataclass(frozen=True)
class FixedServerU8Record:
    opcode: int
    value: int

    SUPPORTED_OPCODES = {58, 71, 89, 105, 121}

    @classmethod
    def parse(cls, payload: bytes) -> "FixedServerU8Record":
        reader = PacketReader(payload, packet_name="fixed_server_u8_record")
        record = cls(opcode=reader.u16("opcode"), value=reader.u8("value"))
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode not in self.SUPPORTED_OPCODES:
            raise PacketShapeError(
                f"unsupported uint8 fixed-server opcode {self.opcode}"
            )
        if not 0 <= self.value <= 0xFF:
            raise PacketShapeError("fixed-server uint8 value is out of range")

    def to_bytes(self) -> bytes:
        self._validate()
        return struct.pack("<HB", self.opcode, self.value)


@dataclass(frozen=True)
class FixedServerU16Record:
    value: int
    opcode: int = 56

    SUPPORTED_OPCODES = {56, 72, 74}

    @classmethod
    def parse(cls, payload: bytes) -> "FixedServerU16Record":
        reader = PacketReader(payload, packet_name="fixed_server_u16_record")
        opcode = reader.u16("opcode")
        record = cls(value=reader.u16("value"), opcode=opcode)
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode not in self.SUPPORTED_OPCODES:
            raise PacketShapeError(
                f"unsupported uint16 fixed-server opcode {self.opcode}"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack("<HH", self.opcode, self.value)
        except struct.error as error:
            raise PacketShapeError(
                f"fixed-server uint16 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class FixedServerI32Record:
    opcode: int
    value: int

    SUPPORTED_OPCODES = {60}

    @classmethod
    def parse(cls, payload: bytes) -> "FixedServerI32Record":
        reader = PacketReader(payload, packet_name="fixed_server_i32_record")
        record = cls(opcode=reader.u16("opcode"), value=reader.i32("value"))
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode not in self.SUPPORTED_OPCODES:
            raise PacketShapeError(
                f"unsupported int32 fixed-server opcode {self.opcode}"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack("<Hi", self.opcode, self.value)
        except struct.error as error:
            raise PacketShapeError(
                f"fixed-server int32 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class FixedServerU32Record:
    opcode: int
    value: int

    SUPPORTED_OPCODES = {112, 131, 301, 386, 388, 389}

    @classmethod
    def parse(cls, payload: bytes) -> "FixedServerU32Record":
        reader = PacketReader(payload, packet_name="fixed_server_u32_record")
        record = cls(opcode=reader.u16("opcode"), value=reader.u32("value"))
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode not in self.SUPPORTED_OPCODES:
            raise PacketShapeError(
                f"unsupported uint32 fixed-server opcode {self.opcode}"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack("<HI", self.opcode, self.value)
        except struct.error as error:
            raise PacketShapeError(
                f"fixed-server uint32 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class FixedServerU16PairRecord:
    value_1: int
    value_2: int
    opcode: int = 96

    SUPPORTED_OPCODES = {96}

    @classmethod
    def parse(cls, payload: bytes) -> "FixedServerU16PairRecord":
        reader = PacketReader(
            payload, packet_name="fixed_server_u16_pair_record"
        )
        _expect_opcode(reader, 96)
        record = cls(
            value_1=reader.u16("value_1"),
            value_2=reader.u16("value_2"),
        )
        reader.finish()
        return record

    def _validate(self) -> None:
        if self.opcode not in self.SUPPORTED_OPCODES:
            raise PacketShapeError(
                f"unsupported uint16-pair fixed-server opcode {self.opcode}"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack("<HHH", self.opcode, self.value_1, self.value_2)
        except struct.error as error:
            raise PacketShapeError(
                f"fixed-server uint16 pair is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class FixedServerU32PairRecord:
    value_1: int
    value_2: int
    opcode: int = 76

    SUPPORTED_OPCODES = {76}

    @classmethod
    def parse(cls, payload: bytes) -> "FixedServerU32PairRecord":
        reader = PacketReader(
            payload, packet_name="fixed_server_u32_pair_record"
        )
        opcode = reader.u16("opcode")
        record = cls(
            value_1=reader.u32("value_1"),
            value_2=reader.u32("value_2"),
            opcode=opcode,
        )
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode not in self.SUPPORTED_OPCODES:
            raise PacketShapeError(
                f"unsupported uint32-pair fixed-server opcode {self.opcode}"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack("<HII", self.opcode, self.value_1, self.value_2)
        except struct.error as error:
            raise PacketShapeError(
                f"fixed-server uint32 pair is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class FixedServerU64Record:
    opcode: int
    value: int

    SUPPORTED_OPCODES = {398}

    @classmethod
    def parse(cls, payload: bytes) -> "FixedServerU64Record":
        reader = PacketReader(payload, packet_name="fixed_server_u64_record")
        record = cls(opcode=reader.u16("opcode"), value=reader.u64("value"))
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode not in self.SUPPORTED_OPCODES:
            raise PacketShapeError(
                f"unsupported uint64 fixed-server opcode {self.opcode}"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack("<HQ", self.opcode, self.value)
        except struct.error as error:
            raise PacketShapeError(
                f"fixed-server uint64 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class FixedServerOpcode11Record:
    reserved_u32: int
    reserved_u8: int
    opcode: int = 11

    @classmethod
    def parse(cls, payload: bytes) -> "FixedServerOpcode11Record":
        reader = PacketReader(payload, packet_name="fixed_server_opcode_11")
        _expect_opcode(reader, 11)
        record = cls(
            reserved_u32=reader.u32("reserved_u32"),
            reserved_u8=reader.u8("reserved_u8"),
        )
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode != 11:
            raise PacketShapeError("fixed-server reserved opcode must be 11")
        if self.reserved_u32 != 0 or self.reserved_u8 != 0:
            raise PacketShapeError(
                "fixed-server opcode 11 reserved values must be zero"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        return struct.pack(
            "<HIB",
            self.opcode,
            self.reserved_u32,
            self.reserved_u8,
        )


@dataclass(frozen=True)
class InitialCharacterContextRecord:
    character_id: int
    context_flag: int
    reserved_u32s: tuple[int, int, int]
    opcode: int = 59

    @classmethod
    def parse(cls, payload: bytes) -> "InitialCharacterContextRecord":
        reader = PacketReader(payload, packet_name="initial_character_context")
        _expect_opcode(reader, 59)
        record = cls(
            character_id=reader.u32("character_id"),
            context_flag=reader.u8("context_flag"),
            reserved_u32s=(
                reader.u32("reserved_u32_1"),
                reader.u32("reserved_u32_2"),
                reader.u32("reserved_u32_3"),
            ),
        )
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opcode != 59:
            raise PacketShapeError("initial character context opcode must be 59")
        if self.context_flag != 1:
            raise PacketShapeError(
                "initial character context flag must match captured value one"
            )
        if self.reserved_u32s != (0, 0, 0):
            raise PacketShapeError(
                "initial character context reserved values must be zero"
            )

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack(
                "<HIBIII",
                self.opcode,
                self.character_id,
                self.context_flag,
                *self.reserved_u32s,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"initial character context field is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class VariableServerEntry:
    selector: int
    value: int

    def to_bytes(self) -> bytes:
        try:
            return struct.pack("<Bi", self.selector, self.value)
        except struct.error as error:
            raise PacketShapeError(
                f"variable-server entry field is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class VariableServerRecord:
    opcode: int
    variant: int
    opaque_tail: bytes = field(default=b"", repr=False)
    entries: tuple[VariableServerEntry, ...] = ()
    text: str | None = None
    flag: bool | None = None
    values: tuple[int, ...] = ()

    KEYBOARD_BINDING_COUNT = 89
    EMPTY_BINDING_SELECTOR = 0
    SKILL_BINDING_SELECTOR = 1
    ACTION_BINDING_SELECTOR = 5
    PICKUP_ACTION_ID = 50
    JUMP_ACTION_ID = 53
    NPC_INTERACTION_ACTION_ID = 54
    LEFT_CTRL_KEY_CODE = 29
    Z_KEY_CODE = 44
    LEFT_ALT_KEY_CODE = 56
    SPACE_KEY_CODE = 57
    KEYPAD_ZERO_KEY_CODE = 82

    @property
    def keyboard_skill_bindings(self) -> dict[int, int]:
        if self.opcode != 385 or self.variant:
            return {}
        return {
            key_code: entry.value
            for key_code, entry in enumerate(self.entries)
            if entry.selector == self.SKILL_BINDING_SELECTOR
        }

    @property
    def keyboard_action_bindings(self) -> dict[int, int]:
        if self.opcode != 385 or self.variant:
            return {}
        return {
            key_code: entry.value
            for key_code, entry in enumerate(self.entries)
            if entry.selector == self.ACTION_BINDING_SELECTOR
        }

    @property
    def pickup_key_codes(self) -> tuple[int, ...]:
        return tuple(
            key_code
            for key_code, action_id in self.keyboard_action_bindings.items()
            if action_id == self.PICKUP_ACTION_ID
        )

    @property
    def jump_key_codes(self) -> tuple[int, ...]:
        return tuple(
            key_code
            for key_code, action_id in self.keyboard_action_bindings.items()
            if action_id == self.JUMP_ACTION_ID
        )

    @property
    def npc_interaction_key_codes(self) -> tuple[int, ...]:
        return tuple(
            key_code
            for key_code, action_id in self.keyboard_action_bindings.items()
            if action_id == self.NPC_INTERACTION_ACTION_ID
        )

    @property
    def left_ctrl_skill_id(self) -> int | None:
        return self.keyboard_skill_bindings.get(self.LEFT_CTRL_KEY_CODE)

    @property
    def nonzero_keyboard_selector_count(self) -> int:
        if self.opcode != 385 or self.variant:
            return 0
        return sum(entry.selector != 0 for entry in self.entries)

    @property
    def empty_keyboard_binding_count(self) -> int:
        if self.opcode != 385 or self.variant:
            return 0
        return sum(
            entry.selector == self.EMPTY_BINDING_SELECTOR
            for entry in self.entries
        )

    @classmethod
    def parse(cls, payload: bytes) -> "VariableServerRecord":
        reader = PacketReader(payload, packet_name="variable_server_record")
        opcode = reader.u16("opcode")
        variant = reader.u8("variant")
        entries: tuple[VariableServerEntry, ...] = ()
        text = None
        flag = None
        values: tuple[int, ...] = ()
        opaque_tail = b""
        if opcode == 156 and variant in {0, 1}:
            if variant:
                text = reader.utf16_string("text", trailing_byte=True)
                flag_raw = reader.u8("flag")
                if flag_raw not in {0, 1}:
                    raise PacketShapeError(
                        "variable_server_record.flag is "
                        f"{flag_raw}, expected boolean 0 or 1"
                    )
                flag = bool(flag_raw)
                values = tuple(
                    reader.i32(f"values[{index}]") for index in range(3)
                )
        elif opcode == 385 and variant in {0, 1}:
            entry_count = (
                0 if variant else cls.KEYBOARD_BINDING_COUNT
            )
            entries = tuple(
                VariableServerEntry(
                    selector=reader.u8(f"entries[{index}].selector"),
                    value=reader.i32(f"entries[{index}].value"),
                )
                for index in range(entry_count)
            )
        else:
            opaque_tail = reader.bytes(reader.remaining, "opaque_tail")
        record = cls(
            opcode=opcode,
            variant=variant,
            opaque_tail=opaque_tail,
            entries=entries,
            text=text,
            flag=flag,
            values=values,
        )
        reader.finish()
        record._validate()
        return record

    def _validate(self) -> None:
        if self.opaque_tail:
            raise PacketShapeError(
                "variable-server records have typed fields, not an opaque tail"
            )
        if self.opcode == 156 and self.variant in {0, 1}:
            if self.entries:
                raise PacketShapeError(
                    "opcode 156 has scalar fields, not typed entries"
                )
            if not self.variant:
                if self.text is not None or self.flag is not None or self.values:
                    raise PacketShapeError(
                        "opcode 156 variant 0 has no scalar fields"
                    )
                return
            if self.text is None:
                raise PacketShapeError(
                    "opcode 156 variant 1 requires a UTF-16 text field"
                )
            if type(self.flag) is not bool:
                raise PacketShapeError(
                    "opcode 156 variant 1 requires a boolean flag"
                )
            if len(self.values) != 3:
                raise PacketShapeError(
                    "opcode 156 variant 1 requires exactly 3 int32 values"
                )
            encode_utf16_string(self.text, trailing_byte=True)
            try:
                struct.pack("<iii", *self.values)
            except struct.error as error:
                raise PacketShapeError(
                    "opcode 156 variant 1 values must fit int32"
                ) from error
            return
        if self.opcode == 385 and self.variant in {0, 1}:
            expected_entry_count = (
                0
                if self.variant
                else self.KEYBOARD_BINDING_COUNT
            )
            if self.text is not None or self.flag is not None or self.values:
                raise PacketShapeError(
                    "opcode 385 has typed entries, not scalar fields"
                )
            if len(self.entries) != expected_entry_count:
                raise PacketShapeError(
                    f"opcode 385 variant {self.variant} has "
                    f"{len(self.entries)} entries, expected "
                    f"{expected_entry_count}"
                )
            for entry in self.entries:
                entry.to_bytes()
            return
        raise PacketShapeError(
            "unsupported variable-server opcode/variant "
            f"{self.opcode}/{self.variant}"
        )

    def to_bytes(self) -> bytes:
        self._validate()
        if self.opcode == 156 and self.variant:
            if self.text is None or self.flag is None:
                raise PacketShapeError(
                    "opcode 156 variant 1 is missing typed fields"
                )
            body = b"".join(
                (
                    encode_utf16_string(self.text, trailing_byte=True),
                    struct.pack("<Biii", int(self.flag), *self.values),
                )
            )
        else:
            body = b"".join(entry.to_bytes() for entry in self.entries)
        return b"".join(
            (
                struct.pack("<HB", self.opcode, self.variant),
                body,
                self.opaque_tail,
            )
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
    opaque_tail: bytes = b""
    opcode: int = 158

    @classmethod
    def parse(cls, payload: bytes) -> "FieldLoadStage":
        reader = PacketReader(payload, packet_name="field_load_stage")
        _expect_opcode(reader, 158)
        stage = reader.u32("stage")
        trailing = reader.u32("trailing")
        opaque_tail = reader.bytes(reader.remaining, "opaque_tail")
        reader.finish()
        if stage not in {0, 1, 2}:
            raise PacketShapeError(
                f"field_load_stage.stage is {stage}, expected observed stage 0, 1, or 2"
            )
        if stage == 0 and trailing != 1:
            raise PacketShapeError(
                f"field_load_stage stage-0 trailing is {trailing}, expected 1"
            )
        if stage in {1, 2} and trailing != 0:
            raise PacketShapeError(
                f"field_load_stage stage-{stage} trailing is {trailing}, expected 0"
            )
        if stage == 0 and len(opaque_tail) != 9:
            raise PacketShapeError(
                "field_load_stage stage 0 requires the observed 9-byte tail"
            )
        if stage in {1, 2} and opaque_tail:
            raise PacketShapeError(
                "field_load_stage stages 1 and 2 cannot carry an opaque tail"
            )
        return cls(stage=stage, trailing=trailing, opaque_tail=opaque_tail)

    def to_bytes(self) -> bytes:
        if self.stage not in {0, 1, 2}:
            raise PacketShapeError("field load stage must be 0, 1, or 2")
        if self.stage == 0 and self.trailing != 1:
            raise PacketShapeError("field load stage-0 trailing value must be one")
        if self.stage in {1, 2} and self.trailing != 0:
            raise PacketShapeError(
                "field load stage-1/stage-2 trailing value must be zero"
            )
        if self.stage == 0 and len(self.opaque_tail) != 9:
            raise PacketShapeError(
                "field load stage 0 requires the observed 9-byte tail"
            )
        if self.stage in {1, 2} and self.opaque_tail:
            raise PacketShapeError(
                "field load stages 1 and 2 cannot carry an opaque tail"
            )
        return (
            struct.pack("<HII", self.opcode, self.stage, self.trailing)
            + self.opaque_tail
        )


@dataclass(frozen=True)
class ClientOpcode309Acknowledgement:
    """Exact empty acknowledgement sent after server opcode 426."""

    opcode: int = 309

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode309Acknowledgement":
        reader = PacketReader(
            payload, packet_name="client_opcode_309_acknowledgement"
        )
        _expect_opcode(reader, 309)
        reader.finish()
        return cls()

    def to_bytes(self) -> bytes:
        return struct.pack("<H", self.opcode)


@dataclass(frozen=True)
class SkillRecordUpdateAcknowledgement:
    control_value: int
    client_tick: int
    trailing_value: int
    opcode: int = 293

    @classmethod
    def parse(cls, payload: bytes) -> "SkillRecordUpdateAcknowledgement":
        reader = PacketReader(
            payload, packet_name="skill_record_update_acknowledgement"
        )
        _expect_opcode(reader, 293)
        acknowledgement = cls(
            control_value=reader.u32("control_value"),
            client_tick=reader.u32("client_tick"),
            trailing_value=reader.u16("trailing_value"),
        )
        reader.finish()
        return acknowledgement

    def safe_dict(self) -> dict[str, int]:
        return {
            "control_value": self.control_value,
            "client_tick": self.client_tick,
            "trailing_value": self.trailing_value,
        }

    def to_bytes(self) -> bytes:
        try:
            return struct.pack(
                "<HIIH",
                self.opcode,
                self.control_value,
                self.client_tick,
                self.trailing_value,
            )
        except struct.error as error:
            raise PacketShapeError(
                "skill record update acknowledgement field is out of range: "
                f"{error}"
            ) from error


ABILITY_POINT_ALLOCATION_STAT_NAMES = {
    CharacterStatUpdate.STRENGTH: "strength",
    CharacterStatUpdate.DEXTERITY: "dexterity",
    CharacterStatUpdate.INTELLIGENCE: "intelligence",
    CharacterStatUpdate.LUCK: "luck",
}


@dataclass(frozen=True)
class AbilityPointAllocationEntry:
    """One stat-mask/increment pair from a client allocation request."""

    stat_mask: int
    increment: int

    @property
    def stat_name(self) -> str:
        try:
            return ABILITY_POINT_ALLOCATION_STAT_NAMES[self.stat_mask]
        except KeyError as error:
            raise PacketShapeError(
                "ability-point allocation stat mask is unsupported: "
                f"0x{self.stat_mask:08x}"
            ) from error

    def _validate(self) -> None:
        _ = self.stat_name
        if not 0 <= self.increment <= 0xFFFF_FFFF:
            raise PacketShapeError(
                "ability-point allocation increment must fit u32"
            )

    def safe_dict(self) -> dict[str, int | str]:
        self._validate()
        return {
            "stat": self.stat_name,
            "stat_mask": f"0x{self.stat_mask:08x}",
            "increment": self.increment,
        }


@dataclass(frozen=True)
class ClientAbilityPointAllocationRequest:
    """Client opcode-100 request allocating AP across base attributes."""

    client_tick: int
    allocations: tuple[AbilityPointAllocationEntry, ...]
    opcode: int = 100

    @classmethod
    def parse(cls, payload: bytes) -> "ClientAbilityPointAllocationRequest":
        reader = PacketReader(
            payload, packet_name="ability_point_allocation_request"
        )
        _expect_opcode(reader, 100)
        client_tick = reader.u32("client_tick")
        allocation_count = reader.u32("allocation_count")
        if not 1 <= allocation_count <= len(
            ABILITY_POINT_ALLOCATION_STAT_NAMES
        ):
            raise PacketShapeError(
                "ability-point allocation count must be between one and four"
            )
        if reader.remaining != allocation_count * 8:
            raise PacketShapeError(
                "ability-point allocation count does not match packet length"
            )
        allocations = tuple(
            AbilityPointAllocationEntry(
                stat_mask=reader.u32(f"allocation[{index}].stat_mask"),
                increment=reader.u32(f"allocation[{index}].increment"),
            )
            for index in range(allocation_count)
        )
        reader.finish()
        request = cls(client_tick=client_tick, allocations=allocations)
        request._validate()
        return request

    def _validate(self) -> None:
        if self.opcode != 100:
            raise PacketShapeError(
                "ability-point allocation request opcode must be 100"
            )
        if not 0 <= self.client_tick <= 0xFFFF_FFFF:
            raise PacketShapeError(
                "ability-point allocation client tick must fit u32"
            )
        if not 1 <= len(self.allocations) <= len(
            ABILITY_POINT_ALLOCATION_STAT_NAMES
        ):
            raise PacketShapeError(
                "ability-point allocation count must be between one and four"
            )
        seen_masks: set[int] = set()
        for allocation in self.allocations:
            allocation._validate()
            if allocation.stat_mask in seen_masks:
                raise PacketShapeError(
                    "ability-point allocation stat masks must be unique"
                )
            seen_masks.add(allocation.stat_mask)
        if self.total_increment == 0:
            raise PacketShapeError(
                "ability-point allocation request must spend at least one point"
            )

    @property
    def total_increment(self) -> int:
        return sum(allocation.increment for allocation in self.allocations)

    def safe_dict(self) -> dict[str, object]:
        self._validate()
        return {
            "client_tick": self.client_tick,
            "allocation_count": len(self.allocations),
            "allocations": [
                allocation.safe_dict() for allocation in self.allocations
            ],
            "total_increment": self.total_increment,
        }

    def to_bytes(self) -> bytes:
        self._validate()
        return b"".join(
            (
                struct.pack(
                    "<HII", self.opcode, self.client_tick, len(self.allocations)
                ),
                *(
                    struct.pack(
                        "<II", allocation.stat_mask, allocation.increment
                    )
                    for allocation in self.allocations
                ),
            )
        )


@dataclass(frozen=True)
class ClientOpcode307NeutralRecord:
    """Cross-capture three-word record with redacted neutral values."""

    neutral_value: int = field(repr=False)
    redacted_value: int = field(repr=False)
    opcode: int = 307

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode307NeutralRecord":
        reader = PacketReader(payload, packet_name="client_opcode_307_neutral")
        _expect_opcode(reader, 307)
        neutral_value = reader.u32("neutral_value")
        redacted_value = reader.u32("redacted_value")
        if reader.u32("reserved_zero") != 0:
            raise PacketShapeError(
                "client opcode-307 reserved trailer must be zero"
            )
        reader.finish()
        return cls(
            neutral_value=neutral_value,
            redacted_value=redacted_value,
        )

    def safe_dict(self) -> dict[str, object]:
        return {
            "neutral_value_redacted": True,
            "redacted_value_redacted": True,
            "redacted_value_zero": self.redacted_value == 0,
            "reserved_zero": True,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 307:
            raise PacketShapeError("neutral record opcode must be 307")
        for name, value in (
            ("neutral", self.neutral_value),
            ("redacted", self.redacted_value),
        ):
            if not 0 <= value <= 0xFFFF_FFFF:
                raise PacketShapeError(
                    f"client opcode-307 {name} value must fit u32"
                )
        return struct.pack(
            "<HIII", self.opcode, self.neutral_value, self.redacted_value, 0
        )


@dataclass(frozen=True)
class ClientOpcode310TextRecord:
    """Counted UTF-16 client record whose text and purpose stay redacted."""

    redacted_text: str = field(repr=False)
    opcode: int = 310

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode310TextRecord":
        reader = PacketReader(payload, packet_name="client_opcode_310_text")
        _expect_opcode(reader, 310)
        redacted_text = reader.utf16_string(
            "redacted_text", trailing_byte=False
        )
        if reader.u32("reserved_zero_u32") != 0:
            raise PacketShapeError(
                "client opcode-310 reserved u32 must be zero"
            )
        if reader.u8("reserved_zero_u8") != 0:
            raise PacketShapeError(
                "client opcode-310 reserved u8 must be zero"
            )
        reader.finish()
        return cls(redacted_text=redacted_text)

    @property
    def text_code_units(self) -> int:
        return len(self.redacted_text.encode("utf-16-le")) // 2

    def safe_dict(self) -> dict[str, object]:
        return {
            "text_code_units": self.text_code_units,
            "text_redacted": True,
            "reserved_zero_u32": True,
            "reserved_zero_u8": True,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 310:
            raise PacketShapeError("text record opcode must be 310")
        try:
            encoded = self.redacted_text.encode("utf-16-le")
        except UnicodeEncodeError as error:
            raise PacketShapeError(
                "client opcode-310 text is not valid UTF-16"
            ) from error
        code_units = len(encoded) // 2
        if code_units > 0xFFFF:
            raise PacketShapeError(
                "client opcode-310 text exceeds the u16 code-unit count"
            )
        return (
            struct.pack("<HH", self.opcode, code_units)
            + encoded
            + struct.pack("<IB", 0, 0)
        )


@dataclass(frozen=True)
class ClientOpcode308PeriodicRecord:
    """Cross-capture typed periodic record with neutral numeric values."""

    neutral_f64_values: tuple[float, float] = field(repr=False)
    neutral_u64_values: tuple[int, int] = field(repr=False)
    mirrored_value: int
    variant: int
    opcode: int = 308

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode308PeriodicRecord":
        reader = PacketReader(payload, packet_name="client_opcode_308_periodic")
        _expect_opcode(reader, 308)
        neutral_f64_values = tuple(
            struct.unpack("<d", reader.bytes(8, f"neutral_f64[{index}]"))[0]
            for index in range(2)
        )
        neutral_u64_values = tuple(
            reader.u64(f"neutral_u64[{index}]") for index in range(2)
        )
        mirrored_value = reader.u32("mirrored_value")
        if reader.u32("constant_50") != 50:
            raise PacketShapeError("client opcode-308 constant_50 must be 50")
        if reader.u32("constant_1_a") != 1:
            raise PacketShapeError("client opcode-308 constant_1_a must be 1")
        variant = reader.u32("variant")
        mirrored_f64_values = tuple(
            struct.unpack("<d", reader.bytes(8, f"mirrored_f64[{index}]"))[0]
            for index in range(2)
        )
        if reader.u32("constant_1_b") != 1:
            raise PacketShapeError("client opcode-308 constant_1_b must be 1")
        if reader.u32("reserved_zero") != 0:
            raise PacketShapeError(
                "client opcode-308 reserved trailer must be zero"
            )
        reader.finish()
        record = cls(
            neutral_f64_values=neutral_f64_values,
            neutral_u64_values=neutral_u64_values,
            mirrored_value=mirrored_value,
            variant=variant,
        )
        record._validate(mirrored_f64_values=mirrored_f64_values)
        return record

    def _validate(
        self, *, mirrored_f64_values: tuple[float, float] | None = None
    ) -> None:
        if self.opcode != 308:
            raise PacketShapeError("periodic record opcode must be 308")
        if len(self.neutral_f64_values) != 2 or not all(
            math.isfinite(value) for value in self.neutral_f64_values
        ):
            raise PacketShapeError(
                "client opcode-308 requires two finite neutral doubles"
            )
        if len(self.neutral_u64_values) != 2 or any(
            not 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF
            for value in self.neutral_u64_values
        ):
            raise PacketShapeError(
                "client opcode-308 requires two neutral u64 values"
            )
        if not 0 <= self.mirrored_value <= 0xFFFF_FFFF:
            raise PacketShapeError(
                "client opcode-308 mirrored value must fit u32"
            )
        if self.variant not in {0, 1}:
            raise PacketShapeError(
                "client opcode-308 variant must be zero or one"
            )
        expected_mirror = (float(self.mirrored_value),) * 2
        if (
            mirrored_f64_values is not None
            and mirrored_f64_values != expected_mirror
        ):
            raise PacketShapeError(
                "client opcode-308 doubles do not mirror the u32 value"
            )

    def safe_dict(self) -> dict[str, object]:
        return {
            "neutral_f64_values": 2,
            "neutral_f64_values_redacted": True,
            "neutral_u64_values": 2,
            "neutral_u64_values_redacted": True,
            "mirrored_value": self.mirrored_value,
            "mirrored_double_copies": 2,
            "variant": self.variant,
            "fixed_controls": [50, 1, 1, 0],
        }

    def to_bytes(self) -> bytes:
        self._validate()
        mirror = float(self.mirrored_value)
        try:
            return struct.pack(
                "<H2d2Q4I2d2I",
                self.opcode,
                *self.neutral_f64_values,
                *self.neutral_u64_values,
                self.mirrored_value,
                50,
                1,
                self.variant,
                mirror,
                mirror,
                1,
                0,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"client opcode-308 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ClientOpcode311PeriodicRecord:
    """Cross-capture zero-bounded periodic u32 record."""

    neutral_value: int = field(repr=False)
    opcode: int = 311

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode311PeriodicRecord":
        reader = PacketReader(payload, packet_name="client_opcode_311_periodic")
        _expect_opcode(reader, 311)
        if reader.u64("reserved_prefix") != 0:
            raise PacketShapeError(
                "client opcode-311 reserved prefix must be zero"
            )
        neutral_value = reader.u32("neutral_value")
        if reader.u64("reserved_suffix") != 0:
            raise PacketShapeError(
                "client opcode-311 reserved suffix must be zero"
            )
        reader.finish()
        return cls(neutral_value=neutral_value)

    def safe_dict(self) -> dict[str, object]:
        return {
            "reserved_prefix_zero": True,
            "neutral_value_width_bits": 32,
            "neutral_value_redacted": True,
            "reserved_suffix_zero": True,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 311:
            raise PacketShapeError("periodic record opcode must be 311")
        if not 0 <= self.neutral_value <= 0xFFFF_FFFF:
            raise PacketShapeError(
                "client opcode-311 neutral value must fit u32"
            )
        return struct.pack("<HQIQ", self.opcode, 0, self.neutral_value, 0)


@dataclass(frozen=True)
class ClientOpcode75EmptyRecord:
    """Exact empty client marker observed during field bootstrap."""

    opcode: int = 75

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode75EmptyRecord":
        reader = PacketReader(payload, packet_name="client_opcode_75_empty")
        _expect_opcode(reader, 75)
        reader.finish()
        return cls()

    def to_bytes(self) -> bytes:
        if self.opcode != 75:
            raise PacketShapeError("client empty-record opcode must be 75")
        return struct.pack("<H", self.opcode)


@dataclass(frozen=True)
class ClientWorldExitRequest:
    """Exact empty client marker correlated with terminal server opcode 9."""

    opcode: int = 241

    @classmethod
    def parse(cls, payload: bytes) -> "ClientWorldExitRequest":
        reader = PacketReader(payload, packet_name="client_world_exit_request")
        _expect_opcode(reader, 241)
        reader.finish()
        return cls()

    def to_bytes(self) -> bytes:
        if self.opcode != 241:
            raise PacketShapeError("world-exit request opcode must be 241")
        return struct.pack("<H", self.opcode)


@dataclass(frozen=True)
class ClientWorldExitStatus:
    """Redacted four-byte status sent between exit request and termination."""

    value: int = field(repr=False)
    opcode: int

    @classmethod
    def parse(cls, payload: bytes) -> "ClientWorldExitStatus":
        reader = PacketReader(payload, packet_name="client_world_exit_status")
        opcode = reader.u16("opcode")
        if opcode not in {45, 46}:
            raise PacketShapeError(
                f"world-exit status opcode must be 45 or 46, got {opcode}"
            )
        value = reader.u32("value")
        reader.finish()
        return cls(value=value, opcode=opcode)

    def safe_dict(self) -> dict[str, object]:
        return {
            "status_opcode": self.opcode,
            "value_redacted": True,
        }

    def to_bytes(self) -> bytes:
        if self.opcode not in {45, 46}:
            raise PacketShapeError(
                f"world-exit status opcode must be 45 or 46, got {self.opcode}"
            )
        try:
            return struct.pack("<HI", self.opcode, self.value)
        except struct.error as error:
            raise PacketShapeError(
                f"world-exit status value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode394TextEnvelope:
    """One redacted counted-text envelope correlated with client opcode 279."""

    text: str = field(repr=False)
    opcode: int = 394

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode394TextEnvelope":
        reader = PacketReader(payload, packet_name="server_opcode_394_text")
        _expect_opcode(reader, 394)
        text = reader.utf16_string("text", trailing_byte=True)
        reader.finish()
        return cls(text=text)

    @property
    def text_code_units(self) -> int:
        return len(self.text.encode("utf-16le")) // 2

    def safe_dict(self) -> dict[str, object]:
        return {
            "text_code_units": self.text_code_units,
            "text_redacted": True,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 394:
            raise PacketShapeError("server text envelope opcode must be 394")
        return struct.pack("<H", self.opcode) + encode_utf16_string(
            self.text,
            trailing_byte=True,
        )


@dataclass(frozen=True)
class ClientOpcode276RecordGroup:
    """Redacted counted pair group inside client opcode 276 selector 24."""

    selector: int = field(repr=False)
    pairs: tuple[tuple[int, int], ...] = field(repr=False)

    @classmethod
    def parse(
        cls, reader: PacketReader, *, group_index: int
    ) -> "ClientOpcode276RecordGroup":
        selector = reader.u32(f"groups[{group_index}].selector")
        pair_count = reader.u32(f"groups[{group_index}].pair_count")
        if pair_count > 1024:
            raise PacketShapeError(
                f"client opcode-276 group {group_index} pair count "
                f"{pair_count} exceeds 1024"
            )
        return cls(
            selector=selector,
            pairs=tuple(
                (
                    reader.u32(
                        f"groups[{group_index}].pairs[{pair_index}].value_1"
                    ),
                    reader.u32(
                        f"groups[{group_index}].pairs[{pair_index}].value_2"
                    ),
                )
                for pair_index in range(pair_count)
            ),
        )

    def to_bytes(self) -> bytes:
        if len(self.pairs) > 1024:
            raise PacketShapeError(
                "client opcode-276 group cannot contain more than 1024 pairs"
            )
        try:
            return struct.pack("<II", self.selector, len(self.pairs)) + b"".join(
                struct.pack("<II", value_1, value_2)
                for value_1, value_2 in self.pairs
            )
        except struct.error as error:
            raise PacketShapeError(
                f"client opcode-276 group value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ClientOpcode276Envelope:
    """Capture-bounded compact or grouped client opcode-276 envelope."""

    selector: int
    header_value_1: int | None = field(repr=False)
    header_value_2: int | None = field(repr=False)
    groups: tuple[ClientOpcode276RecordGroup, ...] = field(repr=False)
    compact_reserved: bytes = field(repr=False)
    opcode: int = 276

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode276Envelope":
        reader = PacketReader(payload, packet_name="client_opcode_276_envelope")
        _expect_opcode(reader, 276)
        selector = reader.u32("selector")
        if selector == 17:
            envelope = cls(
                selector=selector,
                header_value_1=None,
                header_value_2=None,
                groups=(),
                compact_reserved=reader.bytes(3, "compact_reserved"),
            )
        elif selector == 24:
            header_value_1 = reader.u32("header_value_1")
            header_value_2 = reader.u32("header_value_2")
            group_count = reader.u32("group_count")
            if group_count > 64:
                raise PacketShapeError(
                    f"client opcode-276 group count {group_count} exceeds 64"
                )
            envelope = cls(
                selector=selector,
                header_value_1=header_value_1,
                header_value_2=header_value_2,
                groups=tuple(
                    ClientOpcode276RecordGroup.parse(
                        reader, group_index=group_index
                    )
                    for group_index in range(group_count)
                ),
                compact_reserved=b"",
            )
        else:
            raise PacketShapeError(
                f"client opcode-276 selector is {selector}, expected 17 or 24"
            )
        reader.finish()
        envelope._validate()
        return envelope

    def _validate(self) -> None:
        if self.opcode != 276:
            raise PacketShapeError("client opcode-276 envelope opcode must be 276")
        if self.selector == 17:
            if self.header_value_1 is not None or self.header_value_2 is not None:
                raise PacketShapeError(
                    "client opcode-276 selector 17 cannot include header values"
                )
            if self.groups:
                raise PacketShapeError(
                    "client opcode-276 selector 17 cannot include groups"
                )
            if self.compact_reserved != b"\x00\x00\x00":
                raise PacketShapeError(
                    "client opcode-276 selector 17 reserved bytes must be zero"
                )
            return
        if self.selector != 24:
            raise PacketShapeError(
                f"client opcode-276 selector is {self.selector}, expected 17 or 24"
            )
        if self.header_value_1 is None or self.header_value_2 is None:
            raise PacketShapeError(
                "client opcode-276 selector 24 requires both header values"
            )
        if not self.groups or len(self.groups) > 64:
            raise PacketShapeError(
                "client opcode-276 selector 24 requires one through 64 groups"
            )
        if self.compact_reserved:
            raise PacketShapeError(
                "client opcode-276 selector 24 cannot include compact bytes"
            )

    @property
    def shape_name(self) -> str:
        return "compact" if self.selector == 17 else "grouped"

    @property
    def pair_count(self) -> int:
        return sum(len(group.pairs) for group in self.groups)

    def safe_dict(self) -> dict[str, object]:
        return {
            "selector": self.selector,
            "shape": self.shape_name,
            "group_count": len(self.groups),
            "pair_count": self.pair_count,
            "group_pair_counts": [len(group.pairs) for group in self.groups],
            "compact_reserved_zero": (
                self.compact_reserved == b"\x00\x00\x00"
                if self.selector == 17
                else None
            ),
            "header_and_record_values_redacted": True,
        }

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            prefix = struct.pack("<HI", self.opcode, self.selector)
            if self.selector == 17:
                return prefix + self.compact_reserved
            assert self.header_value_1 is not None
            assert self.header_value_2 is not None
            return (
                prefix
                + struct.pack(
                    "<III",
                    self.header_value_1,
                    self.header_value_2,
                    len(self.groups),
                )
                + b"".join(group.to_bytes() for group in self.groups)
            )
        except struct.error as error:
            raise PacketShapeError(
                f"client opcode-276 envelope value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ClientOpcode279TextEnvelope:
    """Redacted counted-text envelope correlated with server opcode 394."""

    control_value: int
    text: str = field(repr=False)
    opcode: int = 279

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode279TextEnvelope":
        reader = PacketReader(payload, packet_name="client_opcode_279_text")
        _expect_opcode(reader, 279)
        control_value = reader.u8("control_value")
        text = reader.utf16_string("text", trailing_byte=True)
        reader.finish()
        return cls(control_value=control_value, text=text)

    @property
    def text_code_units(self) -> int:
        return len(self.text.encode("utf-16le")) // 2

    def changed_code_unit_indices(self, source_text: str) -> tuple[int, ...]:
        source = source_text.encode("utf-16le")
        response = self.text.encode("utf-16le")
        source_units = tuple(
            source[offset : offset + 2] for offset in range(0, len(source), 2)
        )
        response_units = tuple(
            response[offset : offset + 2]
            for offset in range(0, len(response), 2)
        )
        shared_count = min(len(source_units), len(response_units))
        changed = [
            index
            for index in range(shared_count)
            if source_units[index] != response_units[index]
        ]
        changed.extend(
            range(shared_count, max(len(source_units), len(response_units)))
        )
        return tuple(changed)

    def safe_dict(self) -> dict[str, object]:
        return {
            "control_value": self.control_value,
            "text_code_units": self.text_code_units,
            "text_redacted": True,
        }

    def to_bytes(self) -> bytes:
        if self.opcode != 279:
            raise PacketShapeError("client text response opcode must be 279")
        try:
            prefix = struct.pack("<HB", self.opcode, self.control_value)
        except struct.error as error:
            raise PacketShapeError(
                f"client opcode-279 control is out of range: {error}"
            ) from error
        return prefix + encode_utf16_string(self.text, trailing_byte=True)


@dataclass(frozen=True)
class ClientOpcode298ItemAcquisitionRequest:
    """Capture-bounded item request followed by inventory additions."""

    control_value: int
    selection_index: int
    request_kind: int
    item_id: int
    quantity: int
    duration_value: int
    expires_at_ticks: int
    serial_value: int = field(repr=False)
    reserved_values: tuple[int, int, int, int, int]
    signed_sentinel_values: tuple[int, int]
    trailing_values: tuple[int, int]
    flag_1: int
    flag_2: int
    opcode: int = 298

    REQUEST_INVENTORY_NAMES = {1: "use", 2: "cash"}

    @classmethod
    def parse(cls, payload: bytes) -> "ClientOpcode298ItemAcquisitionRequest":
        reader = PacketReader(
            payload, packet_name="client_opcode_298_item_acquisition_request"
        )
        _expect_opcode(reader, 298)
        request = cls(
            control_value=reader.u32("control_value"),
            selection_index=reader.u32("selection_index"),
            request_kind=reader.u32("request_kind"),
            item_id=reader.u32("item_id"),
            quantity=reader.u32("quantity"),
            duration_value=reader.u32("duration_value"),
            expires_at_ticks=reader.u64("expires_at_ticks"),
            serial_value=reader.u32("serial_value"),
            reserved_values=tuple(
                reader.u32(f"reserved_value_{index + 1}")
                for index in range(5)
            ),
            signed_sentinel_values=(
                reader.i32("signed_sentinel_1"),
                reader.i32("signed_sentinel_2"),
            ),
            trailing_values=(
                reader.u32("trailing_value_1"),
                reader.u32("trailing_value_2"),
            ),
            flag_1=reader.u8("flag_1"),
            flag_2=reader.u8("flag_2"),
        )
        reader.finish()
        request._validate()
        return request

    def _validate(self) -> None:
        if self.opcode != 298:
            raise PacketShapeError(
                "client item-acquisition request opcode must be 298"
            )
        if self.control_value != 0:
            raise PacketShapeError(
                "client opcode-298 control value must be zero"
            )
        if self.selection_index <= 0:
            raise PacketShapeError(
                "client opcode-298 selection index must be positive"
            )
        if self.request_kind not in self.REQUEST_INVENTORY_NAMES:
            raise PacketShapeError(
                "client opcode-298 request kind must be one or two"
            )
        if self.item_id <= 0 or self.quantity <= 0:
            raise PacketShapeError(
                "client opcode-298 item id and quantity must be positive"
            )
        if self.expires_at_ticks != PERMANENT_ITEM_EXPIRATION_TICKS:
            raise PacketShapeError(
                "client opcode-298 expiration must use the captured sentinel"
            )
        if self.reserved_values != (0, 0, 0, 0, 0):
            raise PacketShapeError(
                "client opcode-298 reserved values must be zero"
            )
        if self.signed_sentinel_values != (-99, -99):
            raise PacketShapeError(
                "client opcode-298 signed sentinels must both be -99"
            )
        if self.trailing_values != (0, 0):
            raise PacketShapeError(
                "client opcode-298 trailing values must be zero"
            )
        if (self.flag_1, self.flag_2) != (0, 1):
            raise PacketShapeError(
                "client opcode-298 flags must match the captured 0/1 pair"
            )

    @property
    def inventory_name(self) -> str:
        return self.REQUEST_INVENTORY_NAMES[self.request_kind]

    def safe_dict(self) -> dict[str, object]:
        return {
            "control_value": self.control_value,
            "selection_index": self.selection_index,
            "inventory": self.inventory_name,
            "request_kind": self.request_kind,
            "item_id": self.item_id,
            "quantity": self.quantity,
            "duration_value": self.duration_value,
            "expiration_is_sentinel": True,
            "serial_value_present": self.serial_value != 0,
            "serial_value_redacted": True,
            "reserved_values_zero": True,
            "signed_sentinel_values": list(self.signed_sentinel_values),
            "trailing_values": list(self.trailing_values),
            "flags": [self.flag_1, self.flag_2],
        }

    def to_bytes(self) -> bytes:
        self._validate()
        try:
            return struct.pack(
                "<HIIIIIIQI5IiiIIBB",
                self.opcode,
                self.control_value,
                self.selection_index,
                self.request_kind,
                self.item_id,
                self.quantity,
                self.duration_value,
                self.expires_at_ticks,
                self.serial_value,
                *self.reserved_values,
                *self.signed_sentinel_values,
                *self.trailing_values,
                self.flag_1,
                self.flag_2,
            )
        except struct.error as error:
            raise PacketShapeError(
                f"client opcode-298 value is out of range: {error}"
            ) from error


@dataclass(frozen=True)
class ServerOpcode426Notification:
    """Exact empty notification acknowledged by client opcode 309."""

    opcode: int = 426

    @classmethod
    def parse(cls, payload: bytes) -> "ServerOpcode426Notification":
        reader = PacketReader(
            payload, packet_name="server_opcode_426_notification"
        )
        _expect_opcode(reader, 426)
        reader.finish()
        return cls()

    def to_bytes(self) -> bytes:
        return struct.pack("<H", self.opcode)


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
