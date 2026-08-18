"""Reproduce the client's opcode-13/subtype-1 security envelope.

Native source addresses are for GameAssembly.dll SHA-256
6f2a93efc0f16f30685c902134ecc79ad67fe384f345f503fa688658acbddeea:

* VA 0x181CD62A0 (RVA 0x1CD62A0): the pre-send producer.  It checks
  ``uint16(send_iv) % 31``, hashes ``BitConverter.GetBytes(uint16(send_iv))``,
  and sends opcode 13, subtype 1, the hash, and a zero uint32.
* VA 0x181C96BF0 (RVA 0x1C96BF0): the native CRC helper emulated here.
* VA 0x181C98C50 (RVA 0x1C98C50): the helper's static constructor, which
  installs the non-reflected CRC-32 table for polynomial 0x04C11DB7.

The value is a deterministic function of the current outbound Maple cipher IV;
it is not a response derived from an inbound server packet.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
from typing import Any


SUPPORTED_GAME_ASSEMBLY_SHA256 = (
    "6f2a93efc0f16f30685c902134ecc79ad67fe384f345f503fa688658acbddeea"
)
CRC_POLYNOMIAL = 0x04C11DB7
TYPE1_OPCODE = 13
TYPE1_SUBTYPE = 1
TYPE1_PERIOD = 31

# Original native addresses used by the Unicorn harness.
CRC_HELPER_VA = 0x181C96BF0
TYPE_INFO_SLOT_VA = 0x186966520
TYPE_INITIALIZED_GUARD_VA = 0x186EDF895

_PAGE_SIZE = 0x1000
_FAKE_BASE = 0x70000000
_FAKE_SIZE = 0x10000
_STACK_BASE = 0x71000000
_STACK_SIZE = 0x20000
_STOP_ADDRESS = 0x72000000
_FAKE_CLASS = _FAKE_BASE + 0x100
_FAKE_STATIC_FIELDS = _FAKE_BASE + 0x400
_FAKE_CRC_TABLE = _FAKE_BASE + 0x1000
_FAKE_INPUT_ARRAY = _FAKE_BASE + 0x3000


def _align_page(value: int) -> int:
    return (value + _PAGE_SIZE - 1) & -_PAGE_SIZE


def _iv_bytes(iv: bytes | bytearray | int) -> bytes:
    if isinstance(iv, int):
        if not 0 <= iv <= 0xFFFFFFFF:
            raise ValueError("IV integer must fit in uint32")
        return iv.to_bytes(4, "little")
    value = bytes(iv)
    if len(value) != 4:
        raise ValueError(f"Maple IV must be four bytes, got {len(value)}")
    return value


def security_type1_triggered(iv: bytes | bytearray | int) -> bool:
    """Return whether the pre-send hook emits subtype 1 for this IV."""
    value = _iv_bytes(iv)
    return int.from_bytes(value[:2], "little") % TYPE1_PERIOD == 0


def crc32_mpeg2_raw(data: bytes, seed: int = 0) -> int:
    """Compute the native helper's non-reflected, zero-xor CRC-32."""
    crc = seed & 0xFFFFFFFF
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            top_bit = crc & 0x80000000
            crc = (crc << 1) & 0xFFFFFFFF
            if top_bit:
                crc ^= CRC_POLYNOMIAL
    return crc


def security_type1_value(iv: bytes | bytearray | int) -> int:
    """Reference value for an IV, independent of Unicorn."""
    value = _iv_bytes(iv)
    return crc32_mpeg2_raw(value[:2])


def build_security_type1_packet(
    iv: bytes | bytearray | int, *, value: int | None = None
) -> bytes:
    """Build the 11-byte plaintext envelope for the supplied outbound IV."""
    result = security_type1_value(iv) if value is None else value
    if not 0 <= result <= 0xFFFFFFFF:
        raise ValueError("security value must fit in uint32")
    return struct.pack("<HBII", TYPE1_OPCODE, TYPE1_SUBTYPE, result, 0)


def _crc_table() -> bytes:
    entries: list[bytes] = []
    for index in range(256):
        value = index << 24
        for _ in range(8):
            top_bit = value & 0x80000000
            value = (value << 1) & 0xFFFFFFFF
            if top_bit:
                value ^= CRC_POLYNOMIAL
        entries.append(struct.pack("<I", value))
    return b"".join(entries)


@dataclass(frozen=True)
class _PeImage:
    image_base: int
    image_size: int
    header_size: int
    sections: tuple[tuple[int, int, int], ...]

    @classmethod
    def parse(cls, data: bytes) -> "_PeImage":
        if data[:2] != b"MZ":
            raise ValueError("GameAssembly.dll is not a PE image")
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ValueError("GameAssembly.dll has no PE signature")
        coff = pe_offset + 4
        section_count = struct.unpack_from("<H", data, coff + 2)[0]
        optional_size = struct.unpack_from("<H", data, coff + 16)[0]
        optional = coff + 20
        if struct.unpack_from("<H", data, optional)[0] != 0x20B:
            raise ValueError("GameAssembly.dll is not PE32+")
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
        image_size = struct.unpack_from("<I", data, optional + 56)[0]
        header_size = struct.unpack_from("<I", data, optional + 60)[0]
        table = optional + optional_size
        sections: list[tuple[int, int, int]] = []
        for index in range(section_count):
            offset = table + index * 40
            virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<III", data, offset + 12
            )
            if raw_offset + raw_size > len(data):
                raise ValueError("PE section extends beyond GameAssembly.dll")
            sections.append((virtual_address, raw_offset, raw_size))
        return cls(
            image_base=image_base,
            image_size=image_size,
            header_size=header_size,
            sections=tuple(sections),
        )


class SecurityType1Unicorn:
    """Long-lived Unicorn instance around the original native CRC helper."""

    def __init__(self, game_assembly: str | Path) -> None:
        try:
            from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
        except ImportError as error:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "The Unicorn package is required; install project requirements"
            ) from error

        self.game_assembly = Path(game_assembly)
        image = self.game_assembly.read_bytes()
        digest = hashlib.sha256(image).hexdigest()
        if digest != SUPPORTED_GAME_ASSEMBLY_SHA256:
            raise ValueError(
                "unsupported GameAssembly.dll SHA-256: "
                f"{digest}; expected {SUPPORTED_GAME_ASSEMBLY_SHA256}"
            )
        pe = _PeImage.parse(image)
        self._uc: Any = Uc(UC_ARCH_X86, UC_MODE_64)
        self._uc.mem_map(pe.image_base, _align_page(pe.image_size))
        self._uc.mem_write(pe.image_base, image[: pe.header_size])
        for virtual_address, raw_offset, raw_size in pe.sections:
            if raw_size:
                self._uc.mem_write(
                    pe.image_base + virtual_address,
                    image[raw_offset : raw_offset + raw_size],
                )
        self._uc.mem_map(_FAKE_BASE, _FAKE_SIZE)
        self._uc.mem_map(_STACK_BASE, _STACK_SIZE)
        self._uc.mem_map(_STOP_ADDRESS, _PAGE_SIZE)
        self._install_managed_state()

    def _install_managed_state(self) -> None:
        """Install the IL2CPP objects the native helper dereferences.

        The offsets are visible in the original helper at VA 0x181C97AFD and
        its short-input loop near VA 0x181C98865: Il2CppClass.static_fields is
        at +0xB8 and array length/data are at +0x18/+0x20.
        """
        self._uc.mem_write(
            _FAKE_CLASS + 0xB8, struct.pack("<Q", _FAKE_STATIC_FIELDS)
        )
        self._uc.mem_write(_FAKE_CLASS + 0xE4, struct.pack("<I", 1))
        self._uc.mem_write(
            _FAKE_STATIC_FIELDS, struct.pack("<Q", _FAKE_CRC_TABLE)
        )
        self._uc.mem_write(_FAKE_CRC_TABLE + 0x18, struct.pack("<Q", 256))
        self._uc.mem_write(_FAKE_CRC_TABLE + 0x20, _crc_table())
        self._uc.mem_write(TYPE_INFO_SLOT_VA, struct.pack("<Q", _FAKE_CLASS))
        self._uc.mem_write(TYPE_INITIALIZED_GUARD_VA, b"\x01")

    def compute(self, iv: bytes | bytearray | int) -> int:
        """Execute the original native helper for the low uint16 of ``iv``."""
        from unicorn import UcError
        from unicorn.x86_const import (
            UC_X86_REG_R8,
            UC_X86_REG_R9,
            UC_X86_REG_RAX,
            UC_X86_REG_RCX,
            UC_X86_REG_RDX,
            UC_X86_REG_RIP,
            UC_X86_REG_RSP,
        )

        value = _iv_bytes(iv)
        self._uc.mem_write(_FAKE_INPUT_ARRAY + 0x18, struct.pack("<Q", 2))
        self._uc.mem_write(_FAKE_INPUT_ARRAY + 0x20, value[:2])
        stack_pointer = _STACK_BASE + _STACK_SIZE - _PAGE_SIZE
        self._uc.mem_write(stack_pointer, struct.pack("<Q", _STOP_ADDRESS))
        self._uc.reg_write(UC_X86_REG_RSP, stack_pointer)
        self._uc.reg_write(UC_X86_REG_RCX, _FAKE_INPUT_ARRAY)
        self._uc.reg_write(UC_X86_REG_RDX, 0)
        self._uc.reg_write(UC_X86_REG_R8, 0)
        self._uc.reg_write(UC_X86_REG_R9, 0)
        try:
            self._uc.emu_start(
                CRC_HELPER_VA,
                _STOP_ADDRESS,
                timeout=1_000_000,
                count=1_000_000,
            )
        except UcError as error:
            instruction = self._uc.reg_read(UC_X86_REG_RIP)
            raise RuntimeError(
                f"native CRC emulation failed at {instruction:#x}: {error}"
            ) from error
        if self._uc.reg_read(UC_X86_REG_RIP) != _STOP_ADDRESS:
            raise RuntimeError("native CRC emulation stopped before returning")
        return self._uc.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF

    def packet(self, iv: bytes | bytearray | int) -> bytes:
        """Build an 11-byte envelope using the emulated native result."""
        return build_security_type1_packet(iv, value=self.compute(iv))
