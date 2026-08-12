use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Direction, PacketJsonl};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ShapeSpec {
    pub name: String,
    pub direction: Direction,
    pub opcode: u16,
    #[serde(default)]
    pub length: Option<usize>,
    pub source: String,
    pub operations: Vec<ShapeOp>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ShapeOp {
    Read {
        name: String,
        kind: ReadKind,
        #[serde(default)]
        equals: Option<i64>,
    },
    Bytes {
        name: String,
        length: usize,
        #[serde(default)]
        equals_hex: Option<String>,
    },
    BytesFrom {
        name: String,
        length_from: String,
    },
    Utf16 {
        name: String,
        #[serde(default)]
        trailing_zero: bool,
    },
    Repeat {
        count_from: String,
        operations: Vec<ShapeOp>,
    },
    Switch {
        field: String,
        cases: Vec<ShapeCase>,
    },
    IfMask {
        field: String,
        mask: u64,
        operations: Vec<ShapeOp>,
    },
    BitField {
        name: String,
        field: String,
        shift: u8,
        mask: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ShapeCase {
    pub equals: i64,
    pub operations: Vec<ShapeOp>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadKind {
    Bool,
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
}

impl ReadKind {
    const fn width(self) -> usize {
        match self {
            Self::Bool | Self::U8 | Self::I8 => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 => 4,
            Self::U64 | Self::I64 => 8,
        }
    }

    const fn signed(self) -> bool {
        matches!(self, Self::I8 | Self::I16 | Self::I32 | Self::I64)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ValidationReport {
    pub packet_count: usize,
    pub supported_count: usize,
    pub unsupported_count: usize,
    pub passed_count: usize,
    pub failures: Vec<ShapeFailure>,
    pub unsupported: Vec<UnsupportedShape>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ShapeFailure {
    pub tcp_stream: u32,
    pub direction: Direction,
    pub direction_index: usize,
    pub opcode: u16,
    pub length: usize,
    pub shape: String,
    pub consumed: usize,
    pub remaining: usize,
    pub error: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnsupportedShape {
    pub direction: Direction,
    pub opcode: u16,
    pub length: usize,
    pub count: usize,
}

struct Cursor<'a> {
    payload: &'a [u8],
    offset: usize,
    values: BTreeMap<String, i128>,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize, field: &str) -> std::result::Result<&'a [u8], String> {
        let end = self.offset.saturating_add(length);
        if end > self.payload.len() {
            return Err(format!(
                "{field} needs {length} bytes at offset {}, only {} remain (less bytes than shape requires)",
                self.offset,
                self.payload.len().saturating_sub(self.offset)
            ));
        }
        let bytes = &self.payload[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn execute(&mut self, operations: &[ShapeOp]) -> std::result::Result<(), String> {
        for operation in operations {
            match operation {
                ShapeOp::Read { name, kind, equals } => {
                    let bytes = self.take(kind.width(), name)?;
                    let raw_value = decode_integer(bytes, kind.signed());
                    // The pinned IL2CPP reader delegates to
                    // BitConverter.ToBoolean, whose wire semantics are zero
                    // for false and any nonzero byte for true.  Store the
                    // normalized value so equals/switch/repeat conditions see
                    // the same value as the client.
                    let value = if matches!(*kind, ReadKind::Bool) {
                        i128::from(raw_value != 0)
                    } else {
                        raw_value
                    };
                    if let Some(expected) = equals
                        && value != i128::from(*expected)
                    {
                        return Err(format!(
                            "{name} is {value}, expected {expected} at offset {}",
                            self.offset - kind.width()
                        ));
                    }
                    self.values.insert(name.clone(), value);
                }
                ShapeOp::Bytes {
                    name,
                    length,
                    equals_hex,
                } => {
                    let bytes = self.take(*length, name)?;
                    if let Some(expected_hex) = equals_hex {
                        let expected = hex::decode(expected_hex)
                            .map_err(|error| format!("invalid equals_hex for {name}: {error}"))?;
                        if bytes != expected {
                            return Err(format!(
                                "{name} does not match expected bytes at offset {}",
                                self.offset - length
                            ));
                        }
                    }
                }
                ShapeOp::BytesFrom { name, length_from } => {
                    self.execute_bytes_from(name, length_from)?;
                }
                ShapeOp::Utf16 {
                    name,
                    trailing_zero,
                } => {
                    let count_bytes = self.take(2, &format!("{name}.character_count"))?;
                    let character_count =
                        usize::from(u16::from_le_bytes([count_bytes[0], count_bytes[1]]));
                    let encoded = self.take(
                        character_count.saturating_mul(2),
                        &format!("{name}.utf16le"),
                    )?;
                    for pair in encoded.chunks_exact(2) {
                        let _ = u16::from_le_bytes([pair[0], pair[1]]);
                    }
                    if *trailing_zero {
                        let terminator = self.take(1, &format!("{name}.trailing_zero"))?[0];
                        if terminator != 0 {
                            return Err(format!(
                                "{name}.trailing_zero is {terminator}, expected 0 at offset {}",
                                self.offset - 1
                            ));
                        }
                    }
                }
                ShapeOp::Repeat {
                    count_from,
                    operations,
                } => {
                    let count = self.values.get(count_from).ok_or_else(|| {
                        format!("repeat references unread count field {count_from}")
                    })?;
                    let count = usize::try_from(*count).map_err(|_| {
                        format!("repeat count {count_from} is negative or too large: {count}")
                    })?;
                    if count > 1_000_000 {
                        return Err(format!("repeat count {count_from} is implausible: {count}"));
                    }
                    for _ in 0..count {
                        self.execute(operations)?;
                    }
                }
                ShapeOp::Switch { field, cases } => self.execute_switch(field, cases)?,
                ShapeOp::IfMask {
                    field,
                    mask,
                    operations,
                } => self.execute_if_mask(field, *mask, operations)?,
                ShapeOp::BitField {
                    name,
                    field,
                    shift,
                    mask,
                } => self.execute_bit_field(name, field, *shift, *mask)?,
            }
        }
        Ok(())
    }

    fn execute_bit_field(
        &mut self,
        name: &str,
        field: &str,
        shift: u8,
        mask: u64,
    ) -> std::result::Result<(), String> {
        let value = *self
            .values
            .get(field)
            .ok_or_else(|| format!("bit_field references unread field {field}"))?;
        if value < 0 {
            return Err(format!("bit_field source {field} is negative: {value}"));
        }
        if shift >= 64 {
            return Err(format!("bit_field shift must be below 64, got {shift}"));
        }
        let shifted = value >> shift;
        self.values
            .insert(name.to_owned(), shifted & i128::from(mask));
        Ok(())
    }

    fn execute_if_mask(
        &mut self,
        field: &str,
        mask: u64,
        operations: &[ShapeOp],
    ) -> std::result::Result<(), String> {
        let value = *self
            .values
            .get(field)
            .ok_or_else(|| format!("if_mask references unread field {field}"))?;
        if value & i128::from(mask) != 0 {
            self.execute(operations)?;
        }
        Ok(())
    }

    fn execute_switch(
        &mut self,
        field: &str,
        cases: &[ShapeCase],
    ) -> std::result::Result<(), String> {
        let value = *self
            .values
            .get(field)
            .ok_or_else(|| format!("switch references unread field {field}"))?;
        let selected = cases
            .iter()
            .find(|case| value == i128::from(case.equals))
            .ok_or_else(|| {
                let expected = cases
                    .iter()
                    .map(|case| case.equals.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{field} is {value}, expected one of {expected}")
            })?;
        self.execute(&selected.operations)
    }

    fn execute_bytes_from(
        &mut self,
        name: &str,
        length_from: &str,
    ) -> std::result::Result<(), String> {
        let length = self
            .values
            .get(length_from)
            .ok_or_else(|| format!("bytes_from references unread length field {length_from}"))?;
        let length = usize::try_from(*length).map_err(|_| {
            format!("bytes_from length {length_from} is negative or too large: {length}")
        })?;
        self.take(length, name)?;
        Ok(())
    }
}

fn decode_integer(bytes: &[u8], signed: bool) -> i128 {
    let mut raw = 0_u64;
    for (index, byte) in bytes.iter().enumerate() {
        raw |= u64::from(*byte) << (index * 8);
    }
    if !signed {
        return i128::from(raw);
    }
    let bits = bytes.len() * 8;
    if bits == 64 {
        i128::from(raw.cast_signed())
    } else {
        let sign_bit = 1_u64 << (bits - 1);
        if raw & sign_bit == 0 {
            i128::from(raw)
        } else {
            i128::from(raw) - (1_i128 << bits)
        }
    }
}

/// Validate every supported packet against exactly one manual shape.
///
/// # Errors
///
/// Returns an error for corrupt JSONL metadata, hash/opcode mismatches, or
/// ambiguous shape selection. Shape-consumption failures are returned in the
/// report so every failing frame can be audited together.
#[allow(clippy::too_many_lines)]
pub fn validate_packets(packets: &[PacketJsonl], shapes: &[ShapeSpec]) -> Result<ValidationReport> {
    let mut report = ValidationReport {
        packet_count: packets.len(),
        ..ValidationReport::default()
    };
    let mut unsupported = BTreeMap::<(Direction, u16, usize), usize>::new();

    for packet in packets {
        let payload = hex::decode(&packet.payload_hex).map_err(|error| {
            anyhow::anyhow!(
                "stream {} {} frame {} has invalid payload_hex: {error}",
                packet.tcp_stream,
                packet.direction,
                packet.direction_index
            )
        })?;
        if payload.len() != packet.length {
            bail!(
                "stream {} {} frame {} declares length {}, decoded {}",
                packet.tcp_stream,
                packet.direction,
                packet.direction_index,
                packet.length,
                payload.len()
            );
        }
        if hex::encode(Sha256::digest(&payload)) != packet.payload_sha256 {
            bail!(
                "stream {} {} frame {} payload SHA-256 mismatch",
                packet.tcp_stream,
                packet.direction,
                packet.direction_index
            );
        }
        if payload.len() < 2 || u16::from_le_bytes([payload[0], payload[1]]) != packet.opcode {
            bail!(
                "stream {} {} frame {} opcode metadata does not match payload",
                packet.tcp_stream,
                packet.direction,
                packet.direction_index
            );
        }

        let opcode_matches = shapes
            .iter()
            .filter(|shape| shape.direction == packet.direction && shape.opcode == packet.opcode)
            .collect::<Vec<_>>();
        let has_exact_match = opcode_matches
            .iter()
            .any(|shape| shape.length == Some(packet.length));
        let matches = opcode_matches
            .into_iter()
            .filter(|shape| {
                shape.length == Some(packet.length) || (!has_exact_match && shape.length.is_none())
            })
            .collect::<Vec<_>>();
        if matches.is_empty() {
            report.unsupported_count += 1;
            *unsupported
                .entry((packet.direction, packet.opcode, packet.length))
                .or_default() += 1;
            continue;
        }
        if matches.len() > 1 {
            bail!(
                "ambiguous manual shape for {} opcode {} length {}",
                packet.direction,
                packet.opcode,
                packet.length
            );
        }

        report.supported_count += 1;
        let shape = matches[0];
        let mut cursor = Cursor {
            payload: &payload,
            offset: 0,
            values: BTreeMap::new(),
        };
        let execution = cursor.execute(&shape.operations);
        if let Err(error) = execution {
            report.failures.push(ShapeFailure {
                tcp_stream: packet.tcp_stream,
                direction: packet.direction,
                direction_index: packet.direction_index,
                opcode: packet.opcode,
                length: packet.length,
                shape: shape.name.clone(),
                consumed: cursor.offset,
                remaining: payload.len().saturating_sub(cursor.offset),
                error,
            });
        } else if cursor.offset != payload.len() {
            let remaining = payload.len() - cursor.offset;
            report.failures.push(ShapeFailure {
                tcp_stream: packet.tcp_stream,
                direction: packet.direction,
                direction_index: packet.direction_index,
                opcode: packet.opcode,
                length: packet.length,
                shape: shape.name.clone(),
                consumed: cursor.offset,
                remaining,
                error: format!(
                    "shape consumed {} bytes but packet has {} ({remaining} extra bytes)",
                    cursor.offset,
                    payload.len()
                ),
            });
        } else {
            report.passed_count += 1;
        }
    }

    report.unsupported = unsupported
        .into_iter()
        .map(|((direction, opcode, length), count)| UnsupportedShape {
            direction,
            opcode,
            length,
            count,
        })
        .collect();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_extra_and_missing_bytes() {
        let shape = ShapeSpec {
            name: "fixed".into(),
            direction: Direction::ClientToServer,
            opcode: 4,
            length: None,
            source: "manual".into(),
            operations: vec![
                ShapeOp::Read {
                    name: "opcode".into(),
                    kind: ReadKind::U16,
                    equals: Some(4),
                },
                ShapeOp::Read {
                    name: "value".into(),
                    kind: ReadKind::U32,
                    equals: None,
                },
            ],
        };
        let extra = validate_raw(&[4, 0, 1, 0, 0, 0, 9], &shape);
        assert!(extra.contains("extra bytes"));
        let missing = validate_raw(&[4, 0, 1], &shape);
        assert!(missing.contains("less bytes"));
    }

    #[test]
    fn bool_normalizes_nonzero_bytes() {
        let shape = ShapeSpec {
            name: "boolean".into(),
            direction: Direction::ServerToClient,
            opcode: 94,
            length: Some(1),
            source: "generated reader evidence".into(),
            operations: vec![ShapeOp::Read {
                name: "flag".into(),
                kind: ReadKind::Bool,
                equals: Some(1),
            }],
        };
        assert_eq!(validate_raw(&[1], &shape), "ok");
        assert_eq!(validate_raw(&[5], &shape), "ok");
        assert!(validate_raw(&[0], &shape).contains("expected 1"));
    }

    #[test]
    fn repeat_and_utf16_consume_dynamic_shapes() {
        let shape = ShapeSpec {
            name: "dynamic".into(),
            direction: Direction::ServerToClient,
            opcode: 2,
            length: None,
            source: "manual".into(),
            operations: vec![
                ShapeOp::Read {
                    name: "opcode".into(),
                    kind: ReadKind::U16,
                    equals: Some(2),
                },
                ShapeOp::Read {
                    name: "count".into(),
                    kind: ReadKind::U8,
                    equals: None,
                },
                ShapeOp::Repeat {
                    count_from: "count".into(),
                    operations: vec![ShapeOp::Utf16 {
                        name: "item".into(),
                        trailing_zero: true,
                    }],
                },
            ],
        };
        let payload = [2, 0, 1, 2, 0, b'A', 0, b'B', 0, 0];
        assert_eq!(validate_raw(&payload, &shape), "ok");
    }

    #[test]
    fn switch_consumes_the_selected_branch() {
        let shape = ShapeSpec {
            name: "switch".into(),
            direction: Direction::ClientToServer,
            opcode: 1,
            length: None,
            source: "manual".into(),
            operations: vec![
                ShapeOp::Read {
                    name: "kind".into(),
                    kind: ReadKind::U8,
                    equals: None,
                },
                ShapeOp::Switch {
                    field: "kind".into(),
                    cases: vec![
                        ShapeCase {
                            equals: 1,
                            operations: vec![ShapeOp::Bytes {
                                name: "short".into(),
                                length: 2,
                                equals_hex: None,
                            }],
                        },
                        ShapeCase {
                            equals: 2,
                            operations: vec![ShapeOp::Bytes {
                                name: "long".into(),
                                length: 4,
                                equals_hex: None,
                            }],
                        },
                    ],
                },
            ],
        };
        assert_eq!(validate_raw(&[1, 0xaa, 0xbb], &shape), "ok");
        assert_eq!(validate_raw(&[2, 1, 2, 3, 4], &shape), "ok");
        assert!(validate_raw(&[3], &shape).contains("expected one of 1, 2"));
    }

    fn validate_raw(payload: &[u8], shape: &ShapeSpec) -> String {
        let mut cursor = Cursor {
            payload,
            offset: 0,
            values: BTreeMap::new(),
        };
        match cursor.execute(&shape.operations) {
            Err(error) => error,
            Ok(()) if cursor.offset != payload.len() => {
                format!("{} extra bytes", payload.len() - cursor.offset)
            }
            Ok(()) => "ok".into(),
        }
    }

    #[test]
    fn if_mask_consumes_only_present_fields() {
        let operations = vec![
            ShapeOp::Read {
                name: "mask".into(),
                kind: ReadKind::U32,
                equals: None,
            },
            ShapeOp::IfMask {
                field: "mask".into(),
                mask: 0x100,
                operations: vec![ShapeOp::Read {
                    name: "intelligence".into(),
                    kind: ReadKind::U16,
                    equals: None,
                }],
            },
            ShapeOp::IfMask {
                field: "mask".into(),
                mask: 0x400,
                operations: vec![ShapeOp::Read {
                    name: "hp".into(),
                    kind: ReadKind::U16,
                    equals: None,
                }],
            },
        ];
        let payload = [0x00, 0x05, 0x00, 0x00, 0x34, 0x12, 0x78, 0x56];
        let mut cursor = Cursor {
            payload: &payload,
            offset: 0,
            values: BTreeMap::new(),
        };
        cursor.execute(&operations).unwrap();
        assert_eq!(cursor.offset, payload.len());
        assert_eq!(cursor.values.get("intelligence"), Some(&0x1234));
        assert_eq!(cursor.values.get("hp"), Some(&0x5678));
    }

    #[test]
    fn bit_field_derives_repeat_counts() {
        let shape = ShapeSpec {
            name: "bit_field".into(),
            direction: Direction::ServerToClient,
            opcode: 0,
            length: None,
            source: "test".into(),
            operations: vec![
                ShapeOp::Read {
                    name: "packed_counts".into(),
                    kind: ReadKind::U8,
                    equals: None,
                },
                ShapeOp::BitField {
                    name: "target_count".into(),
                    field: "packed_counts".into(),
                    shift: 4,
                    mask: 0x0f,
                },
                ShapeOp::BitField {
                    name: "hit_count".into(),
                    field: "packed_counts".into(),
                    shift: 0,
                    mask: 0x0f,
                },
                ShapeOp::Repeat {
                    count_from: "target_count".into(),
                    operations: vec![
                        ShapeOp::Read {
                            name: "target".into(),
                            kind: ReadKind::U8,
                            equals: None,
                        },
                        ShapeOp::Repeat {
                            count_from: "hit_count".into(),
                            operations: vec![ShapeOp::Read {
                                name: "damage".into(),
                                kind: ReadKind::U8,
                                equals: None,
                            }],
                        },
                    ],
                },
            ],
        };
        assert_eq!(validate_raw(&[0x12, 0xaa, 0x01, 0x02], &shape), "ok");
    }

    #[test]
    fn bytes_from_consumes_the_declared_length() {
        let operations = vec![
            ShapeOp::Read {
                name: "body_length".into(),
                kind: ReadKind::U16,
                equals: None,
            },
            ShapeOp::BytesFrom {
                name: "body".into(),
                length_from: "body_length".into(),
            },
        ];
        let payload = [3, 0, 0xaa, 0xbb, 0xcc];
        let mut cursor = Cursor {
            payload: &payload,
            offset: 0,
            values: BTreeMap::new(),
        };
        cursor.execute(&operations).unwrap();
        assert_eq!(cursor.offset, payload.len());
    }
}
