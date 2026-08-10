use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::manifest::{LoadedManifest, ReaderSymbol};
use crate::shape::ShapeSpec;

const IMAGE_BASE: u64 = 0x1_8000_0000;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Il2CppDump {
    pub schema: String,
    pub version_id: String,
    pub protocol_version: u16,
    pub opcode_enum: String,
    pub opcode_count: usize,
    pub handler_count: usize,
    pub opcodes: Vec<OpcodeMember>,
    pub handlers: Vec<PacketHandler>,
    pub packet_shapes: Vec<ShapeSpec>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpcodeMember {
    pub value: u16,
    pub member: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PacketHandler {
    pub opcode: u16,
    pub enum_member: String,
    pub declaring_type: String,
    pub method: String,
    pub source_file: String,
    pub source_line: usize,
    pub rva: Option<u64>,
    pub direct_reads: Vec<DirectRead>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DirectRead {
    pub index: usize,
    pub rva: u64,
    pub method: String,
    pub kind: String,
    pub width: Option<usize>,
}

/// Build the stable opcode/handler/read dump for one loaded version.
///
/// # Errors
///
/// Returns an error when source artifacts cannot be read or their structure is
/// inconsistent with the version manifest.
pub fn build_dump(loaded: &LoadedManifest) -> Result<Il2CppDump> {
    let inputs = &loaded.manifest.il2cpp;
    let enum_file = loaded.resolve(&inputs.opcode_enum_file);
    let handlers_dir = loaded.resolve(&inputs.handlers_dir);
    let opcodes = parse_opcode_enum(&enum_file)?;
    let opcode_by_member = opcodes
        .iter()
        .map(|member| (member.member.as_str(), member.value))
        .collect::<BTreeMap<_, _>>();
    let mut handlers = parse_handlers(
        &handlers_dir,
        &inputs.handler_attribute,
        &inputs.opcode_enum,
        &opcode_by_member,
    )?;

    let reader_by_rva = inputs
        .readers
        .iter()
        .map(|symbol| (symbol.rva, symbol))
        .collect::<BTreeMap<_, _>>();
    let declaring_types = handlers
        .iter()
        .map(|handler| handler.declaring_type.clone())
        .collect::<BTreeSet<_>>();
    let isil = parse_isil_for_types(loaded, &inputs.isil_dirs, &declaring_types, &reader_by_rva)?;
    let addresses =
        parse_addresses_for_types(loaded, &inputs.handler_metadata_dirs, &declaring_types)?;
    for handler in &mut handlers {
        handler.direct_reads = isil
            .get(&(handler.declaring_type.clone(), handler.method.clone()))
            .cloned()
            .unwrap_or_default();
        handler.rva = addresses
            .get(&(handler.declaring_type.clone(), handler.method.clone()))
            .copied();
    }
    handlers.sort_by(|left, right| {
        (
            left.opcode,
            left.declaring_type.as_str(),
            left.method.as_str(),
        )
            .cmp(&(
                right.opcode,
                right.declaring_type.as_str(),
                right.method.as_str(),
            ))
    });

    Ok(Il2CppDump {
        schema: "maple-il2cpp-packet-dump/v1".into(),
        version_id: loaded.manifest.id.clone(),
        protocol_version: loaded.manifest.protocol_version,
        opcode_enum: inputs.opcode_enum.clone(),
        opcode_count: opcodes.len(),
        handler_count: handlers.len(),
        opcodes,
        handlers,
        packet_shapes: loaded.packet_shapes()?,
    })
}

/// Serialize a dump as pretty JSON with one final newline.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn deterministic_json(dump: &Il2CppDump) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(dump)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn parse_opcode_enum(path: &Path) -> Result<Vec<OpcodeMember>> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read opcode enum {}", path.display()))?;
    let member = Regex::new(r"(?m)^\s*([0-9a-fA-F]{32,128})\s*=\s*(\d+)\s*,?\s*$")?;
    let mut opcodes = member
        .captures_iter(&source)
        .map(|capture| {
            let value = capture[2].parse::<u16>().with_context(|| {
                format!(
                    "opcode {} is not a ushort in {}",
                    &capture[2],
                    path.display()
                )
            })?;
            Ok(OpcodeMember {
                value,
                member: capture[1].to_ascii_lowercase(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if opcodes.is_empty() {
        bail!("no opcode members found in {}", path.display());
    }
    opcodes.sort_by_key(|member| member.value);
    for pair in opcodes.windows(2) {
        if pair[0].value == pair[1].value {
            bail!("duplicate opcode {} in {}", pair[0].value, path.display());
        }
    }
    Ok(opcodes)
}

fn parse_handlers(
    directory: &Path,
    attribute: &str,
    opcode_enum: &str,
    opcode_by_member: &BTreeMap<&str, u16>,
) -> Result<Vec<PacketHandler>> {
    let files = recursive_files(directory, "cs")?;
    let attribute_pattern = Regex::new(&format!(
        r"^\s*\[{}\({}(?:::|\.)([0-9a-fA-F]{{32,128}})(?:\s*\((\d+)\))?\)\]\s*$",
        regex::escape(attribute),
        regex::escape(opcode_enum)
    ))?;
    let method_pattern = Regex::new(
        r"^\s*(?:public|private|protected|internal)(?:\s+override)?(?:\s+unsafe)?\s+[A-Za-z0-9_<>,.?\[\]]+\s+([A-Za-z0-9_]+)\s*\(",
    )?;
    let mut handlers = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path)
            .with_context(|| format!("failed to read handler source {}", path.display()))?;
        let lines = source.lines().collect::<Vec<_>>();
        for (line_index, line) in lines.iter().enumerate() {
            let Some(capture) = attribute_pattern.captures(line) else {
                continue;
            };
            let enum_member = capture[1].to_ascii_lowercase();
            let opcode = opcode_by_member
                .get(enum_member.as_str())
                .copied()
                .with_context(|| {
                    format!(
                        "handler attribute references unknown enum member {} in {}:{}",
                        enum_member,
                        path.display(),
                        line_index + 1
                    )
                })?;
            if let Some(rendered) = capture.get(2) {
                let rendered_opcode = rendered.as_str().parse::<u16>()?;
                if rendered_opcode != opcode {
                    bail!(
                        "handler opcode annotation disagrees with enum: {} vs {} in {}:{}",
                        rendered_opcode,
                        opcode,
                        path.display(),
                        line_index + 1
                    );
                }
            }
            let (method_line, method) = lines
                .iter()
                .enumerate()
                .skip(line_index + 1)
                .take(64)
                .find_map(|(index, candidate)| {
                    method_pattern
                        .captures(candidate)
                        .map(|method_capture| (index, method_capture[1].to_owned()))
                })
                .with_context(|| {
                    format!(
                        "handler attribute has no following method in {}:{}",
                        path.display(),
                        line_index + 1
                    )
                })?;
            let declaring_type = path
                .file_stem()
                .and_then(|value| value.to_str())
                .context("handler filename is not UTF-8")?
                .to_owned();
            let source_file = path
                .strip_prefix(directory)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            handlers.push(PacketHandler {
                opcode,
                enum_member,
                declaring_type,
                method,
                source_file,
                source_line: method_line + 1,
                rva: None,
                direct_reads: Vec::new(),
            });
        }
    }
    if handlers.is_empty() {
        bail!("no packet handlers found under {}", directory.display());
    }
    Ok(handlers)
}

fn parse_isil_for_types(
    loaded: &LoadedManifest,
    directories: &[PathBuf],
    types: &BTreeSet<String>,
    readers: &BTreeMap<u64, &ReaderSymbol>,
) -> Result<BTreeMap<(String, String), Vec<DirectRead>>> {
    let method_pattern = Regex::new(r"^Method:\s+.*?\s([A-Za-z0-9_]+)\(")?;
    let call_pattern = Regex::new(r"^\s*\d+\s+Call\s+([0-9A-Fa-f]+)")?;
    let mut result = BTreeMap::new();
    for declaring_type in types {
        let path = directories
            .iter()
            .map(|directory| {
                loaded
                    .resolve(directory)
                    .join(format!("{declaring_type}.txt"))
            })
            .find(|candidate| candidate.exists());
        let Some(path) = path else {
            continue;
        };
        let source = fs::read_to_string(&path)
            .with_context(|| format!("failed to read ISIL {}", path.display()))?;
        let mut current_method = None::<String>;
        let mut in_isil = false;
        for line in source.lines() {
            if let Some(capture) = method_pattern.captures(line) {
                current_method = Some(capture[1].to_owned());
                in_isil = false;
                continue;
            }
            if line == "ISIL:" {
                in_isil = true;
                continue;
            }
            if !in_isil {
                continue;
            }
            let (Some(method), Some(capture)) = (&current_method, call_pattern.captures(line))
            else {
                continue;
            };
            let Ok(absolute) = u64::from_str_radix(&capture[1], 16) else {
                continue;
            };
            let rva = absolute.checked_sub(IMAGE_BASE).unwrap_or(absolute);
            let Some(reader) = readers.get(&rva) else {
                continue;
            };
            let reads = result
                .entry((declaring_type.clone(), method.clone()))
                .or_insert_with(Vec::new);
            reads.push(DirectRead {
                index: reads.len(),
                rva,
                method: reader.method.clone(),
                kind: reader.kind.clone(),
                width: reader.width,
            });
        }
    }
    Ok(result)
}

fn parse_addresses_for_types(
    loaded: &LoadedManifest,
    directories: &[PathBuf],
    types: &BTreeSet<String>,
) -> Result<BTreeMap<(String, String), u64>> {
    let address_pattern = Regex::new(r#"\[Address\(RVA = \"0x([0-9A-Fa-f]+)\""#)?;
    let method_pattern = Regex::new(
        r"^\s*(?:public|private|protected|internal)(?:\s+override)?(?:\s+unsafe)?\s+[A-Za-z0-9_<>,.?\[\]]+\s+([A-Za-z0-9_]+)\s*\(",
    )?;
    let mut result = BTreeMap::new();
    for declaring_type in types {
        let candidates = directories.iter().flat_map(|directory| {
            let base = loaded.resolve(directory);
            [
                base.join(format!("{declaring_type}.cs")),
                base.join(format!("{declaring_type}.decompiled.cs")),
            ]
        });
        let Some(path) = candidates.into_iter().find(|candidate| candidate.exists()) else {
            continue;
        };
        let source = fs::read_to_string(&path)
            .with_context(|| format!("failed to read handler metadata {}", path.display()))?;
        let mut pending_address = None;
        for line in source.lines() {
            if let Some(capture) = address_pattern.captures(line) {
                pending_address = Some(u64::from_str_radix(&capture[1], 16)?);
            }
            if let Some(capture) = method_pattern.captures(line)
                && let Some(rva) = pending_address.take()
            {
                result.insert((declaring_type.clone(), capture[1].to_owned()), rva);
            }
        }
    }
    Ok(result)
}

fn recursive_files(directory: &Path, extension: &str) -> Result<Vec<PathBuf>> {
    fn visit(directory: &Path, extension: &str, output: &mut Vec<PathBuf>) -> Result<()> {
        let mut entries = fs::read_dir(directory)
            .with_context(|| format!("failed to read directory {}", directory.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                visit(&path, extension, output)?;
            } else if path.extension().and_then(|value| value.to_str()) == Some(extension) {
                output.push(path);
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    visit(directory, extension, &mut files)?;
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_absolute_isil_addresses() {
        assert_eq!(0x1_81cd_0530_u64 - IMAGE_BASE, 0x1cd_0530);
    }
}
