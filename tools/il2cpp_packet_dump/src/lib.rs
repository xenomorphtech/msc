pub mod il2cpp;
pub mod manifest;
pub mod maple;
pub mod pcap;
pub mod shape;

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PacketJsonl {
    pub schema: String,
    pub version_id: String,
    pub capture_sha256: String,
    pub tcp_stream: u32,
    pub protocol_version: u16,
    pub direction: Direction,
    pub direction_index: usize,
    pub opcode: u16,
    pub length: usize,
    pub payload_sha256: String,
    pub payload_hex: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientToServer => formatter.write_str("client_to_server"),
            Self::ServerToClient => formatter.write_str("server_to_client"),
        }
    }
}

/// Read deterministic plaintext packet rows from a JSONL file.
///
/// # Errors
///
/// Returns an error when the file cannot be read or any nonblank row is invalid.
pub fn read_packet_jsonl(path: &Path) -> Result<Vec<PacketJsonl>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open packet JSONL {}", path.display()))?;
    BufReader::new(file)
        .lines()
        .enumerate()
        .filter_map(|(index, line)| match line {
            Ok(line) if line.trim().is_empty() => None,
            other => Some((index, other)),
        })
        .map(|(index, line)| {
            let line = line
                .with_context(|| format!("failed to read {} line {}", path.display(), index + 1))?;
            serde_json::from_str(&line)
                .with_context(|| format!("invalid JSON in {} line {}", path.display(), index + 1))
        })
        .collect()
}
