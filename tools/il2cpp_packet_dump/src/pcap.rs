use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::manifest::sha256_file;
use crate::maple::{Handshake, decrypt_direction, parse_handshake};
use crate::{Direction, PacketJsonl};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StreamSummary {
    pub tcp_stream: u32,
    pub client_endpoint: String,
    pub server_endpoint: String,
    pub handshake: Handshake,
    pub client_version_mask: u16,
    pub server_version_mask: u16,
    pub client_packets: usize,
    pub server_packets: usize,
}

#[derive(Clone, Debug)]
pub struct ExportedStream {
    pub summary: StreamSummary,
    pub packets: Vec<PacketJsonl>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Endpoint {
    address: String,
    port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.address, self.port)
    }
}

#[derive(Clone, Debug)]
struct Segment {
    frame: u64,
    source: Endpoint,
    destination: Endpoint,
    sequence: u64,
    payload: Vec<u8>,
}

/// Extract, reassemble, identify, and decrypt one `tcp.stream` from a PCAP.
///
/// # Errors
///
/// Returns an error when tshark fails, TCP data is inconsistent, the stream is
/// not uniquely Maple, or frame decryption/header validation fails.
pub fn export_stream(
    pcap: &Path,
    tcp_stream: u32,
    tshark: &Path,
    version_id: &str,
    expected_protocol_version: u16,
) -> Result<ExportedStream> {
    let capture_sha256 = sha256_file(pcap)?;
    let segments = read_segments(pcap, tcp_stream, tshark)?;
    let endpoints = segments
        .iter()
        .flat_map(|segment| [segment.source.clone(), segment.destination.clone()])
        .collect::<BTreeSet<_>>();
    if endpoints.len() != 2 {
        bail!(
            "TCP stream {tcp_stream} has {} endpoints, expected 2",
            endpoints.len()
        );
    }
    let streams = endpoints
        .iter()
        .map(|endpoint| {
            let endpoint_segments = segments
                .iter()
                .filter(|segment| &segment.source == endpoint)
                .cloned()
                .collect::<Vec<_>>();
            Ok((endpoint.clone(), reassemble(&endpoint_segments)?))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let candidates = streams
        .iter()
        .filter_map(|(endpoint, data)| {
            parse_handshake(data).ok().and_then(|handshake| {
                (handshake.version > 0
                    && handshake.version < 10_000
                    && handshake.wire_length() <= 256
                    && handshake
                        .subversion
                        .chars()
                        .all(|character| !character.is_control()))
                .then_some((endpoint.clone(), handshake))
            })
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        bail!(
            "could not uniquely identify Maple server in TCP stream {tcp_stream}; candidates={}",
            candidates.len()
        );
    }
    let (server, handshake) = candidates[0].clone();
    if handshake.version != expected_protocol_version {
        bail!(
            "TCP stream {tcp_stream} protocol version is {}, manifest expects {expected_protocol_version}",
            handshake.version
        );
    }
    let client = endpoints
        .iter()
        .find(|endpoint| **endpoint != server)
        .context("client endpoint is missing")?
        .clone();
    let client_encrypted = streams.get(&client).context("client stream is missing")?;
    let server_stream = streams.get(&server).context("server stream is missing")?;
    let server_encrypted = server_stream
        .get(handshake.wire_length()..)
        .context("server stream is shorter than handshake")?;
    let client_plain = decrypt_direction(client_encrypted, handshake.first_iv)?;
    let server_plain = decrypt_direction(server_encrypted, handshake.second_iv)?;
    let mut packets =
        Vec::with_capacity(client_plain.plaintexts.len() + server_plain.plaintexts.len());
    append_packets(
        &mut packets,
        &client_plain.plaintexts,
        Direction::ClientToServer,
        tcp_stream,
        version_id,
        &capture_sha256,
        expected_protocol_version,
    )?;
    append_packets(
        &mut packets,
        &server_plain.plaintexts,
        Direction::ServerToClient,
        tcp_stream,
        version_id,
        &capture_sha256,
        expected_protocol_version,
    )?;

    Ok(ExportedStream {
        summary: StreamSummary {
            tcp_stream,
            client_endpoint: client.to_string(),
            server_endpoint: server.to_string(),
            handshake,
            client_version_mask: client_plain.version_mask,
            server_version_mask: server_plain.version_mask,
            client_packets: client_plain.plaintexts.len(),
            server_packets: server_plain.plaintexts.len(),
        },
        packets,
    })
}

fn append_packets(
    output: &mut Vec<PacketJsonl>,
    plaintexts: &[Vec<u8>],
    direction: Direction,
    tcp_stream: u32,
    version_id: &str,
    capture_sha256: &str,
    protocol_version: u16,
) -> Result<()> {
    for (direction_index, payload) in plaintexts.iter().enumerate() {
        if payload.len() < 2 {
            bail!(
                "stream {tcp_stream} {direction} frame {direction_index} is shorter than its opcode"
            );
        }
        let opcode = u16::from_le_bytes([payload[0], payload[1]]);
        output.push(PacketJsonl {
            schema: "maple-plaintext-packet/v1".into(),
            version_id: version_id.into(),
            capture_sha256: capture_sha256.into(),
            tcp_stream,
            protocol_version,
            direction,
            direction_index,
            opcode,
            length: payload.len(),
            payload_sha256: hex::encode(Sha256::digest(payload)),
            payload_hex: hex::encode(payload),
        });
    }
    Ok(())
}

fn read_segments(pcap: &Path, tcp_stream: u32, tshark: &Path) -> Result<Vec<Segment>> {
    let output = Command::new(tshark)
        .args(["-n", "-r"])
        .arg(pcap)
        .args([
            "-Y",
            &format!("tcp.stream == {tcp_stream} && tcp.len > 0"),
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-E",
            "quote=n",
            "-E",
            "occurrence=f",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "tcp.seq",
            "-e",
            "tcp.payload",
        ])
        .output()
        .with_context(|| format!("failed to run {}", tshark.display()))?;
    if !output.status.success() {
        bail!(
            "tshark failed for stream {tcp_stream}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8(output.stdout).context("tshark output is not UTF-8")?;
    let mut segments = Vec::new();
    for (line_index, line) in stdout.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 7 {
            bail!(
                "tshark stream {tcp_stream} line {} has {} fields, expected 7",
                line_index + 1,
                fields.len()
            );
        }
        let payload = hex::decode(fields[6].replace(':', ""))
            .with_context(|| format!("invalid TCP payload on tshark line {}", line_index + 1))?;
        if payload.is_empty() {
            continue;
        }
        segments.push(Segment {
            frame: fields[0].parse()?,
            source: Endpoint {
                address: fields[1].into(),
                port: fields[2].parse()?,
            },
            destination: Endpoint {
                address: fields[3].into(),
                port: fields[4].parse()?,
            },
            sequence: fields[5].parse()?,
            payload,
        });
    }
    if segments.is_empty() {
        bail!("tshark returned no payload segments for TCP stream {tcp_stream}");
    }
    Ok(segments)
}

fn reassemble(segments: &[Segment]) -> Result<Vec<u8>> {
    if segments.is_empty() {
        bail!("cannot reassemble an empty TCP direction");
    }
    let mut ordered = segments.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|segment| (segment.sequence, segment.frame));
    let start = ordered[0].sequence;
    let mut output = Vec::new();
    for segment in ordered {
        let relative = usize::try_from(segment.sequence.saturating_sub(start))?;
        if relative > output.len() {
            bail!(
                "TCP reassembly has a {}-byte gap before frame {}",
                relative - output.len(),
                segment.frame
            );
        }
        let overlap = output
            .len()
            .saturating_sub(relative)
            .min(segment.payload.len());
        if output[relative..relative + overlap] != segment.payload[..overlap] {
            bail!("conflicting TCP retransmission at frame {}", segment.frame);
        }
        output.extend_from_slice(&segment.payload[overlap..]);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(frame: u64, sequence: u64, payload: &[u8]) -> Segment {
        Segment {
            frame,
            source: Endpoint {
                address: "client".into(),
                port: 1,
            },
            destination: Endpoint {
                address: "server".into(),
                port: 2,
            },
            sequence,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn reassembles_out_of_order_and_identical_retransmissions() {
        let segments = [
            segment(3, 103, b"def"),
            segment(1, 100, b"abcd"),
            segment(2, 100, b"abcd"),
        ];
        assert_eq!(reassemble(&segments).unwrap(), b"abcdef");
    }

    #[test]
    fn rejects_sequence_gaps() {
        let error = reassemble(&[segment(1, 100, b"a"), segment(2, 102, b"c")]).unwrap_err();
        assert!(error.to_string().contains("gap"));
    }
}
