use std::collections::BTreeSet;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use maple_il2cpp_packet_dump::il2cpp::{build_dump, deterministic_json};
use maple_il2cpp_packet_dump::manifest::LoadedManifest;
use maple_il2cpp_packet_dump::pcap::{StreamSummary, export_stream};
use maple_il2cpp_packet_dump::shape::validate_packets;
use maple_il2cpp_packet_dump::{PacketJsonl, read_packet_jsonl};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Verify every pinned artifact that is present (and all required artifacts).
    Verify {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        repository_root: Option<PathBuf>,
        #[arg(long)]
        include_optional: bool,
    },
    /// Dump IL2CPP opcodes, handlers, direct reads, and version-locked packet shapes.
    Dump {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        repository_root: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Reassemble and decrypt one or more Maple TCP streams into deterministic JSONL.
    ExportPcap {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        repository_root: Option<PathBuf>,
        #[arg(long)]
        pcap: PathBuf,
        #[arg(long, required = true)]
        stream: Vec<u32>,
        #[arg(long, default_value = "tshark")]
        tshark: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        summary: Option<PathBuf>,
    },
    /// Check JSONL packets against the version manifest with exact byte consumption.
    Validate {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        repository_root: Option<PathBuf>,
        #[arg(long, required = true)]
        input: Vec<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        require_all_supported: bool,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Verify {
            manifest,
            repository_root,
            include_optional,
        } => {
            let loaded = load(&manifest, repository_root.as_deref())?;
            loaded.verify_artifacts(include_optional)?;
            println!(
                "verified version {} (protocol {})",
                loaded.manifest.id, loaded.manifest.protocol_version
            );
        }
        Commands::Dump {
            manifest,
            repository_root,
            output,
        } => {
            let loaded = load(&manifest, repository_root.as_deref())?;
            loaded.verify_artifacts(false)?;
            let dump = build_dump(&loaded)?;
            write_file(&output, &deterministic_json(&dump)?)?;
            println!(
                "wrote {} opcodes and {} handlers to {}",
                dump.opcode_count,
                dump.handler_count,
                output.display()
            );
        }
        Commands::ExportPcap {
            manifest,
            repository_root,
            pcap,
            stream,
            tshark,
            output,
            summary,
        } => {
            let loaded = load(&manifest, repository_root.as_deref())?;
            loaded.verify_artifacts(false)?;
            let streams = stream.into_iter().collect::<BTreeSet<_>>();
            let mut packets = Vec::new();
            let mut summaries = Vec::new();
            for tcp_stream in streams {
                let exported = export_stream(
                    &pcap,
                    tcp_stream,
                    &tshark,
                    &loaded.manifest.id,
                    loaded.manifest.protocol_version,
                )?;
                summaries.push(exported.summary);
                packets.extend(exported.packets);
            }
            write_jsonl(&output, &packets)?;
            if let Some(summary_path) = summary {
                write_pretty_json(&summary_path, &summaries)?;
            }
            println!(
                "wrote {} decrypted packets from {} stream(s) to {}",
                packets.len(),
                summaries.len(),
                output.display()
            );
        }
        Commands::Validate {
            manifest,
            repository_root,
            input,
            output,
            require_all_supported,
        } => {
            let loaded = load(&manifest, repository_root.as_deref())?;
            let mut packets = Vec::new();
            for path in input {
                packets.extend(read_packet_jsonl(&path)?);
            }
            let shapes = loaded.packet_shapes()?;
            let report = validate_packets(&packets, &shapes)?;
            if let Some(output) = output {
                write_pretty_json(&output, &report)?;
            } else {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            if !report.failures.is_empty() {
                bail!("{} supported packet shapes failed", report.failures.len());
            }
            if require_all_supported && report.unsupported_count != 0 {
                bail!(
                    "{} packets use shapes absent from the version manifest",
                    report.unsupported_count
                );
            }
        }
    }
    Ok(())
}

fn load(path: &Path, repository_root: Option<&Path>) -> Result<LoadedManifest> {
    LoadedManifest::load(path, repository_root)
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

fn write_pretty_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_file(path, &bytes)
}

fn write_jsonl(path: &Path, packets: &[PacketJsonl]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let file =
        fs::File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    for packet in packets {
        serde_json::to_writer(&mut writer, packet)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

#[allow(dead_code)]
fn _summaries_are_deterministic(summaries: &[StreamSummary]) -> bool {
    summaries
        .windows(2)
        .all(|pair| pair[0].tcp_stream < pair[1].tcp_stream)
}
