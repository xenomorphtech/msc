use std::collections::BTreeMap;
use std::path::PathBuf;

use maple_il2cpp_packet_dump::Direction;
use maple_il2cpp_packet_dump::manifest::{LoadedManifest, sha256_file};
use maple_il2cpp_packet_dump::read_packet_jsonl;
use maple_il2cpp_packet_dump::shape::validate_packets;

#[test]
#[ignore = "requires tests/private/111.streams-83-92-114.jsonl generated from private capture 111"]
fn capture_111_jsonl_has_zero_unsupported_or_consumption_failures() {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = LoadedManifest::load(
        &crate_root.join("versions/maple-classic-300-2026-08-08.json"),
        Some(&crate_root.join("../..")),
    )
    .unwrap();
    let jsonl = std::env::var_os("MAPLE_PACKET_JSONL").map_or_else(
        || crate_root.join("tests/private/111.streams-83-92-114.jsonl"),
        PathBuf::from,
    );
    assert_eq!(
        sha256_file(&jsonl).unwrap(),
        "176914d54735b13baa247d4add250ae835b3b9ab68fb392037232afbe6a1fdd1"
    );
    let packets = read_packet_jsonl(&jsonl).unwrap();
    assert_eq!(packets.len(), 35_316);
    assert!(packets.iter().all(|packet| {
        packet.version_id == "maple-classic-300-2026-08-08"
            && packet.capture_sha256
                == "6f98e4aa1e1f432740d14b5f6df86761bf00bd7d544f759436a68c67a63a17ef"
    }));
    let mut counts = BTreeMap::new();
    for packet in &packets {
        *counts
            .entry((packet.tcp_stream, packet.direction))
            .or_insert(0_usize) += 1;
    }
    assert_eq!(counts[&(83, Direction::ClientToServer)], 12);
    assert_eq!(counts[&(83, Direction::ServerToClient)], 21);
    assert_eq!(counts[&(92, Direction::ClientToServer)], 14_640);
    assert_eq!(counts[&(92, Direction::ServerToClient)], 20_567);
    assert_eq!(counts[&(114, Direction::ClientToServer)], 11);
    assert_eq!(counts[&(114, Direction::ServerToClient)], 65);

    let shapes = manifest.packet_shapes().unwrap();
    assert_eq!(manifest.manifest.manual_shapes.len(), 106);
    assert_eq!(manifest.manifest.observed_opaque_shapes.len(), 96);
    assert_eq!(shapes.len(), 182);
    let report = validate_packets(&packets, &shapes).unwrap();
    assert_eq!(report.packet_count, 35_316);
    assert_eq!(report.supported_count, 35_316);
    assert_eq!(report.passed_count, 35_316);
    assert_eq!(report.unsupported_count, 0);
    assert!(report.unsupported.is_empty());
    assert!(report.failures.is_empty(), "{:#?}", report.failures);
}
