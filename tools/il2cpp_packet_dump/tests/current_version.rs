use std::path::PathBuf;

use maple_il2cpp_packet_dump::il2cpp::{build_dump, deterministic_json};
use maple_il2cpp_packet_dump::manifest::LoadedManifest;

fn manifest() -> LoadedManifest {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    LoadedManifest::load(
        &crate_root.join("versions/maple-classic-300-2026-08-08.json"),
        Some(&crate_root.join("../..")),
    )
    .unwrap()
}

#[test]
fn manifest_expands_observed_opaque_shapes_with_exact_widths() {
    let loaded = manifest();
    let shapes = loaded.packet_shapes().unwrap();
    assert_eq!(loaded.manifest.manual_shapes.len(), 65);
    assert_eq!(loaded.manifest.observed_opaque_shapes.len(), 97);
    assert_eq!(shapes.len(), 162);

    let shape = shapes
        .iter()
        .find(|shape| shape.name == "observed_server_to_client_opcode_189_length_326")
        .unwrap();
    assert_eq!(shape.length, Some(326));
    assert_eq!(shape.operations.len(), 2);
}

#[test]
#[ignore = "requires the pinned IL2CPP artifacts under downloads/ and .codex_tmp/"]
fn pinned_build_has_expected_opcodes_handlers_and_login_reads() {
    let loaded = manifest();
    loaded.verify_artifacts(false).unwrap();
    let dump = build_dump(&loaded).unwrap();

    assert_eq!(dump.version_id, "maple-classic-300-2026-08-08");
    assert_eq!(dump.protocol_version, 300);
    assert_eq!(dump.opcode_count, 433);
    assert_eq!(dump.handler_count, 289);
    assert_eq!(dump.packet_shapes.len(), 162);
    assert_eq!(
        dump.handlers
            .iter()
            .filter(|handler| !handler.direct_reads.is_empty())
            .count(),
        209
    );
    assert_eq!(
        dump.handlers
            .iter()
            .filter(|handler| handler.rva.is_some())
            .count(),
        27
    );
    assert_eq!(dump.opcodes.first().unwrap().value, 0);
    assert_eq!(dump.opcodes.last().unwrap().value, 432);

    let declaring_type = "ae9c5ed19d1cd2635d4a9b233f1011be23a3f74181b2d0dba5ea29832435fa4";
    let account = dump
        .handlers
        .iter()
        .find(|handler| handler.declaring_type == declaring_type && handler.opcode == 1)
        .unwrap();
    assert_eq!(account.rva, Some(0x00c0_e5c0));
    assert_eq!(
        account
            .direct_reads
            .iter()
            .map(|read| read.kind.as_str())
            .collect::<Vec<_>>(),
        [
            "u8", "u32", "u8", "u8", "bool", "utf16", "i32", "u8", "u8", "u8", "datetime", "utf16",
            "utf16"
        ]
    );

    let world = dump
        .handlers
        .iter()
        .find(|handler| handler.declaring_type == declaring_type && handler.opcode == 2)
        .unwrap();
    assert_eq!(world.rva, Some(0x00c1_0630));
    assert_eq!(world.direct_reads.len(), 1);
    assert_eq!(world.direct_reads[0].kind, "i8");

    let transition = dump
        .handlers
        .iter()
        .find(|handler| handler.declaring_type == declaring_type && handler.opcode == 402)
        .unwrap();
    assert_eq!(transition.rva, Some(0x00c1_1620));
    assert_eq!(transition.direct_reads[0].kind, "i16");

    assert_eq!(
        deterministic_json(&dump).unwrap(),
        deterministic_json(&dump).unwrap()
    );
}
