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
    assert_eq!(loaded.manifest.manual_shapes.len(), 74);
    assert_eq!(loaded.manifest.observed_opaque_shapes.len(), 96);
    assert_eq!(shapes.len(), 170);

    let shape = shapes
        .iter()
        .find(|shape| shape.name == "observed_server_to_client_opcode_189_length_326")
        .unwrap();
    assert_eq!(shape.length, Some(326));
    assert_eq!(shape.operations.len(), 2);

    let skill_update = shapes
        .iter()
        .find(|shape| shape.name == "skill_record_update")
        .unwrap();
    assert_eq!(skill_update.opcode, 46);
    assert_eq!(skill_update.length, None);
    assert_eq!(skill_update.operations.len(), 6);

    let signed_i32 = shapes
        .iter()
        .find(|shape| shape.name == "server_opcode_60_i32")
        .unwrap();
    assert_eq!(signed_i32.opcode, 60);
    assert_eq!(signed_i32.length, Some(6));
    assert_eq!(signed_i32.operations.len(), 2);

    let flag_and_pair = shapes
        .iter()
        .find(|shape| shape.name == "server_opcode_94_record")
        .unwrap();
    assert_eq!(flag_and_pair.opcode, 94);
    assert_eq!(flag_and_pair.length, Some(11));
    assert_eq!(flag_and_pair.operations.len(), 4);

    let opcode_148 = shapes
        .iter()
        .find(|shape| shape.name == "server_opcode_148_envelope")
        .unwrap();
    assert_eq!(opcode_148.opcode, 148);
    assert_eq!(opcode_148.length, None);
    assert_eq!(opcode_148.operations.len(), 3);

    let legacy_opcode_148 = shapes
        .iter()
        .find(|shape| shape.name == "observed_server_to_client_opcode_148_length_1639")
        .unwrap();
    assert_eq!(legacy_opcode_148.length, Some(1_639));

    let opcode_43_identified = shapes
        .iter()
        .find(|shape| shape.name == "client_opcode_43_identified_text")
        .unwrap();
    assert_eq!(opcode_43_identified.opcode, 43);
    assert_eq!(opcode_43_identified.length, None);
    assert_eq!(opcode_43_identified.operations.len(), 5);

    let opcode_43_compact = shapes
        .iter()
        .find(|shape| shape.name == "client_opcode_43_compact")
        .unwrap();
    assert_eq!(opcode_43_compact.opcode, 43);
    assert_eq!(opcode_43_compact.length, Some(12));
    assert_eq!(opcode_43_compact.operations.len(), 3);

    let opcode_114 = shapes
        .iter()
        .find(|shape| shape.name == "client_opcode_114_text_envelope")
        .unwrap();
    assert_eq!(opcode_114.opcode, 114);
    assert_eq!(opcode_114.length, None);
    assert_eq!(opcode_114.operations.len(), 4);

    let opcode_66 = shapes
        .iter()
        .find(|shape| shape.name == "client_opcode_66_server_348_acknowledgement")
        .unwrap();
    assert_eq!(opcode_66.opcode, 66);
    assert_eq!(opcode_66.length, None);
    assert_eq!(opcode_66.operations.len(), 3);
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
    assert_eq!(dump.packet_shapes.len(), 170);
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

    for (opcode, expected_reads) in [
        (60, vec!["i32"]),
        (94, vec!["bool", "i32", "i32"]),
        (
            379,
            vec!["u8", "datetime", "datetime", "datetime", "datetime"],
        ),
    ] {
        let handler = dump
            .handlers
            .iter()
            .find(|handler| handler.opcode == opcode)
            .unwrap();
        assert_eq!(
            handler
                .direct_reads
                .iter()
                .map(|read| read.kind.as_str())
                .collect::<Vec<_>>(),
            expected_reads
        );
    }

    assert_eq!(
        deterministic_json(&dump).unwrap(),
        deterministic_json(&dump).unwrap()
    );
}
