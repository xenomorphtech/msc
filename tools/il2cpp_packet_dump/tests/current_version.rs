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
fn manifest_prefers_semantic_shapes_over_exact_opaque_pins() {
    let loaded = manifest();
    let shapes = loaded.packet_shapes().unwrap();
    assert_eq!(loaded.manifest.manual_shapes.len(), 103);
    assert_eq!(loaded.manifest.observed_opaque_shapes.len(), 96);
    assert_eq!(shapes.len(), 179);

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

    let opcode_137 = shapes
        .iter()
        .find(|shape| shape.name == "server_opcode_137_primitive_prefix")
        .unwrap();
    assert_eq!(opcode_137.opcode, 137);
    assert_eq!(opcode_137.length, Some(84));
    assert_eq!(opcode_137.operations.len(), 5);

    let opcode_169 = shapes
        .iter()
        .find(|shape| shape.name == "server_opcode_169_text_instruction")
        .unwrap();
    assert_eq!(opcode_169.opcode, 169);
    assert_eq!(opcode_169.length, Some(54));
    assert_eq!(opcode_169.operations.len(), 3);

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

    let opcode_147 = shapes
        .iter()
        .find(|shape| shape.name == "server_opcode_147_bounds_ledger")
        .unwrap();
    assert_eq!(opcode_147.opcode, 147);
    assert_eq!(opcode_147.length, Some(94));
    assert_eq!(opcode_147.operations.len(), 11);

    for (name, opcode, length, operation_count) in [
        ("server_opcode_27_integer_ledger_large", 27, 1_056, 3),
        ("server_opcode_27_integer_ledger_compact", 27, 27, 3),
        ("server_opcode_28_text_ledger_large", 28, 260, 3),
        ("server_opcode_28_text_ledger_compact", 28, 164, 3),
        ("server_opcode_29_text_ledger", 29, 327, 3),
        ("client_world_exit_status_45", 45, 6, 2),
        ("client_world_exit_status_46", 46, 6, 2),
        ("client_opcode_75_empty_bootstrap_marker", 75, 2, 1),
        ("inventory_move_request", 79, 13, 6),
        ("client_positioned_effect_action", 225, 16, 5),
        ("server_opcode_135_bootstrap_ledger", 135, 3_725, 10),
        ("server_opcode_142_text_ledger_large", 142, 254, 5),
        ("server_opcode_142_text_ledger_compact", 142, 190, 5),
        ("server_opcode_394_text_envelope", 394, 119, 2),
        ("client_opcode_279_text_envelope", 279, 120, 3),
        ("client_world_exit_request", 241, 2, 1),
        ("observed_client_to_server_opcode_100_length_26", 100, 26, 2),
        ("observed_client_to_server_opcode_307_length_14", 307, 14, 2),
        ("observed_client_to_server_opcode_308_length_74", 308, 74, 2),
        ("client_opcode_310_live_fixed_record", 310, 41, 2),
        ("observed_client_to_server_opcode_311_length_22", 311, 22, 2),
        ("server_opcode_425_value_ledger", 425, 68, 7),
    ] {
        let shape = shapes.iter().find(|shape| shape.name == name).unwrap();
        assert_eq!(shape.opcode, opcode);
        assert_eq!(shape.length, Some(length));
        assert_eq!(shape.operations.len(), operation_count);
    }

    for (name, opcode, length) in [
        ("server_opcode_228_u32_opaque_tail", 228, 10),
        ("server_opcode_230_u32_short_tail", 230, 7),
        ("server_opcode_230_u32_long_tail", 230, 13),
        ("server_opcode_231_u32_opaque_tail", 231, 26),
        ("server_opcode_232_u32_opaque_tail", 232, 22),
        ("server_opcode_234_u32_opaque_tail", 234, 9),
        ("server_opcode_235_u32_opaque_tail", 235, 12),
    ] {
        let shape = shapes.iter().find(|shape| shape.name == name).unwrap();
        assert_eq!(shape.opcode, opcode);
        assert_eq!(shape.length, Some(length));
        assert_eq!(shape.operations.len(), 3);
    }

    let opcode_272 = shapes
        .iter()
        .find(|shape| shape.name == "server_opcode_272_field_ledger")
        .unwrap();
    assert_eq!(opcode_272.opcode, 272);
    assert_eq!(opcode_272.length, Some(1_056));
    assert_eq!(opcode_272.operations.len(), 12);
    let opcode_276 = shapes
        .iter()
        .find(|shape| shape.name == "server_opcode_276_boolean_flag")
        .unwrap();
    assert_eq!(opcode_276.opcode, 276);
    assert_eq!(opcode_276.length, Some(3));
    assert_eq!(opcode_276.operations.len(), 2);
    assert!(!shapes.iter().any(|shape| {
        shape.name == "observed_server_to_client_opcode_27_length_1056"
            || shape.name == "observed_server_to_client_opcode_28_length_260"
            || shape.name == "observed_server_to_client_opcode_29_length_327"
            || shape.name == "observed_server_to_client_opcode_135_length_3725"
            || shape.name == "observed_server_to_client_opcode_137_length_84"
            || shape.name == "observed_server_to_client_opcode_142_length_254"
            || shape.name == "observed_server_to_client_opcode_147_length_94"
            || shape.name == "observed_server_to_client_opcode_228_length_10"
            || shape.name == "observed_server_to_client_opcode_230_length_7"
            || shape.name == "observed_server_to_client_opcode_232_length_22"
            || shape.name == "observed_server_to_client_opcode_234_length_9"
            || shape.name == "observed_server_to_client_opcode_235_length_12"
            || shape.name == "observed_server_to_client_opcode_272_length_1056"
            || shape.name == "observed_server_to_client_opcode_276_length_3"
            || shape.name == "observed_client_to_server_opcode_46_length_6"
            || shape.name == "observed_client_to_server_opcode_75_length_2"
            || shape.name == "observed_client_to_server_opcode_279_length_120"
            || shape.name == "observed_client_to_server_opcode_241_length_2"
            || shape.name == "observed_server_to_client_opcode_394_length_119"
            || shape.name == "observed_server_to_client_opcode_425_length_68"
    }));
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
    assert_eq!(dump.packet_shapes.len(), 179);
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
        (27, vec!["i32"]),
        (28, vec!["i32"]),
        (60, vec!["i32"]),
        (94, vec!["bool", "i32", "i32"]),
        (142, vec!["bool"]),
        (
            169,
            vec![
                "u8", "u8", "i32", "i32", "utf16", "utf16", "utf16", "i32", "i32", "i32", "u8",
                "i32", "i32", "i32", "i32", "u8", "u8", "utf16",
            ],
        ),
        (228, vec!["u32"]),
        (230, vec!["u32"]),
        (231, vec!["u32"]),
        (232, vec!["u32"]),
        (234, vec!["u32"]),
        (235, vec!["u32"]),
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

    let delegated_425 = dump
        .handlers
        .iter()
        .find(|handler| handler.opcode == 425)
        .unwrap();
    assert!(delegated_425.direct_reads.is_empty());

    assert_eq!(
        deterministic_json(&dump).unwrap(),
        deterministic_json(&dump).unwrap()
    );
}
