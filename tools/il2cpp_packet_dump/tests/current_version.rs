use std::path::PathBuf;

use maple_il2cpp_packet_dump::il2cpp::{build_dump, deterministic_json};
use maple_il2cpp_packet_dump::manifest::LoadedManifest;
use maple_il2cpp_packet_dump::shape::{ReadKind, ShapeOp};

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
    assert_eq!(loaded.manifest.manual_shapes.len(), 144);
    assert_eq!(loaded.manifest.observed_opaque_shapes.len(), 88);
    assert_eq!(shapes.len(), 199);

    let life_submission = shapes
        .iter()
        .find(|shape| shape.name == "client_life_movement_relay")
        .unwrap();
    let command_repeat = life_submission
        .operations
        .iter()
        .find_map(|operation| match operation {
            ShapeOp::Repeat { operations, .. } => Some(operations),
            _ => None,
        })
        .unwrap();
    let command_cases = command_repeat
        .iter()
        .find_map(|operation| match operation {
            ShapeOp::Switch { cases, .. } => Some(cases),
            _ => None,
        })
        .unwrap();
    for command_type in 0..=17 {
        let command_case = command_cases
            .iter()
            .find(|case| case.equals == command_type)
            .unwrap();
        assert!(
            command_case
                .operations
                .iter()
                .all(|operation| matches!(operation, ShapeOp::Read { .. }))
        );
    }
    let tail_cases = life_submission
        .operations
        .iter()
        .find_map(|operation| match operation {
            ShapeOp::Switch { field, cases } if field == "tail_type" => Some(cases),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        tail_cases
            .iter()
            .map(|case| (case.equals, case.operations.len()))
            .collect::<Vec<_>>(),
        [(17, 8), (18, 8), (21, 10), (24, 11)]
    );
    assert!(tail_cases.iter().all(|case| {
        case.operations
            .iter()
            .all(|operation| matches!(operation, ShapeOp::Read { .. }))
    }));

    let heartbeat_response = shapes
        .iter()
        .find(|shape| shape.name == "heartbeat_response")
        .unwrap();
    assert!(matches!(
        heartbeat_response.operations.as_slice(),
        [
            ShapeOp::Read {
                kind: ReadKind::U16,
                equals: Some(23),
                ..
            },
            ShapeOp::Read {
                name,
                kind: ReadKind::U64,
                equals: None,
            }
        ] if name == "response_value"
    ));

    let server_opcode_69 = shapes
        .iter()
        .find(|shape| shape.name == "server_opcode_69")
        .unwrap();
    assert!(matches!(
        server_opcode_69.operations.as_slice(),
        [
            ShapeOp::Read {
                kind: ReadKind::U16,
                equals: Some(69),
                ..
            },
            ShapeOp::Read {
                kind: ReadKind::U8,
                equals: Some(7),
                ..
            },
            ShapeOp::Repeat {
                count_from,
                operations,
            }
        ] if count_from == "record_count"
            && matches!(
                operations.as_slice(),
                [ShapeOp::Bytes {
                    length: 38,
                    equals_hex: Some(value),
                    ..
                }] if value == &"00".repeat(38)
            )
    ));

    let pet_activation = shapes
        .iter()
        .find(|shape| shape.name == "server_opcode_201_pet_activation")
        .unwrap();
    assert_eq!(pet_activation.opcode, 201);
    assert!(pet_activation.length.is_none());
    assert_eq!(pet_activation.operations.len(), 13);
    assert!(matches!(
        &pet_activation.operations[6],
        ShapeOp::Read {
            kind: ReadKind::U16,
            equals: Some(0),
            ..
        }
    ));
    assert!(matches!(
        &pet_activation.operations[7],
        ShapeOp::Read {
            kind: ReadKind::U8,
            equals: Some(0),
            ..
        }
    ));

    for (length, reserved) in [
        (36, "00".repeat(28)),
        (37, format!("01{}", "00".repeat(28))),
        (44, "00".repeat(36)),
    ] {
        let status = shapes
            .iter()
            .find(|shape| shape.name == format!("server_opcode_49_status_{length}"))
            .unwrap();
        assert_eq!(status.opcode, 49);
        assert_eq!(status.length, Some(length));
        assert!(matches!(
            status.operations.as_slice(),
            [
                ShapeOp::Read {
                    kind: ReadKind::U16,
                    equals: Some(49),
                    ..
                },
                ShapeOp::Read {
                    kind: ReadKind::U8,
                    equals: Some(3),
                    ..
                },
                ShapeOp::Read {
                    kind: ReadKind::U8,
                    equals: Some(1),
                    ..
                },
                ShapeOp::Read {
                    kind: ReadKind::U32,
                    ..
                },
                ShapeOp::Bytes {
                    length,
                    equals_hex: Some(value),
                    ..
                }
            ] if *length == reserved.len() / 2 && value == &reserved
        ));
    }

    let chair_sit = shapes
        .iter()
        .find(|shape| shape.name == "chair_sit_request")
        .unwrap();
    assert_eq!(chair_sit.opcode, 49);
    assert_eq!(chair_sit.length, Some(6));
    assert_eq!(chair_sit.operations.len(), 2);

    let chair_stand = shapes
        .iter()
        .find(|shape| shape.name == "chair_stand_request")
        .unwrap();
    assert_eq!(chair_stand.opcode, 48);
    assert_eq!(chair_stand.length, Some(4));
    assert_eq!(chair_stand.operations.len(), 2);

    let chair_recovery = shapes
        .iter()
        .find(|shape| shape.name == "chair_recovery_request")
        .unwrap();
    assert_eq!(chair_recovery.opcode, 82);
    assert_eq!(chair_recovery.length, Some(2));
    assert_eq!(chair_recovery.operations.len(), 1);

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
        .find(|shape| shape.name == "server_opcode_137_pair_ledger")
        .unwrap();
    assert_eq!(opcode_137.opcode, 137);
    assert_eq!(opcode_137.length, Some(84));
    assert!(matches!(
        opcode_137.operations.as_slice(),
        [
            ShapeOp::Read {
                kind: ReadKind::U16,
                equals: Some(137),
                ..
            },
            ShapeOp::Read {
                kind: ReadKind::I16,
                equals: Some(10),
                ..
            },
            ShapeOp::Repeat {
                count_from,
                operations,
            }
        ] if count_from == "record_count"
            && matches!(
                operations.as_slice(),
                [
                    ShapeOp::Read {
                        kind: ReadKind::I32,
                        ..
                    },
                    ShapeOp::Read {
                        kind: ReadKind::I32,
                        ..
                    }
                ]
            )
    ));

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
        .find(|shape| shape.name == "client_portal_field_transfer_request")
        .unwrap();
    assert_eq!(opcode_43_identified.opcode, 43);
    assert_eq!(opcode_43_identified.length, None);
    assert_eq!(opcode_43_identified.operations.len(), 7);

    let opcode_43_compact = shapes
        .iter()
        .find(|shape| shape.name == "client_death_respawn_field_transfer_request")
        .unwrap();
    assert_eq!(opcode_43_compact.opcode, 43);
    assert_eq!(opcode_43_compact.length, Some(12));
    assert_eq!(opcode_43_compact.operations.len(), 5);

    let opcode_114 = shapes
        .iter()
        .find(|shape| shape.name == "client_opcode_114_text_envelope")
        .unwrap();
    assert_eq!(opcode_114.opcode, 114);
    assert_eq!(opcode_114.length, None);
    assert_eq!(opcode_114.operations.len(), 4);

    let inner_portal = shapes
        .iter()
        .find(|shape| shape.name == "client_inner_portal_request")
        .unwrap();
    assert_eq!(inner_portal.opcode, 115);
    assert_eq!(inner_portal.length, Some(22));
    assert_eq!(inner_portal.operations.len(), 7);

    let opcode_66 = shapes
        .iter()
        .find(|shape| shape.name == "client_opcode_66_server_348_acknowledgement")
        .unwrap();
    assert_eq!(opcode_66.opcode, 66);
    assert_eq!(opcode_66.length, None);
    assert_eq!(opcode_66.operations.len(), 3);

    let opcode_31 = shapes
        .iter()
        .find(|shape| shape.name == "client_opcode_31_record")
        .unwrap();
    assert_eq!(opcode_31.opcode, 31);
    assert_eq!(opcode_31.length, None);
    assert_eq!(opcode_31.operations.len(), 9);

    let opcode_6 = shapes
        .iter()
        .find(|shape| shape.name == "client_opcode_6_record_set")
        .unwrap();
    assert_eq!(opcode_6.opcode, 6);
    assert_eq!(opcode_6.length, None);
    assert_eq!(opcode_6.operations.len(), 12);

    let opcode_22 = shapes
        .iter()
        .find(|shape| shape.name == "server_opcode_22_indexed_text_ledger")
        .unwrap();
    assert_eq!(opcode_22.opcode, 22);
    assert_eq!(opcode_22.length, None);
    assert_eq!(opcode_22.operations.len(), 3);

    let opcode_0_probe = shapes
        .iter()
        .find(|shape| shape.name == "server_opcode_0_local_account_bootstrap_probe")
        .unwrap();
    assert_eq!(opcode_0_probe.opcode, 0);
    assert_eq!(opcode_0_probe.length, Some(36));
    assert_eq!(opcode_0_probe.operations.len(), 9);

    for (name, opcode, length, operation_count) in [
        ("login_server_opcode_3_generated_record", 3, Some(8), 4),
        ("login_client_opcode_255_u32", 255, Some(6), 2),
        ("login_server_opcode_390_u8", 390, Some(3), 2),
        ("login_client_opcode_9_text_record", 9, None, 2),
        ("login_server_opcode_6_text_record", 6, None, 3),
    ] {
        let shape = shapes.iter().find(|shape| shape.name == name).unwrap();
        assert_eq!(shape.opcode, opcode);
        assert_eq!(shape.length, length);
        assert_eq!(shape.operations.len(), operation_count);
    }

    for (name, opcode, length, operation_count) in [
        ("login_server_opcode_35_text_record", 35, Some(24), 5),
        ("client_opcode_10_character_creation_request", 10, None, 10),
        ("server_opcode_7_character_creation_success", 7, None, 29),
        (
            "client_opcode_16_created_character_selection",
            16,
            Some(7),
            3,
        ),
    ] {
        let shape = shapes.iter().find(|shape| shape.name == name).unwrap();
        assert_eq!(shape.opcode, opcode);
        assert_eq!(shape.length, length);
        assert_eq!(shape.operations.len(), operation_count);
    }

    let opcode_274 = shapes
        .iter()
        .find(|shape| shape.name == "client_opcode_274_opaque_text_record")
        .unwrap();
    assert_eq!(opcode_274.opcode, 274);
    assert_eq!(opcode_274.length, Some(1_698));
    assert_eq!(opcode_274.operations.len(), 10);

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
        ("client_npc_interaction_request", 64, 10, 4),
        ("client_recovery_request", 101, 11, 7),
        ("client_opcode_111_cash_slot_action", 111, 8, 3),
        ("inventory_move_request", 79, 13, 6),
        ("item_use_request", 80, 12, 4),
        ("client_reactor_hit_request", 225, 16, 5),
        ("compact_item_pickup_request", 222, 19, 7),
        ("client_opcode_276_compact", 276, 9, 4),
        ("client_opcode_276_grouped", 276, 210, 6),
        ("client_item_acquisition_request", 298, 76, 20),
        ("server_opcode_135_bootstrap_ledger", 135, 3_725, 10),
        ("server_opcode_142_text_ledger_large", 142, 254, 5),
        ("server_opcode_142_text_ledger_compact", 142, 190, 5),
        ("server_opcode_394_text_envelope", 394, 119, 2),
        ("client_opcode_279_text_envelope", 279, 120, 3),
        ("client_world_exit_request", 241, 2, 1),
        ("client_ability_point_allocation_request", 100, 26, 4),
        ("client_opcode_307_neutral_record", 307, 14, 4),
        ("client_opcode_310_text_record", 310, 41, 4),
        ("client_opcode_308_periodic_record", 308, 74, 11),
        ("client_opcode_311_periodic_record", 311, 22, 4),
        ("login_server_opcode_20_u32", 20, 6, 2),
        ("login_server_opcode_21_zero", 21, 3, 2),
        ("login_server_opcode_23_zero", 23, 6, 2),
        ("login_server_opcode_161_zero", 161, 3, 2),
        ("server_opcode_425_value_ledger", 425, 68, 7),
    ] {
        let shape = shapes.iter().find(|shape| shape.name == name).unwrap();
        assert_eq!(shape.opcode, opcode);
        assert_eq!(shape.length, Some(length));
        assert_eq!(shape.operations.len(), operation_count);
    }

    let opcode_158 = shapes
        .iter()
        .find(|shape| shape.name == "client_opcode_158_request")
        .unwrap();
    assert_eq!(opcode_158.opcode, 158);
    assert_eq!(opcode_158.length, None);
    assert_eq!(opcode_158.operations.len(), 4);

    let ranged_attack = shapes
        .iter()
        .find(|shape| shape.name == "server_ranged_attack_relay")
        .unwrap();
    assert_eq!(ranged_attack.opcode, 219);
    assert_eq!(ranged_attack.length, None);
    assert!(ranged_attack.operations.iter().any(|operation| {
        matches!(
            operation,
            ShapeOp::BitField {
                name,
                field,
                shift: 4,
                mask: 15,
            } if name == "target_count" && field == "packed_counts"
        )
    }));
    assert!(!shapes.iter().any(|shape| {
        shape
            .name
            .starts_with("observed_server_to_client_opcode_219_")
    }));

    for (name, opcode) in [("client_action_50", 50), ("client_action_52", 52)] {
        let attack = shapes.iter().find(|shape| shape.name == name).unwrap();
        assert_eq!(attack.opcode, opcode);
        assert_eq!(attack.length, None);
        assert!(attack.operations.iter().any(|operation| {
            matches!(
                operation,
                ShapeOp::BitField {
                    name,
                    field,
                    shift: 4,
                    mask: 15,
                } if name == "target_count" && field == "variant"
            )
        }));
        assert!(attack.operations.iter().any(|operation| {
            matches!(
                operation,
                ShapeOp::Repeat {
                    count_from,
                    operations,
                } if count_from == "target_count"
                    && operations.iter().any(|nested| {
                        matches!(
                            nested,
                            ShapeOp::Repeat { count_from, .. }
                                if count_from == "hit_count"
                        )
                    })
            )
        }));
    }

    for (name, opcode, length) in [
        ("server_opcode_230_u32_long_tail", 230, 13),
        ("server_opcode_232_u32_opaque_tail", 232, 22),
    ] {
        let shape = shapes.iter().find(|shape| shape.name == name).unwrap();
        assert_eq!(shape.opcode, opcode);
        assert_eq!(shape.length, Some(length));
        assert_eq!(shape.operations.len(), 3);
    }

    for (name, opcode, length, reserved_length) in [
        ("server_opcode_228_u32_reserved_zero", 228, 10, 4),
        ("server_opcode_231_u32_reserved_zero", 231, 26, 20),
        ("server_opcode_234_u32_reserved_zero", 234, 9, 3),
        ("server_opcode_235_u32_reserved_zero", 235, 12, 6),
    ] {
        let shape = shapes.iter().find(|shape| shape.name == name).unwrap();
        assert_eq!(shape.opcode, opcode);
        assert_eq!(shape.length, Some(length));
        assert!(matches!(
            shape.operations.last().unwrap(),
            ShapeOp::Bytes {
                length,
                equals_hex: Some(value),
                ..
            } if *length == reserved_length
                && value == &"00".repeat(reserved_length)
        ));
    }

    let short_opcode_230 = shapes
        .iter()
        .find(|shape| shape.name == "server_opcode_230_u32_short_reserved_09")
        .unwrap();
    assert_eq!(short_opcode_230.opcode, 230);
    assert_eq!(short_opcode_230.length, Some(7));
    assert!(matches!(
        short_opcode_230.operations.last().unwrap(),
        ShapeOp::Bytes {
            length: 1,
            equals_hex: Some(value),
            ..
        } if value == "09"
    ));

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
            || shape.name == "observed_server_to_client_opcode_20_length_6"
            || shape.name == "observed_server_to_client_opcode_21_length_3"
            || shape.name == "observed_server_to_client_opcode_22_length_34447"
            || shape.name == "observed_server_to_client_opcode_23_length_6"
            || shape.name == "observed_server_to_client_opcode_161_length_3"
            || shape.name == "observed_client_to_server_opcode_46_length_6"
            || shape.name == "observed_client_to_server_opcode_6_length_1836"
            || shape.name == "observed_client_to_server_opcode_31_length_183"
            || shape.name == "observed_client_to_server_opcode_75_length_2"
            || shape.name == "observed_client_to_server_opcode_274_length_1698"
            || shape.name == "observed_client_to_server_opcode_279_length_120"
            || shape.name == "observed_client_to_server_opcode_241_length_2"
            || shape.name == "observed_client_to_server_opcode_100_length_26"
            || shape.name == "observed_client_to_server_opcode_307_length_14"
            || shape.name == "observed_client_to_server_opcode_308_length_74"
            || shape.name == "observed_client_to_server_opcode_311_length_22"
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
    assert_eq!(dump.packet_shapes.len(), 196);
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
