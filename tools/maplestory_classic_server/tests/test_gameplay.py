from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.gameplay import (  # noqa: E402
    GameplayPhase,
    GameplayStateFold,
    MAX_MOB_MOVEMENT_FOLLOW_UP_DECISIONS,
    MobHealthResponsePolicy,
    MobMovementBroadcastDecisionQueue,
    MobMovementBroadcastScheduler,
    MobMovementRelativeDecisionPolicy,
    PlayerMobProximityPredicate,
    analyze_gameplay_transcript,
    build_mob_movement_planning_context,
    derive_item_pickup_response_policy,
    derive_item_use_response_policy,
    derive_mob_movement_acknowledgement_policy,
    plan_composed_mob_movement_broadcasts,
    plan_mob_movement_broadcast,
    plan_current_hp_stat_update,
    plan_fixed_server_record_replay,
    plan_field_npc_spawn_replay,
    plan_final_field_drop_owner_to_player_rewrite,
    plan_final_field_drop_position_rewrite,
    plan_inventory_quantity_update,
    plan_initial_field_snapshot_replay,
    plan_initial_player_hp_rewrite,
    plan_variable_server_record_replay,
    plan_final_field_npc_state_replay,
    mob_hp_bounds_for_percentage,
    predict_mob_health_percentage_range,
    render_gameplay_analysis,
    world_session_termination_frame_index,
)
from maple_server.gamestate import PlainFrame  # noqa: E402
from maple_server.packets import (  # noqa: E402
    CharacterStatUpdate,
    ClientAttackAction,
    ClientOpcode43Envelope,
    ClientOpcode101Record,
    ClientOpcode114TextEnvelope,
    ClientOpcode122Envelope,
    ClientOpcode217RecordSet,
    ClientOpcode309Acknowledgement,
    ClientOpcode54AttackAction,
    ClientSkillUseRequest,
    CompactFieldTransition,
    CompactInitialProgressionSnapshot,
    FieldDropRemoval,
    FieldDropSpawn,
    FixedServerEmptyRecord,
    FixedServerI32Record,
    FixedServerOpcode11Record,
    FixedServerU16PairRecord,
    FixedServerU16Record,
    FixedServerU32PairRecord,
    FixedServerU32Record,
    FixedServerU64Record,
    FixedServerU8Record,
    FieldLoadStage,
    FieldSnapshotEnvelope,
    HeartbeatProbe,
    HeartbeatResponse,
    InitialCharacterSnapshot,
    InitialCharacterContextRecord,
    InitialFieldTrailer,
    InitialFieldSnapshot,
    InitialInventoryItem,
    InitialInventorySnapshot,
    InitialProgressionSnapshot,
    TypedInitialFieldSnapshot,
    VariableServerEntry,
    VariableServerRecord,
    InventoryChangeSet,
    InventoryModification,
    ItemPickupRequest,
    ItemUseRequest,
    LifeMovementBroadcast,
    LifeMovementCommand,
    LifeMovementPath,
    LifeMovementSubmission,
    LocalTemporaryStatSetHeader,
    MobControllerChange,
    MobEnterField,
    MobHealthPercentageUpdate,
    MobLeaveField,
    MobMovementAcknowledgement,
    MobMovementBroadcast,
    MobMovementCommand,
    MobMovementPath,
    MobMovementSubmission,
    MobSpawnData,
    MobTemporaryStatReset,
    MobTemporaryStatSet,
    NpcLifecycleControl,
    NpcSpawn,
    NpcStateUpdate,
    Opcode13Envelope,
    Opcode13Type1Envelope,
    PacketShapeError,
    PlayerMovementBroadcast,
    PlayerMovementCommand,
    PlayerMovementPath,
    PlayerMovementSubmission,
    PickupGainNotice,
    RemotePlayerEnterField,
    RemotePlayerLeaveField,
    RemotePlayerMobValueRecord,
    ServerAttackRelay,
    ServerOpcode43Envelope,
    ServerOpcode69Record,
    ServerOpcode93Record,
    ServerOpcode94Record,
    ServerOpcode148Envelope,
    ServerOpcode201Record,
    ServerOpcode205Record,
    ServerOpcode239Envelope,
    ServerOpcode239ValueRecord,
    ServerOpcode244DialogueInstruction,
    ServerOpcode320PositionedEffectRecord,
    ServerOpcode322PositionedEffectRecord,
    ServerOpcode323PositionedEffectRecord,
    ServerOpcode348TextEnvelope,
    ServerOpcode379Record,
    ServerOpcode49Envelope,
    ServerOpcode77Envelope,
    ServerOpcode426Notification,
    SkillLevelChangeRequest,
    SkillRecordEntry,
    SkillRecordUpdate,
    SkillRecordUpdateAcknowledgement,
    TutorialUiInstruction,
    WorldBootstrapAcknowledgement,
    WorldEntryRequest,
    WorldSessionTermination,
)
from maple_server.protocol import (  # noqa: E402
    crypt_payload,
    encode_frame_header,
    shuffle_iv,
)
from maple_server.transcript import Transcript, TranscriptEvent  # noqa: E402


FIRST_IV = bytes.fromhex("6e3c795a")
SECOND_IV = bytes.fromhex("885db958")
HANDSHAKE = bytes.fromhex(
    "1f00 2c01 0300 330030003000 6e3c795a 885db958 04 "
    "2c010000 2c010000 00000000"
)
CHARACTER_ID = 300_001
NPC_OBJECT_ID = 10_001
MOB_OBJECT_ID = 20_001
PLAYER_OBJECT_ID = 30_001
PERMANENT_ITEM_EXPIRATION = 150_842_304_000_000_000


def fixture_attack_relay_body(
    *,
    prefix_length: int,
    target_count: int,
    hit_count: int,
    tail_length: int,
    zero_targets: bool = False,
) -> bytes:
    if tail_length == 4:
        ranged_prefixes = {
            11: bytes.fromhex("10000016000600e06e1f00"),
            15: bytes.fromhex("1008400e3d00001a800600f0951f00"),
        }
        body = bytearray(ranged_prefixes[prefix_length])
    else:
        melee_prefixes = {
            6: bytes.fromhex("080000050004"),
            11: bytes.fromhex("0800000500040000000000"),
        }
        body = bytearray(melee_prefixes[prefix_length])
    for target_index in range(target_count):
        object_id = 0 if zero_targets else MOB_OBJECT_ID + target_index
        body.extend(object_id.to_bytes(4, "little"))
        body.append(0 if zero_targets else 6)
        for hit_index in range(hit_count):
            damage = 0 if zero_targets else 40 + target_index + hit_index
            if not zero_targets and hit_index == 0:
                damage |= 0x8000_0000
            body.extend(damage.to_bytes(4, "little"))
    if tail_length == 4:
        body.extend(struct.pack("<hh", 122, -198))
    else:
        body.extend(b"\x00" * tail_length)
    return bytes(body)


def fixture_npc() -> NpcSpawn:
    return NpcSpawn(
        object_id=NPC_OBJECT_ID,
        template_id=1_032_000,
        x=-120,
        cy=45,
        facing_value=1,
        foothold_id=7,
        range_left=-300,
        range_right=200,
        hidden=False,
    )


def fixture_fixed_server_records() -> tuple[object, ...]:
    return (
        FixedServerEmptyRecord(opcode=24),
        FixedServerU8Record(opcode=105, value=0),
        FixedServerOpcode11Record(reserved_u32=0, reserved_u8=0),
        FixedServerU16PairRecord(value_1=6, value_2=17),
        FixedServerEmptyRecord(opcode=178),
        InitialCharacterContextRecord(
            character_id=CHARACTER_ID,
            context_flag=1,
            reserved_u32s=(0, 0, 0),
        ),
        FixedServerU32Record(opcode=386, value=0),
        FixedServerU32Record(opcode=389, value=0),
        FixedServerU32Record(opcode=388, value=0xFDE04000),
        FixedServerU16Record(value=0x1800),
        FixedServerU8Record(opcode=58, value=1),
        FixedServerEmptyRecord(opcode=45),
        FixedServerU8Record(opcode=71, value=53),
        FixedServerU8Record(opcode=89, value=0),
        FixedServerU8Record(opcode=121, value=0),
        FixedServerU16Record(opcode=72, value=7),
        FixedServerU16Record(opcode=74, value=26),
        FixedServerI32Record(opcode=60, value=1_037),
        FixedServerU32Record(opcode=112, value=0),
        FixedServerU32Record(opcode=131, value=0),
        FixedServerU32Record(opcode=301, value=3_290),
        FixedServerU32PairRecord(
            value_1=999_999_999,
            value_2=999_999_999,
        ),
        FixedServerU64Record(
            opcode=398,
            value=134_305_036_800_000_000,
        ),
    )


def fixture_variable_server_records() -> tuple[VariableServerRecord, ...]:
    keyboard_bindings = [
        VariableServerEntry(selector=0, value=0) for _ in range(89)
    ]
    keyboard_bindings[2] = VariableServerEntry(selector=4, value=10)
    keyboard_bindings[29] = VariableServerEntry(
        selector=1, value=2_001_005
    )
    keyboard_bindings[71] = VariableServerEntry(
        selector=1, value=2_001_002
    )
    return (
        VariableServerRecord(opcode=156, variant=0, opaque_tail=b""),
        VariableServerRecord(
            opcode=156,
            variant=1,
            text="x",
            flag=False,
            values=(0x11111111, 0, 0),
        ),
        VariableServerRecord(
            opcode=385,
            variant=0,
            entries=tuple(keyboard_bindings),
        ),
        VariableServerRecord(opcode=385, variant=1, opaque_tail=b""),
    )


def fixture_movement_path() -> MobMovementPath:
    return MobMovementPath(
        opaque_control=b"\x00anitized-control".ljust(19, b"\x00"),
        reference_x=100,
        reference_y=-200,
        commands=(
            MobMovementCommand.absolute(
                position_x=110,
                position_y=-200,
                velocity_x=10,
                velocity_y=0,
                foothold_id=7,
                stance=2,
                duration_ms=90,
            ),
        ),
        trailer_marker=0,
        path_start_x=90,
        path_start_y=-200,
        path_end_x=110,
        path_end_y=-200,
    )


def fixture_player_movement_path() -> PlayerMovementPath:
    return PlayerMovementPath(
        reference_x=100,
        reference_y=-200,
        commands=(
            PlayerMovementCommand.absolute(
                position_x=110,
                position_y=-195,
                velocity_x=10,
                velocity_y=5,
                foothold_id=7,
                stance=2,
                duration_ms=90,
            ),
            PlayerMovementCommand.relative(
                velocity_x=4,
                velocity_y=-8,
                stance=3,
                duration_ms=12,
            ),
            PlayerMovementCommand.compact(b"\x01\x02\x03\x04\x05"),
            PlayerMovementCommand.absolute(
                command_type=5,
                position_x=120,
                position_y=-180,
                velocity_x=6,
                velocity_y=0,
                foothold_id=8,
                stance=4,
                duration_ms=40,
            ),
            PlayerMovementCommand.absolute(
                position_x=130,
                position_y=-170,
                velocity_x=2,
                velocity_y=1,
                foothold_id=9,
                stance=5,
                duration_ms=20,
            ),
        ),
    )


def fixture_life_movement_path() -> LifeMovementPath:
    return LifeMovementPath(
        reference_x=100,
        reference_y=-200,
        commands=(
            LifeMovementCommand(command_type=0, opaque_payload=b"\x00" * 13),
            LifeMovementCommand(command_type=2, opaque_payload=b"\x00" * 7),
            LifeMovementCommand(command_type=10, opaque_payload=b"\x00"),
            LifeMovementCommand(command_type=14, opaque_payload=b"\x00" * 9),
            LifeMovementCommand(command_type=15, opaque_payload=b"\x00" * 15),
        ),
    )


def fixture_stack_inventory_item(
    *, slot: int, item_id: int, quantity: int
) -> InitialInventoryItem:
    expires_at_ticks = 150_842_304_000_000_000
    item_sentinel_ticks = 94_354_848_000_000_000
    raw_record = b"".join(
        (
            struct.pack(
                "<BIBqH", 2, item_id, 0, expires_at_ticks, quantity
            ),
            b"\x00\x00\x00",
            b"\x00" * 10,
            struct.pack("<qI", item_sentinel_ticks, 0),
        )
    )
    return InitialInventoryItem(
        slot=slot,
        record_type=2,
        item_id=item_id,
        cash_item=False,
        expires_at_ticks=expires_at_ticks,
        quantity=quantity,
        raw_record=raw_record,
    )


def fixture_equipment_inventory_item(
    *, slot: int, item_id: int
) -> InitialInventoryItem:
    expires_at_ticks = 150_842_304_000_000_000
    item_sentinel_ticks = 94_354_848_000_000_000
    raw_record = b"".join(
        (
            struct.pack("<BIBq", 1, item_id, 0, expires_at_ticks),
            b"\x00" * 12,
            struct.pack("<q", item_sentinel_ticks),
            b"\xff" * 4,
            b"\x00" * 8,
            struct.pack("<qI", item_sentinel_ticks, 0),
        )
    )
    return InitialInventoryItem(
        slot=slot,
        record_type=1,
        item_id=item_id,
        cash_item=False,
        expires_at_ticks=expires_at_ticks,
        quantity=None,
        raw_record=raw_record,
    )


def fixture_cash_inventory_item(*, slot: int) -> InitialInventoryItem:
    item_id = 5_000_046
    expires_at_ticks = 150_842_304_000_000_000
    raw_record = b"".join(
        (
            struct.pack(
                "<BIBQq",
                3,
                item_id,
                1,
                123_456,
                expires_at_ticks,
            ),
            b"\x00\x00\x00",
            struct.pack("<BHBq", 1, 2, 0, 3),
            b"\x00" * 4,
            struct.pack("<IHBIHI", 4, 5, 0, 6, 7, 8),
        )
    )
    return InitialInventoryItem(
        slot=slot,
        record_type=3,
        item_id=item_id,
        cash_item=True,
        expires_at_ticks=expires_at_ticks,
        quantity=None,
        raw_record=raw_record,
    )


def fixture_mob_spawn(*, extended_status: bool = False) -> MobSpawnData:
    return MobSpawnData(
        spawn_marker=1,
        template_id=210_100,
        opaque_status=b"\x00" * (30 if extended_status else 22),
        x=100,
        y=-200,
        stance=2,
        foothold_id=7,
        origin_foothold_id=8,
        spawn_effect=-1,
        opaque_tail=b"\x00" * 4,
    )


def fixture_field_drop_spawn(
    *,
    spawn_mode: int,
    drop_object_id: int,
    drop_kind: int,
    value: int,
    position_x: int,
    position_y: int,
) -> FieldDropSpawn:
    animated = spawn_mode in FieldDropSpawn.ANIMATED_MODES
    return FieldDropSpawn(
        spawn_mode=spawn_mode,
        drop_object_id=drop_object_id,
        drop_kind=drop_kind,
        value=value,
        owner_value_1=CHARACTER_ID,
        owner_value_2=CHARACTER_ID,
        ownership_flag=0,
        position_x=position_x,
        position_y=position_y,
        source_mob_object_id=MOB_OBJECT_ID if animated else 0,
        source_x=100 if animated else None,
        source_y=-200 if animated else None,
        animation_duration_ms=450 if animated else None,
        expiration_ticks=(
            PERMANENT_ITEM_EXPIRATION
            if drop_kind == FieldDropSpawn.ITEM
            else None
        ),
        final_flag=1 if animated else 0,
    )


def fixture_compact_field_transition() -> CompactFieldTransition:
    return CompactFieldTransition(
        marker=23,
        reserved_flag=0,
        transition_sequence=2,
        map_id=100_050_000,
        portal_index=15,
        current_hp=70,
        reserved_u16=0,
        opaque_text_1="1",
        opaque_text_2="1",
        opaque_text_3="sanitized-field!",
        reserved_u32=0,
        constant_u32=2,
        reserved_flag_2=0,
        sentinel_filetime_ticks=94_354_848_000_000_000,
        server_local_filetime_ticks=134_306_812_696_980_000,
        unknown_tail_u32=2,
    )


def fixture_initial_progression_snapshot() -> InitialProgressionSnapshot:
    expected_block = b"\x01\x01\x01\x00" + b"\xff" * 4 + b"\x00" * 9
    return InitialProgressionSnapshot(
        reserved_flag=0,
        skill_levels=((2_001_002, 1), (2_001_005, 6)),
        reserved_u16_1=0,
        string_properties=((2_089, ""),),
        timestamp_properties=((1_015, 134_305_973_644_300_000),),
        reserved_i64=0,
        saved_map_ids=(999_999_999,) * 15 + (0,),
        reserved_flag_2=0,
        constant_u32=1,
        variant=1,
        extended_properties=((7_995, "N=0"),),
        reserved_u16_2=0,
        trailer=InitialFieldTrailer(
            opaque_blocks=(expected_block, expected_block),
            reserved_u16=0,
            opaque_texts=("", "1", "1", "sanitized-field!", ""),
            constant_u8=2,
            reserved_u32=0,
            sentinel_filetime_ticks=94_354_848_000_000_000,
            server_local_filetime_ticks=134_306_812_493_680_000,
            unknown_tail_u32=7,
        ),
    )


def fixture_compact_initial_progression_snapshot(
) -> CompactInitialProgressionSnapshot:
    expected_block = b"\x01\x01\x01\x00" + b"\xff" * 4 + b"\x00" * 9
    return CompactInitialProgressionSnapshot(
        reserved_flag=0,
        skill_levels=((12, 0),),
        reserved_u16_1=0,
        string_properties=(),
        timestamp_properties=(),
        reserved_i64=0,
        saved_map_ids=(999_999_999,) * 15 + (0,),
        opaque_variant_header=b"\x00" * 7,
        trailer=InitialFieldTrailer(
            opaque_blocks=(expected_block, expected_block),
            reserved_u16=0,
            opaque_texts=("", "", "", "", ""),
            constant_u8=0,
            reserved_u32=0,
            sentinel_filetime_ticks=94_354_848_000_000_000,
            server_local_filetime_ticks=134_306_812_493_680_000,
            unknown_tail_u32=1,
        ),
    )


def fixture_initial_field_snapshot() -> InitialFieldSnapshot:
    item_sentinel_ticks = 94_354_848_000_000_000
    use_item_record = b"".join(
        (
            struct.pack("<BIBqH", 2, 2_000_000, 0, 150_842_304_000_000_000, 3),
            b"\x00\x00\x00",
            b"\x00" * 10,
            struct.pack("<qI", item_sentinel_ticks, 0),
        )
    )
    inventory_tail = b"".join(
        (
            b"\x00" * 22,
            struct.pack("<q", item_sentinel_ticks),
            b"\x00" * 5,
            b"\x01" + use_item_record + b"\x00",
            b"\x00" * 3,
            fixture_initial_progression_snapshot().to_bytes(),
        )
    )
    return InitialFieldSnapshot(
        marker=23,
        reserved_flag=0,
        contains_character_data=1,
        character_data_mode=1,
        reserved_u16=0,
        opaque_session_u32s=(101, 202, 303),
        sentinel_i64=-1,
        character_record_prefix=0,
        character=InitialCharacterSnapshot(
            character_id=CHARACTER_ID,
            data_flags=4,
            name="player",
            gender=1,
            skin=0,
            face_id=21_201,
            hair_id=31_047,
            companion_id=0,
            level=12,
            job_id=200,
            strength=4,
            dexterity=4,
            intelligence=57,
            luck=15,
            current_hp=70,
            max_hp=222,
            current_mp=136,
            max_mp=342,
            ability_points=0,
            skill_points=5,
            experience=1_567,
            fame=0,
            map_id=101_000_000,
            portal_index=1,
            opaque_state_flag=1,
            opaque_state_u64=0,
        ),
        opaque_tail=inventory_tail,
    )


def fixture_compact_initial_field_snapshot() -> InitialFieldSnapshot:
    full = fixture_initial_field_snapshot()
    inventory = full.parse_inventory()
    return replace(
        full,
        marker=26,
        opaque_tail=replace(
            inventory,
            opaque_remainder=(
                fixture_compact_initial_progression_snapshot().to_bytes()
            ),
        ).to_bytes(),
    )


def fixture_gameplay_transcript(
    *,
    repeat_npc_update: bool = False,
    leave_mob: bool = False,
    terminate: bool = False,
    close: bool = True,
    acknowledgement_flag: int = 0,
    acknowledgement_auxiliary_1: int = 0,
    acknowledgement_auxiliary_2: int = 0,
    compact_transition: bool = False,
    initial_snapshot: bool = False,
    initial_snapshot_payload: bytes | None = None,
    player_movement: bool = False,
    attack_actions: bool = False,
    opcode_101_records: bool = False,
    opcode_13_messages: bool = False,
    opcode_217_records: bool = False,
    opcode_426_acknowledgement: bool = False,
    skill_record_lifecycle: bool = False,
    stat_updates: bool = False,
    inventory_changes: bool = False,
    item_use: bool = False,
    item_pickup: bool = False,
    active_item_drop: bool = False,
    active_item_drop_owner: int | None = None,
    extra_server_plaintexts: tuple[bytes, ...] = (),
    extra_client_plaintexts: tuple[bytes, ...] = (),
) -> Transcript:
    events = [
        TranscriptEvent(event="connect", timestamp_ns=1),
        TranscriptEvent(
            event="data",
            timestamp_ns=2,
            direction="server_to_client",
            data=HANDSHAKE,
        ),
    ]
    ivs = {
        "client_to_server": FIRST_IV,
        "server_to_client": SECOND_IV,
    }
    masks = {"client_to_server": 3, "server_to_client": ~300}
    timestamp_ns = 3

    def append(direction: str, plaintext: bytes) -> None:
        nonlocal timestamp_ns
        iv = ivs[direction]
        wire = (
            encode_frame_header(len(plaintext), iv, masks[direction])
            + crypt_payload(plaintext, iv)
        )
        ivs[direction] = shuffle_iv(iv)
        events.append(
            TranscriptEvent(
                event="data",
                timestamp_ns=timestamp_ns,
                direction=direction,
                data=wire,
            )
        )
        timestamp_ns += 1

    append(
        "client_to_server",
        WorldEntryRequest(
            entry_value=4,
            character_id=CHARACTER_ID,
            opaque_ticket=b"sanitized-ticket".ljust(56, b"\x00"),
        ).to_bytes(),
    )
    append(
        "server_to_client",
        (
            initial_snapshot_payload
            if initial_snapshot_payload is not None
            else fixture_initial_field_snapshot().to_bytes()
            if initial_snapshot
            else FieldSnapshotEnvelope(
                opaque_snapshot=b"sanitized-field"
            ).to_bytes()
        ),
    )
    append("server_to_client", fixture_npc().to_bytes())
    append(
        "server_to_client",
        NpcStateUpdate(
            object_id=NPC_OBJECT_ID,
            action=3,
            parameter=1,
        ).to_bytes(),
    )
    append(
        "server_to_client",
        MobEnterField(
            object_id=MOB_OBJECT_ID,
            spawn=fixture_mob_spawn(),
        ).to_bytes(),
    )
    append(
        "server_to_client",
        MobControllerChange(
            control_level=1,
            object_id=MOB_OBJECT_ID,
            spawn=fixture_mob_spawn(),
        ).to_bytes(),
    )
    append(
        "server_to_client",
        MobMovementBroadcast(
            object_id=MOB_OBJECT_ID,
            opaque_control=b"\x00\x00\xff\x00\x00\x00\x00",
            reference_x=100,
            reference_y=-200,
            commands=fixture_movement_path().commands,
        ).to_bytes(),
    )
    append(
        "client_to_server",
        WorldBootstrapAcknowledgement(opaque_value=0).to_bytes(),
    )
    append("client_to_server", FieldLoadStage(stage=1).to_bytes())
    append("client_to_server", FieldLoadStage(stage=2).to_bytes())
    for health_percentage in (75, 50, 0):
        append(
            "server_to_client",
            MobHealthPercentageUpdate(
                object_id=MOB_OBJECT_ID,
                health_percentage=health_percentage,
            ).to_bytes(),
        )
    if stat_updates:
        append(
            "server_to_client",
            CharacterStatUpdate(
                request_flag=0,
                stat_mask=(
                    CharacterStatUpdate.CURRENT_HP
                    | CharacterStatUpdate.EXPERIENCE
                ),
                current_hp=77,
                experience=2_000,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            CharacterStatUpdate(
                request_flag=1,
                stat_mask=CharacterStatUpdate.MESOS,
                mesos=9_001,
            ).to_bytes(),
        )
    if inventory_changes:
        append(
            "server_to_client",
            InventoryChangeSet(
                update_flag=0,
                modifications=(
                    InventoryModification(
                        operation=InventoryModification.UPDATE_QUANTITY,
                        inventory_type=2,
                        slot=1,
                        quantity=5,
                    ),
                    InventoryModification(
                        operation=InventoryModification.ADD,
                        inventory_type=4,
                        slot=2,
                        item=fixture_stack_inventory_item(
                            slot=2,
                            item_id=4_010_003,
                            quantity=1,
                        ),
                    ),
                    InventoryModification(
                        operation=InventoryModification.ADD,
                        inventory_type=1,
                        slot=2,
                        item=fixture_equipment_inventory_item(
                            slot=2,
                            item_id=1_000_002,
                        ),
                    ),
                    InventoryModification(
                        operation=InventoryModification.MOVE,
                        inventory_type=1,
                        slot=2,
                        destination_slot=-11,
                        move_flag=2,
                    ),
                ),
            ).to_bytes(),
        )
    if item_use:
        append(
            "client_to_server",
            ItemUseRequest(
                client_tick=102_034,
                slot=1,
                item_id=2_000_000,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            InventoryChangeSet(
                update_flag=0,
                modifications=(
                    InventoryModification(
                        operation=InventoryModification.UPDATE_QUANTITY,
                        inventory_type=2,
                        slot=1,
                        quantity=2,
                    ),
                ),
            ).to_bytes(),
        )
        append(
            "server_to_client",
            CharacterStatUpdate(
                request_flag=1,
                stat_mask=CharacterStatUpdate.CURRENT_HP,
                current_hp=120,
            ).to_bytes(),
        )
    if item_pickup:
        for spawn_mode in (1, 0):
            append(
                "server_to_client",
                fixture_field_drop_spawn(
                    spawn_mode=spawn_mode,
                    drop_object_id=40_001,
                    drop_kind=FieldDropSpawn.ITEM,
                    value=4_010_003,
                    position_x=120,
                    position_y=-210,
                ).to_bytes(),
            )
        append(
            "client_to_server",
            ItemPickupRequest(
                control_value=0,
                field_epoch=1,
                client_tick=102_040,
                position_x=120,
                position_y=-210,
                drop_object_id=40_001,
                item_validation_token=1_352_639_939,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            InventoryChangeSet(
                update_flag=0,
                modifications=(
                    InventoryModification(
                        operation=InventoryModification.ADD,
                        inventory_type=4,
                        slot=20,
                        item=fixture_stack_inventory_item(
                            slot=20,
                            item_id=4_010_003,
                            quantity=1,
                        ),
                    ),
                ),
            ).to_bytes(),
        )
        append(
            "server_to_client",
            PickupGainNotice(
                result_flag=0,
                kind=PickupGainNotice.ITEM,
                item_id=4_010_003,
                quantity=1,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            FieldDropRemoval(
                reason=5,
                drop_object_id=40_001,
                actor_id=CHARACTER_ID,
                trailing_value=0,
            ).to_bytes(),
        )
        for spawn_mode in (1, 0):
            append(
                "server_to_client",
                fixture_field_drop_spawn(
                    spawn_mode=spawn_mode,
                    drop_object_id=40_002,
                    drop_kind=FieldDropSpawn.MESOS,
                    value=16,
                    position_x=121,
                    position_y=-210,
                ).to_bytes(),
            )
        append(
            "client_to_server",
            ItemPickupRequest(
                control_value=0,
                field_epoch=1,
                client_tick=102_041,
                position_x=121,
                position_y=-210,
                drop_object_id=40_002,
                item_validation_token=0,
                optional_proof=bytes.fromhex("00112233445566778899aabb"),
            ).to_bytes(),
        )
        append(
            "server_to_client",
            CharacterStatUpdate(
                request_flag=1,
                stat_mask=CharacterStatUpdate.MESOS,
                mesos=16,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            PickupGainNotice(
                result_flag=0,
                kind=PickupGainNotice.MESOS,
                mesos_subkind=0,
                mesos_amount=16,
                mesos_tail=0,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            FieldDropRemoval(
                reason=5,
                drop_object_id=40_002,
                actor_id=CHARACTER_ID,
                trailing_value=0,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            fixture_field_drop_spawn(
                spawn_mode=FieldDropSpawn.FIELD_LOAD_MODE,
                drop_object_id=40_003,
                drop_kind=FieldDropSpawn.ITEM,
                value=2_380_000,
                position_x=122,
                position_y=-210,
            ).to_bytes(),
        )
        append(
            "client_to_server",
            ItemPickupRequest(
                control_value=0,
                field_epoch=1,
                client_tick=102_042,
                position_x=122,
                position_y=-210,
                drop_object_id=40_003,
                item_validation_token=3_854_219_900,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            PickupGainNotice(
                result_flag=0,
                kind=PickupGainNotice.SPECIAL,
                special_value=2_380_000,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            FieldDropRemoval(
                reason=5,
                drop_object_id=40_003,
                actor_id=CHARACTER_ID,
                trailing_value=0,
            ).to_bytes(),
        )
    if active_item_drop:
        active_drop = fixture_field_drop_spawn(
            spawn_mode=FieldDropSpawn.FIELD_LOAD_MODE,
            drop_object_id=40_004,
            drop_kind=FieldDropSpawn.ITEM,
            value=4_010_003,
            position_x=-863,
            position_y=-1742,
        )
        if active_item_drop_owner is not None:
            active_drop = replace(
                active_drop,
                owner_value_1=active_item_drop_owner,
                owner_value_2=active_item_drop_owner,
            )
        append(
            "server_to_client",
            active_drop.to_bytes(),
        )
    if player_movement:
        append(
            "client_to_server",
            PlayerMovementSubmission(
                control_value=0,
                movement=fixture_player_movement_path(),
                trailer_marker=0,
                path_start_x=90,
                path_start_y=-205,
                path_end_x=132,
                path_end_y=-168,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            PlayerMovementBroadcast(
                object_id=PLAYER_OBJECT_ID,
                control_value=1,
                movement=fixture_player_movement_path(),
            ).to_bytes(),
        )
        append(
            "client_to_server",
            LifeMovementSubmission(
                local_object_index=7,
                client_token=123_456,
                control_value=0,
                movement=fixture_life_movement_path(),
                tail_type=17,
                opaque_tail_state=b"\x00" * 8,
                tail_marker=4,
                path_start_x=90,
                path_start_y=-205,
                path_end_x=132,
                path_end_y=-168,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            LifeMovementBroadcast(
                object_id=PLAYER_OBJECT_ID,
                movement=fixture_life_movement_path(),
            ).to_bytes(),
        )
    append(
        "client_to_server",
        MobMovementSubmission(
            object_id=MOB_OBJECT_ID,
            sequence=9,
            opaque_movement=fixture_movement_path().to_bytes(),
        ).to_bytes(),
    )
    append(
        "server_to_client",
        MobMovementAcknowledgement(
            object_id=MOB_OBJECT_ID,
            sequence=9,
            status_flag=acknowledgement_flag,
            status_value=35,
            status_auxiliary_1=acknowledgement_auxiliary_1,
            status_auxiliary_2=acknowledgement_auxiliary_2,
        ).to_bytes(),
    )
    if leave_mob:
        append(
            "server_to_client",
            MobLeaveField(object_id=MOB_OBJECT_ID, reason=0).to_bytes(),
        )
    if attack_actions:
        append(
            "client_to_server",
            ClientAttackAction(
                opcode=50,
                local_object_index=7,
                variant=1,
                client_token=987_654_321,
                control_value=364_200,
                opaque_common_state=b"state",
                value_1=1,
                value_2=0,
                opaque_suffix=b"",
            ).to_bytes(),
        )
        append(
            "client_to_server",
            ClientAttackAction(
                opcode=50,
                local_object_index=7,
                variant=17,
                client_token=987_654_322,
                control_value=364_201,
                opaque_common_state=b"state",
                value_1=1,
                value_2=MOB_OBJECT_ID,
                opaque_suffix=(
                    b"\x06"
                    + b"\x00" * 13
                    + struct.pack("<I", 0x8000_0028)
                    + b"\x00" * 8
                ),
            ).to_bytes(),
        )
        append(
            "client_to_server",
            ClientAttackAction(
                opcode=52,
                local_object_index=7,
                variant=2,
                client_token=987_654_323,
                control_value=807_665,
                opaque_common_state=b"state",
                value_1=3,
                value_2=0,
                opaque_suffix=b"\x00",
            ).to_bytes(),
        )
        append(
            "client_to_server",
            ClientAttackAction(
                opcode=52,
                local_object_index=7,
                variant=18,
                client_token=987_654_324,
                control_value=807_666,
                opaque_common_state=b"state",
                value_1=3,
                value_2=MOB_OBJECT_ID,
                opaque_suffix=(
                    b"\x06"
                    + b"\x00" * 13
                    + struct.pack("<II", 0x8000_0028, 41)
                    + b"\x00" * 9
                ),
            ).to_bytes(),
        )
        append(
            "client_to_server",
            ClientOpcode54AttackAction(
                control_value=364_201,
                flag_1=255,
                flag_2=0,
                value_1=1,
                value_2=100_100,
                target_object_id=MOB_OBJECT_ID,
                tail_value=1,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            ServerAttackRelay(
                opcode=218,
                object_id=PLAYER_OBJECT_ID,
                packed_counts=0x11,
                opaque_body=fixture_attack_relay_body(
                    prefix_length=11,
                    target_count=1,
                    hit_count=1,
                    tail_length=0,
                ),
            ).to_bytes(),
        )
        append(
            "server_to_client",
            ServerAttackRelay(
                opcode=219,
                object_id=PLAYER_OBJECT_ID,
                packed_counts=0x12,
                opaque_body=fixture_attack_relay_body(
                    prefix_length=15,
                    target_count=1,
                    hit_count=2,
                    tail_length=4,
                ),
            ).to_bytes(),
        )
    if opcode_101_records:
        append(
            "client_to_server",
            ClientOpcode101Record(
                header_value=0,
                primary_value=20,
                flag_value=0,
                secondary_value=3,
                tail_value=0,
            ).to_bytes(),
        )
        append(
            "client_to_server",
            ClientOpcode101Record(
                header_value=0,
                primary_value=0x0A00_0014,
                flag_value=0,
                secondary_value=0,
                tail_value=0,
            ).to_bytes(),
        )
    if opcode_13_messages:
        append(
            "client_to_server",
            Opcode13Type1Envelope(opaque_payload=b"fixed123").to_bytes(),
        )
        append(
            "client_to_server",
            Opcode13Envelope(
                message_type=6,
                opaque_payload=b"variable-six",
            ).to_bytes(),
        )
        append(
            "client_to_server",
            Opcode13Envelope(
                message_type=13,
                opaque_payload=b"variable-thirteen",
            ).to_bytes(),
        )
    if opcode_217_records:
        append(
            "client_to_server",
            ClientOpcode217RecordSet(
                opaque_prefix=b"short!",
            ).to_bytes(),
        )
        append(
            "client_to_server",
            ClientOpcode217RecordSet(
                opaque_prefix=b"prefix-000",
                record_format=0,
                records=(b"a" * 14, b"b" * 14),
                opaque_trailer=b"trailer!",
            ).to_bytes(),
        )
        append(
            "client_to_server",
            ClientOpcode217RecordSet(
                opaque_prefix=b"prefix-002",
                record_format=2,
                records=(b"c" * 11, b"d" * 11),
                opaque_trailer=b"trailer?",
            ).to_bytes(),
        )
    if opcode_426_acknowledgement:
        append("server_to_client", ServerOpcode426Notification().to_bytes())
        append(
            "client_to_server",
            ClientOpcode309Acknowledgement().to_bytes(),
        )
    if skill_record_lifecycle:
        append(
            "client_to_server",
            SkillLevelChangeRequest(
                client_tick=200_000,
                skill_id=2_001_005,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            SkillRecordUpdate(
                flag_a=True,
                flag_b=False,
                records=(
                    SkillRecordEntry(
                        skill_id=2_001_005,
                        level=7,
                        auxiliary_value=0,
                    ),
                ),
                trailing_value=2,
            ).to_bytes(),
        )
        append(
            "client_to_server",
            SkillRecordUpdateAcknowledgement(
                control_value=346,
                client_tick=200_450,
                trailing_value=0,
            ).to_bytes(),
        )
        append(
            "server_to_client",
            SkillRecordUpdate(
                flag_a=False,
                flag_b=False,
                records=(),
                trailing_value=4,
            ).to_bytes(),
        )
        append(
            "client_to_server",
            SkillRecordUpdateAcknowledgement(
                control_value=346,
                client_tick=200_451,
                trailing_value=0,
            ).to_bytes(),
        )
    append("server_to_client", HeartbeatProbe().to_bytes())
    append(
        "client_to_server",
        HeartbeatResponse(opaque_token=b"\x00" * 8).to_bytes(),
    )
    if compact_transition:
        append(
            "server_to_client",
            fixture_compact_field_transition().to_bytes(),
        )
    if repeat_npc_update:
        append(
            "server_to_client",
            NpcStateUpdate(
                object_id=NPC_OBJECT_ID,
                action=3,
                parameter=1,
            ).to_bytes(),
        )
    for plaintext in extra_server_plaintexts:
        append("server_to_client", plaintext)
    for plaintext in extra_client_plaintexts:
        append("client_to_server", plaintext)
    if terminate:
        append(
            "server_to_client",
            WorldSessionTermination(opaque_reason=b"ended!!").to_bytes(),
        )
    if close:
        events.append(TranscriptEvent(event="close", timestamp_ns=timestamp_ns))
    return Transcript(path=Path("sanitized-gameplay.jsonl"), events=tuple(events))


class GameplayPacketShapeTest(unittest.TestCase):
    def test_skill_record_change_lifecycle_round_trip(self) -> None:
        request_bytes = bytes.fromhex("6700affa0200e8030000")
        update_bytes = bytes.fromhex(
            "2e0001000100e8030000010000000000000002"
        )
        empty_update_bytes = bytes.fromhex("2e000000000002")
        acknowledgement_bytes = bytes.fromhex(
            "25015a01000071fc02000000"
        )
        request = SkillLevelChangeRequest(
            client_tick=195_247,
            skill_id=1_000,
        )
        update = SkillRecordUpdate(
            flag_a=True,
            flag_b=False,
            records=(
                SkillRecordEntry(
                    skill_id=1_000,
                    level=1,
                    auxiliary_value=0,
                ),
            ),
            trailing_value=2,
        )
        empty_update = SkillRecordUpdate(
            flag_a=False,
            flag_b=False,
            records=(),
            trailing_value=2,
        )
        acknowledgement = SkillRecordUpdateAcknowledgement(
            control_value=346,
            client_tick=195_697,
            trailing_value=0,
        )

        self.assertEqual(request.to_bytes(), request_bytes)
        self.assertEqual(SkillLevelChangeRequest.parse(request_bytes), request)
        self.assertEqual(update.to_bytes(), update_bytes)
        self.assertEqual(SkillRecordUpdate.parse(update_bytes), update)
        self.assertEqual(empty_update.to_bytes(), empty_update_bytes)
        self.assertEqual(
            SkillRecordUpdate.parse(empty_update_bytes), empty_update
        )
        self.assertEqual(
            acknowledgement.to_bytes(), acknowledgement_bytes
        )
        self.assertEqual(
            SkillRecordUpdateAcknowledgement.parse(acknowledgement_bytes),
            acknowledgement,
        )
        with self.assertRaisesRegex(PacketShapeError, "boolean"):
            SkillRecordUpdate.parse(bytes.fromhex("2e000200000002"))
        with self.assertRaisesRegex(PacketShapeError, "non-negative"):
            SkillRecordUpdate.parse(bytes.fromhex("2e000000ffff02"))

    def test_client_skill_use_request_round_trip(self) -> None:
        observed = bytes.fromhex("6800a40106006a881e00010000")
        restored = bytes.fromhex("68002c8409006a881e00010000")
        request = ClientSkillUseRequest(
            client_tick=393_636,
            skill_id=2_001_002,
            skill_level=1,
            trailing_value=0,
        )

        self.assertEqual(request.to_bytes(), observed)
        self.assertEqual(ClientSkillUseRequest.parse(observed), request)
        self.assertEqual(
            ClientSkillUseRequest.parse(restored),
            replace(request, client_tick=623_660),
        )
        with self.assertRaisesRegex(PacketShapeError, "skill_level"):
            replace(request, skill_level=256).to_bytes()

    def test_local_temporary_stat_zero_mask_header_round_trip(self) -> None:
        observed = bytes.fromhex("2a00" + "00" * 20)
        header = LocalTemporaryStatSetHeader(
            mask_words=(0, 0, 0, 0),
            zero_mask_flag_a=0,
            zero_mask_flag_b=0,
            zero_mask_trailing_i16=0,
        )

        self.assertEqual(header.to_bytes(), observed)
        self.assertEqual(LocalTemporaryStatSetHeader.parse(observed), header)
        self.assertTrue(header.zero_mask)
        self.assertEqual(header.enabled_bit_indices, ())
        self.assertEqual(header.safe_dict()["opaque_tail_length"], 0)
        padded_probe = bytes.fromhex("2a00" + "00" * 158)
        parsed_probe = LocalTemporaryStatSetHeader.parse(padded_probe)
        self.assertEqual(len(parsed_probe.opaque_tail), 138)
        self.assertEqual(parsed_probe.to_bytes(), padded_probe)
        with self.assertRaisesRegex(PacketShapeError, "needs 2 bytes"):
            LocalTemporaryStatSetHeader.parse(observed[:-1])

    def test_local_temporary_stat_nonzero_body_stays_opaque(self) -> None:
        header = LocalTemporaryStatSetHeader(
            mask_words=(1, 0, 0, 0),
            opaque_tail=b"opaque-entry-and-suffix",
        )

        self.assertEqual(
            LocalTemporaryStatSetHeader.parse(header.to_bytes()), header
        )
        self.assertEqual(header.enabled_bit_indices, (0,))
        with self.assertRaisesRegex(PacketShapeError, "remain opaque"):
            replace(header, zero_mask_flag_a=0).to_bytes()

    def test_server_opcode_77_variants_round_trip_with_redacted_text(
        self,
    ) -> None:
        envelopes = (
            ServerOpcode77Envelope(
                variant=3,
                primary_text="private message",
                control_bytes=(0, 4, 1),
            ),
            ServerOpcode77Envelope(variant=4, control_bytes=(0,)),
            ServerOpcode77Envelope(
                variant=4,
                primary_text="private notice",
                control_bytes=(1,),
            ),
            ServerOpcode77Envelope(
                variant=5,
                primary_text="SID_WORLDNOTICE_WEDDING_CATHEDRAL",
                secondary_text="private sender",
                tertiary_text="private recipient",
                control_bytes=ServerOpcode77Envelope.VARIANT_5_CONTROLS,
                terminal_u32=28,
            ),
            ServerOpcode77Envelope(
                variant=8,
                primary_text="private child text",
                opaque_tail=b"\x00\x07\x00\x00",
            ),
        )

        for envelope in envelopes:
            with self.subTest(variant=envelope.variant):
                encoded = envelope.to_bytes()
                self.assertEqual(
                    ServerOpcode77Envelope.parse(encoded), envelope
                )
                safe = str(envelope.safe_dict())
                self.assertNotIn("private", safe)

        captured_variant_5 = bytes.fromhex(
            "4d000521005300490044005f0057004f0052004c0044004e004f005400490043"
            "0045005f00570045004400440049004e0047005f004300410054004800450044"
            "00520041004c00030a0500ab706f67b0518e7f0f5f000a03009b730956c87000"
            "021c000000"
        )
        parsed = ServerOpcode77Envelope.parse(captured_variant_5)
        self.assertEqual(parsed.to_bytes(), captured_variant_5)
        self.assertEqual(parsed.variant, 5)
        self.assertEqual(parsed.text_code_unit_counts, (33, 5, 3))
        self.assertEqual(parsed.control_bytes, (3, 10, 10, 2))
        self.assertEqual(parsed.terminal_u32, 28)

        with self.assertRaisesRegex(PacketShapeError, "control bytes"):
            replace(envelopes[3], control_bytes=(3, 10, 9, 2)).to_bytes()

    def test_server_opcode_49_variants_round_trip_with_redacted_text(
        self,
    ) -> None:
        envelopes = (
            ServerOpcode49Envelope(
                variant=1,
                key=1_039,
                value_kind=ServerOpcode49Envelope.TEXT_VALUE,
                text_value="private keyed value",
            ),
            ServerOpcode49Envelope(
                variant=1,
                key=1_039,
                value_kind=ServerOpcode49Envelope.U64_VALUE,
                numeric_value=134_152_909_663_840_000,
            ),
            ServerOpcode49Envelope(
                variant=3,
                record_marker=1,
                record_value=8,
                opaque_tail=b"\x00" * 28,
            ),
            ServerOpcode49Envelope(variant=4, opaque_tail=b"\x00\x00\x01"),
            ServerOpcode49Envelope(variant=6, numeric_value=200),
            ServerOpcode49Envelope(
                variant=10,
                reserved_value=0,
                text_value="private system text",
            ),
            ServerOpcode49Envelope(
                variant=12,
                key=29_400,
                text_value="private keyed text",
            ),
        )

        for envelope in envelopes:
            with self.subTest(variant=envelope.variant, shape=envelope.shape_name):
                encoded = envelope.to_bytes()
                self.assertEqual(
                    ServerOpcode49Envelope.parse(encoded), envelope
                )
                self.assertNotIn("private", str(envelope.safe_dict()))

        captured = (
            bytes.fromhex("3100010704000001000000"),
            bytes.fromhex("3100010704000002f00946a90528dd01"),
            bytes.fromhex("310004000001"),
            bytes.fromhex("310006c800000000000000"),
            bytes.fromhex(
                "31000cd872000005006d006f006e003d00300000"
            ),
        )
        for payload in captured:
            with self.subTest(payload=payload.hex()):
                self.assertEqual(
                    ServerOpcode49Envelope.parse(payload).to_bytes(), payload
                )

        with self.assertRaisesRegex(PacketShapeError, "pickup gain notice"):
            ServerOpcode49Envelope.parse(
                PickupGainNotice(
                    result_flag=0,
                    kind=PickupGainNotice.SPECIAL,
                    special_value=2_379_040,
                ).to_bytes()
            )

    def test_item_use_request_round_trip(self) -> None:
        request = ItemUseRequest(
            client_tick=102_034,
            slot=21,
            item_id=2_000_014,
        )

        self.assertEqual(request.to_bytes().hex(), "5000928e010015008e841e00")
        self.assertEqual(ItemUseRequest.parse(request.to_bytes()), request)
        self.assertEqual(
            request.safe_dict(),
            {"client_tick": 102_034, "slot": 21, "item_id": 2_000_014},
        )
        with self.assertRaisesRegex(PacketShapeError, "between 1 and 32767"):
            ItemUseRequest(client_tick=0, slot=0, item_id=2_000_014).to_bytes()

    def test_item_pickup_packet_family_round_trip(self) -> None:
        base_payload = bytes.fromhex(
            "b90000000000029c660100e9fb9c04711f0000c3a59f50"
        )
        extended_payload = bytes.fromhex(
            "b900000000000477b90200a8fe2d003c1c0000d5a06278"
            "a8fe2d004fa0482729e30797"
        )
        base = ItemPickupRequest.parse(base_payload)
        extended = ItemPickupRequest.parse(extended_payload)

        self.assertEqual(base.to_bytes(), base_payload)
        self.assertEqual(base.field_epoch, 2)
        self.assertEqual(base.position_x, -1_047)
        self.assertEqual(base.position_y, 1_180)
        self.assertEqual(base.drop_object_id, 8_049)
        self.assertEqual(base.optional_proof, b"")
        self.assertEqual(extended.to_bytes(), extended_payload)
        self.assertEqual(len(extended.optional_proof), 12)
        self.assertNotIn("drop_object_id", base.safe_dict())
        with self.assertRaisesRegex(PacketShapeError, "absent or 12 bytes"):
            ItemPickupRequest(
                control_value=0,
                field_epoch=2,
                client_tick=1,
                position_x=0,
                position_y=0,
                drop_object_id=1,
                item_validation_token=0,
                optional_proof=b"short",
            ).to_bytes()

        spawn_payloads = (
            bytes.fromhex(
                "370101701f00000003093d00189c0400189c040000bdfb8704"
                "382d4300c7fb8c04c201008005bb46e6170201"
            ),
            bytes.fromhex(
                "370101721f00000110000000189c0400189c040000e5fb9a04"
                "382d4300c7fb8c04c20101"
            ),
            bytes.fromhex(
                "370102b70000000004093d00effe0300effe030000a1fc32f9"
                "00000000008005bb46e6170200"
            ),
            bytes.fromhex(
                "370102170500000104000000a2d20200a2d2020000d2ff8b01"
                "6191250001"
            ),
        )
        spawns = tuple(FieldDropSpawn.parse(payload) for payload in spawn_payloads)
        self.assertEqual(
            tuple(spawn.to_bytes() for spawn in spawns), spawn_payloads
        )
        self.assertEqual(
            tuple((spawn.spawn_mode, spawn.kind_name) for spawn in spawns),
            ((1, "item"), (1, "mesos"), (2, "item"), (2, "mesos")),
        )
        self.assertEqual(spawns[0].source_mob_object_id, 4_402_488)
        self.assertEqual(spawns[0].expiration_ticks, PERMANENT_ITEM_EXPIRATION)
        self.assertEqual(spawns[1].mesos_amount, 16)
        self.assertEqual(spawns[2].item_id, 4_000_004)
        self.assertFalse(spawns[2].animated)
        self.assertEqual(spawns[3].mesos_amount, 4)
        self.assertIsNone(spawns[3].expiration_ticks)

        gain_payloads = (
            bytes.fromhex("3100000013303d0001000000"),
            bytes.fromhex("310000010010000000000000000000"),
            PickupGainNotice(
                result_flag=0,
                kind=PickupGainNotice.SPECIAL,
                special_value=2_380_000,
            ).to_bytes(),
        )
        gains = tuple(PickupGainNotice.parse(payload) for payload in gain_payloads)
        self.assertEqual(
            tuple(gain.to_bytes() for gain in gains), gain_payloads
        )
        self.assertEqual(
            tuple(gain.kind_name for gain in gains),
            ("item", "mesos", "special"),
        )

        removals = (
            FieldDropRemoval(reason=1, drop_object_id=8_041),
            FieldDropRemoval(reason=2, drop_object_id=50_056, actor_id=338_724),
            FieldDropRemoval(
                reason=5,
                drop_object_id=8_050,
                actor_id=302_104,
                trailing_value=0,
            ),
        )
        self.assertEqual(
            tuple(len(removal.to_bytes()) for removal in removals),
            (7, 11, 15),
        )
        self.assertEqual(
            tuple(
                FieldDropRemoval.parse(removal.to_bytes())
                for removal in removals
            ),
            removals,
        )

    def test_inventory_change_set_round_trip(self) -> None:
        cash_item = fixture_cash_inventory_item(slot=4)
        equipment_item = fixture_equipment_inventory_item(
            slot=2, item_id=1_000_002
        )
        cash_stack_item = fixture_stack_inventory_item(
            slot=5, item_id=2_000_002, quantity=3
        )
        changes = InventoryChangeSet(
            update_flag=0,
            modifications=(
                InventoryModification(
                    operation=InventoryModification.UPDATE_QUANTITY,
                    inventory_type=2,
                    slot=15,
                    quantity=27,
                ),
                InventoryModification(
                    operation=InventoryModification.REMOVE,
                    inventory_type=5,
                    slot=4,
                ),
                InventoryModification(
                    operation=InventoryModification.ADD,
                    inventory_type=5,
                    slot=4,
                    item=cash_item,
                ),
                InventoryModification(
                    operation=InventoryModification.ADD,
                    inventory_type=1,
                    slot=2,
                    item=equipment_item,
                ),
                InventoryModification(
                    operation=InventoryModification.ADD,
                    inventory_type=5,
                    slot=5,
                    item=cash_stack_item,
                ),
                InventoryModification(
                    operation=InventoryModification.MOVE,
                    inventory_type=1,
                    slot=2,
                    destination_slot=-11,
                    move_flag=2,
                ),
            ),
        )
        empty = InventoryChangeSet(update_flag=0, modifications=())

        self.assertEqual(InventoryChangeSet.parse(changes.to_bytes()), changes)
        self.assertEqual(InventoryChangeSet.parse(empty.to_bytes()), empty)
        self.assertEqual(len(cash_item.raw_record), 58)
        self.assertEqual(changes.modifications[3].item, equipment_item)
        self.assertEqual(changes.modifications[4].item, cash_stack_item)
        self.assertEqual(
            changes.modifications[5].safe_dict(),
            {
                "operation": "move",
                "inventory": "equip",
                "slot": 2,
                "destination_slot": -11,
                "move_flag": 2,
            },
        )
        self.assertEqual(
            changes.modifications[0].safe_dict(),
            {
                "operation": "update_quantity",
                "inventory": "use",
                "slot": 15,
                "quantity": 27,
            },
        )
        with self.assertRaisesRegex(PacketShapeError, "requires destination"):
            InventoryModification(
                operation=InventoryModification.MOVE,
                inventory_type=2,
                slot=1,
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "requires quantity"):
            InventoryModification(
                operation=InventoryModification.UPDATE_QUANTITY,
                inventory_type=2,
                slot=1,
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "signed short"):
            InventoryModification(
                operation=InventoryModification.REMOVE,
                inventory_type=5,
                slot=0x8000,
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "unsigned short"):
            InventoryModification(
                operation=InventoryModification.UPDATE_QUANTITY,
                inventory_type=2,
                slot=1,
                quantity=0x1_0000,
            ).to_bytes()

    def test_character_stat_update_round_trip(self) -> None:
        combined = CharacterStatUpdate(
            request_flag=1,
            stat_mask=(
                CharacterStatUpdate.INTELLIGENCE
                | CharacterStatUpdate.LUCK
                | CharacterStatUpdate.ABILITY_POINTS
            ),
            intelligence=57,
            luck=15,
            ability_points=0,
        )
        zero_mask = CharacterStatUpdate(
            request_flag=0,
            stat_mask=0,
            opaque_tail=b"\x01\x01",
        )

        self.assertEqual(
            combined.to_bytes().hex(),
            "2900010043000039000f00000000",
        )
        self.assertEqual(
            CharacterStatUpdate.parse(combined.to_bytes()), combined
        )
        self.assertEqual(
            CharacterStatUpdate.parse(zero_mask.to_bytes()), zero_mask
        )
        level_up_payload = bytes.fromhex(
            "290000d03c0100071c000b009000b10060007b004101000000"
        )
        level_up = CharacterStatUpdate.parse(level_up_payload)
        self.assertEqual(level_up.to_bytes(), level_up_payload)
        self.assertEqual(
            level_up.values,
            {
                "character_level": 7,
                "strength": 28,
                "dexterity": 11,
                "current_hp": 144,
                "max_hp": 177,
                "current_mp": 96,
                "max_mp": 123,
                "experience": 321,
            },
        )
        extended_zero_mask = bytes.fromhex("2900000000000001aa")
        self.assertEqual(
            CharacterStatUpdate.parse(extended_zero_mask).to_bytes(),
            extended_zero_mask,
        )
        self.assertEqual(
            combined.values,
            {"intelligence": 57, "luck": 15, "ability_points": 0},
        )
        with self.assertRaisesRegex(PacketShapeError, "requires current_hp"):
            CharacterStatUpdate(
                request_flag=0,
                stat_mask=CharacterStatUpdate.CURRENT_HP,
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "unsupported bits"):
            CharacterStatUpdate(
                request_flag=0,
                stat_mask=1,
                opaque_tail=b"\x00",
            ).to_bytes()

    def test_initial_field_snapshot_typed_prefix_round_trip(self) -> None:
        snapshot = fixture_initial_field_snapshot()
        encoded = snapshot.to_bytes()

        self.assertEqual(InitialFieldSnapshot.parse(encoded), snapshot)
        self.assertEqual(snapshot.character.character_id, CHARACTER_ID)
        self.assertEqual(snapshot.character.data_flags, 4)
        self.assertEqual(
            snapshot.typed_prefix_bytes,
            len(encoded) - len(snapshot.opaque_tail),
        )
        inventory = snapshot.parse_inventory()
        self.assertIsInstance(inventory, InitialInventorySnapshot)
        self.assertEqual(inventory.to_bytes(), snapshot.opaque_tail)
        self.assertEqual(
            [
                (item.slot, item.item_id, item.quantity)
                for item in inventory.groups[5].items
            ],
            [(1, 2_000_000, 3)],
        )
        progression = snapshot.parse_progression()
        self.assertEqual(
            InitialProgressionSnapshot.parse(progression.to_bytes()),
            progression,
        )
        self.assertEqual(
            progression.to_bytes(), inventory.opaque_remainder
        )
        with self.assertRaisesRegex(PacketShapeError, "variant"):
            replace(progression, variant=3).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "text lengths"):
            replace(
                progression.trailer,
                opaque_texts=("", "1", "1", "short", ""),
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "marker"):
            replace(snapshot, marker=24).to_bytes()
        marker_26 = replace(snapshot, marker=26)
        self.assertEqual(
            InitialFieldSnapshot.parse(marker_26.to_bytes()), marker_26
        )
        with self.assertRaisesRegex(PacketShapeError, "tail"):
            replace(snapshot, opaque_tail=b"").to_bytes()

    def test_typed_initial_field_snapshot_round_trips_full_and_compact_state(
        self,
    ) -> None:
        full = fixture_initial_field_snapshot()
        full_typed = TypedInitialFieldSnapshot.parse(full.to_bytes())
        compact = fixture_compact_initial_field_snapshot()
        compact_typed = TypedInitialFieldSnapshot.parse(compact.to_bytes())

        self.assertEqual(full_typed.to_bytes(), full.to_bytes())
        self.assertIsInstance(
            full_typed.progression, InitialProgressionSnapshot
        )
        self.assertEqual(compact_typed.to_bytes(), compact.to_bytes())
        self.assertIsInstance(
            compact_typed.progression,
            CompactInitialProgressionSnapshot,
        )
        self.assertEqual(compact_typed.progression.skill_levels, ((12, 0),))
        self.assertEqual(len(compact_typed.to_bytes()), len(compact.to_bytes()))
        with self.assertRaisesRegex(PacketShapeError, "requires compact"):
            replace(full_typed, marker=26).to_bytes()
        with self.assertRaisesRegex(
            PacketShapeError, "requires keyed-property"
        ):
            replace(compact_typed, marker=23).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "full trailer"):
            replace(
                full_typed.progression,
                trailer=compact_typed.progression.trailer,
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "compact trailer"):
            replace(
                compact_typed.progression,
                trailer=full_typed.progression.trailer,
            ).to_bytes()

    def test_fixed_server_records_round_trip(self) -> None:
        records = fixture_fixed_server_records()

        for record in records:
            encoded = record.to_bytes()
            self.assertEqual(type(record).parse(encoded), record)

        with self.assertRaisesRegex(PacketShapeError, "unsupported empty"):
            FixedServerEmptyRecord(opcode=25).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "reserved values"):
            FixedServerOpcode11Record(
                reserved_u32=1,
                reserved_u8=0,
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "context flag"):
            replace(records[5], context_flag=0).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "unsupported uint16"):
            replace(records[9], opcode=57).to_bytes()

        captured = {
            45: "2d00",
            60: "3c000d040000",
            71: "470035",
            72: "48000700",
            74: "4a001a00",
            76: "4c00ffc99a3bffc99a3b",
            89: "590000",
            112: "700000000000",
            121: "790000",
            131: "830000000000",
            301: "2d01da0c0000",
            398: "8e010080022ab825dd01",
        }
        by_opcode = {record.opcode: record for record in records}
        for opcode, expected_hex in captured.items():
            with self.subTest(opcode=opcode):
                self.assertEqual(by_opcode[opcode].to_bytes().hex(), expected_hex)

    def test_tutorial_ui_instruction_round_trip_and_redacts_text(self) -> None:
        compact = TutorialUiInstruction(
            text="$SCRIPTSTRING_TUTORIAL_0$",
            value_1=150,
            value_2=5,
            control_value=1,
        )
        extended = TutorialUiInstruction(
            text="extended",
            value_1=-2,
            value_2=3,
            control_value=0,
            extended_values=(-4, 5),
        )

        encoded = compact.to_bytes()
        self.assertEqual(len(encoded), 60)
        self.assertEqual(TutorialUiInstruction.parse(encoded), compact)
        self.assertEqual(
            TutorialUiInstruction.parse(extended.to_bytes()),
            extended,
        )
        self.assertNotIn("SCRIPTSTRING", str(compact.safe_dict()))
        self.assertEqual(compact.safe_dict()["text_code_units"], 25)

        with self.assertRaisesRegex(PacketShapeError, "zero or eight"):
            TutorialUiInstruction.parse(encoded + b"\x00")

    def test_server_opcode_244_dialogue_instruction_round_trip(self) -> None:
        record = ServerOpcode244DialogueInstruction(
            value_1=1036,
            value_2=2003,
            value_3=0,
        )

        encoded = record.to_bytes()

        self.assertEqual(
            encoded.hex(),
            "f400080c040000d307000000000000",
        )
        self.assertEqual(
            ServerOpcode244DialogueInstruction.parse(encoded),
            record,
        )
        with self.assertRaisesRegex(PacketShapeError, "requires selector 8"):
            ServerOpcode244DialogueInstruction.parse(
                encoded[:2] + b"\x07" + encoded[3:]
            )
        with self.assertRaisesRegex(PacketShapeError, "uninterpreted bytes"):
            ServerOpcode244DialogueInstruction.parse(encoded + b"\x00")

    def test_server_opcode_239_envelope_variants_round_trip(self) -> None:
        record_set = ServerOpcode239Envelope(
            selector=3,
            records=(
                ServerOpcode239ValueRecord(key=4_031_792, value=10),
            ),
        )
        empty_9 = ServerOpcode239Envelope(selector=9)
        empty_13 = ServerOpcode239Envelope(selector=13)
        text = ServerOpcode239Envelope(
            selector=21,
            text="UI/tutorial/28",
            trailing_value=1,
        )

        self.assertEqual(
            record_set.to_bytes().hex(),
            "ef00030130853d000a000000",
        )
        self.assertEqual(empty_9.to_bytes().hex(), "ef0009")
        self.assertEqual(empty_13.to_bytes().hex(), "ef000d")
        self.assertEqual(
            text.to_bytes().hex(),
            "ef00150e00550049002f007400750074006f007200690061006c002f00"
            "320038000001000000",
        )
        for envelope in (record_set, empty_9, empty_13, text):
            self.assertEqual(
                ServerOpcode239Envelope.parse(envelope.to_bytes()),
                envelope,
            )
        self.assertEqual(text.text_code_units, 14)
        safe = str(record_set.safe_dict())
        self.assertNotIn("4031792", safe)
        self.assertNotIn("UI/tutorial/28", str(text.safe_dict()))

        with self.assertRaisesRegex(PacketShapeError, "selector must"):
            ServerOpcode239Envelope.parse(bytes.fromhex("ef0001"))
        with self.assertRaisesRegex(PacketShapeError, "needs 4 bytes"):
            ServerOpcode239Envelope.parse(record_set.to_bytes()[:-1])
        with self.assertRaisesRegex(PacketShapeError, "cannot include a body"):
            replace(empty_9, records=record_set.records).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "requires text"):
            ServerOpcode239Envelope(selector=21).to_bytes()

    def test_client_opcode_43_variants_round_trip_and_redact(self) -> None:
        compact = ClientOpcode43Envelope(
            sequence=4,
            opaque_compact_body=bytes(range(9)),
        )
        identified = ClientOpcode43Envelope(
            sequence=35,
            opaque_identifier=3_456_789,
            opaque_text="hidden",
            opaque_tail=b"ABCDEF",
        )

        for envelope in (compact, identified):
            payload = envelope.to_bytes()
            self.assertEqual(ClientOpcode43Envelope.parse(payload), envelope)
        self.assertEqual(len(compact.to_bytes()), 12)
        self.assertEqual(len(identified.to_bytes()), 28)
        self.assertEqual(compact.variant, "compact")
        self.assertEqual(identified.variant, "identified_text")
        self.assertEqual(identified.text_code_units, 6)
        self.assertEqual(identified.opaque_byte_count, 6)
        safe = str(identified.safe_dict())
        self.assertNotIn("3456789", safe)
        self.assertNotIn("hidden", safe)

        server = ServerOpcode43Envelope(
            message_type=0,
            opaque_body=bytes(range(16)),
        )
        self.assertEqual(ServerOpcode43Envelope.parse(server.to_bytes()), server)
        self.assertEqual(len(server.to_bytes()), 19)
        self.assertNotIn(bytes(range(16)).hex(), str(server.safe_dict()))

        with self.assertRaisesRegex(PacketShapeError, "needs 9 opaque"):
            replace(compact, opaque_compact_body=b"short").to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "needs text"):
            replace(identified, opaque_text=None).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "6-byte tail"):
            replace(identified, opaque_tail=b"short").to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "fit in u8"):
            replace(compact, sequence=256).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "needs 2 bytes"):
            ClientOpcode43Envelope.parse(bytes.fromhex("2b00010000000000"))
        with self.assertRaisesRegex(PacketShapeError, "16-byte opaque"):
            replace(server, opaque_body=b"short").to_bytes()

    def test_client_opcode_114_text_envelope_round_trip_and_redact(self) -> None:
        envelopes = (
            ClientOpcode114TextEnvelope(
                control_value=32,
                opaque_text="secret01",
                opaque_value=3_456_789,
            ),
            ClientOpcode114TextEnvelope(
                control_value=1,
                opaque_text="hidden-text",
                opaque_value=4_567_890,
            ),
        )

        for envelope in envelopes:
            payload = envelope.to_bytes()
            self.assertEqual(
                ClientOpcode114TextEnvelope.parse(payload), envelope
            )
        self.assertEqual(len(envelopes[0].to_bytes()), 26)
        self.assertEqual(len(envelopes[1].to_bytes()), 32)
        self.assertEqual(envelopes[0].text_code_units, 8)
        safe = str(envelopes[0].safe_dict())
        self.assertNotIn("secret01", safe)
        self.assertNotIn("3456789", safe)

        invalid_terminator = bytearray(envelopes[0].to_bytes())
        invalid_terminator[-5] = 1
        with self.assertRaisesRegex(PacketShapeError, "expected 0"):
            ClientOpcode114TextEnvelope.parse(bytes(invalid_terminator))
        with self.assertRaisesRegex(PacketShapeError, "fit in u8"):
            replace(envelopes[0], control_value=256).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "fit in u32"):
            replace(envelopes[0], opaque_value=0x1_0000_0000).to_bytes()

    def test_client_opcode_122_captured_variants_round_trip(self) -> None:
        payloads = (
            bytes.fromhex("7a00015408000041bf0f00"),
            bytes.fromhex("7a0001070400003508000043ffe501"),
            bytes.fromhex("7a00025408000041bf0f00ffffffff"),
            bytes.fromhex(
                "7a000207040000340800008b036d01ffffffff"
            ),
            bytes.fromhex("7a000418040000507b8900a500e7ff"),
            bytes.fromhex("7a0005cc740000685489001dfdf7f4"),
        )

        for payload in payloads:
            self.assertTrue(ClientOpcode122Envelope.is_captured_shape(payload))
            self.assertEqual(
                ClientOpcode122Envelope.parse(payload).to_bytes(), payload
            )
        short = ClientOpcode122Envelope.parse(payloads[0])
        self.assertEqual(short.safe_dict()["shape"], "selector=1:values=2")
        self.assertNotIn("2132", str(short.safe_dict()))
        terminal = ClientOpcode122Envelope.parse(payloads[2])
        self.assertTrue(terminal.terminal_sentinel_present)
        self.assertNotIn("4294967295", str(terminal.safe_dict()))

        unsupported = struct.pack("<HB3I", 122, 3, 1, 2, 3)
        self.assertFalse(ClientOpcode122Envelope.is_captured_shape(unsupported))
        with self.assertRaisesRegex(PacketShapeError, "not a captured shape"):
            ClientOpcode122Envelope.parse(unsupported)
        with self.assertRaisesRegex(PacketShapeError, "complete u32"):
            ClientOpcode122Envelope.parse(payloads[0] + b"\x00")
        with self.assertRaisesRegex(PacketShapeError, "terminal 0xffffffff"):
            ClientOpcode122Envelope(
                selector=2,
                opaque_values=(1, 2, 3),
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "out of range"):
            ClientOpcode122Envelope(
                selector=1,
                opaque_values=(1, 0x1_0000_0000),
            ).to_bytes()

    def test_server_opcode_348_text_envelope_variants_round_trip(self) -> None:
        extended = ServerOpcode348TextEnvelope(
            category=4,
            primary_value=0x01020304,
            selector=0,
            value=0,
            text="A$",
            control_1=0,
            control_2=1,
        )
        simple = tuple(
            ServerOpcode348TextEnvelope(
                category=4,
                primary_value=0x0A0B0C0D + selector,
                selector=selector,
                value=0,
                text=f"text-{selector}",
            )
            for selector in (3, 6, 17)
        )
        signed = replace(simple[0], primary_value=-2, value=-1)

        self.assertEqual(
            extended.to_bytes().hex(),
            "5c0104040302010000000000020041002400000001",
        )
        for envelope in (extended, *simple, signed):
            self.assertEqual(
                ServerOpcode348TextEnvelope.parse(envelope.to_bytes()),
                envelope,
            )
        safe = str(extended.safe_dict())
        self.assertNotIn("16909060", safe)
        self.assertNotIn("A$", safe)
        self.assertEqual(extended.text_code_units, 2)

        with self.assertRaisesRegex(PacketShapeError, "selector must"):
            replace(simple[0], selector=1).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "requires two controls"):
            replace(extended, control_2=None).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "cannot include controls"):
            replace(simple[0], control_1=0).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "uninterpreted bytes"):
            ServerOpcode348TextEnvelope.parse(simple[0].to_bytes() + b"\x00")

    def test_positioned_effect_records_round_trip_and_redact_primary(self) -> None:
        records = (
            (
                ServerOpcode320PositionedEffectRecord(
                    primary_value=2_357_555,
                    control_value=1,
                    x=1412,
                    y=435,
                    numeric_value=305,
                    secondary_control_value=0,
                    trailing_value=5,
                ),
                "400133f92300018405b30131010005",
            ),
            (
                ServerOpcode322PositionedEffectRecord(
                    primary_value=12_597,
                    numeric_value=2000,
                    control_value=0,
                    x=2609,
                    y=-372,
                    trailing_value=0,
                ),
                "420135310000d007000000310a8cfe00",
            ),
            (
                ServerOpcode323PositionedEffectRecord(
                    primary_value=12_597,
                    control_value=0,
                    x=2609,
                    y=-372,
                ),
                "43013531000000310a8cfe",
            ),
        )

        for record, expected_hex in records:
            encoded = record.to_bytes()
            self.assertEqual(encoded.hex(), expected_hex)
            self.assertEqual(type(record).parse(encoded), record)
            self.assertNotIn(str(record.primary_value), str(record.safe_dict()))

        with self.assertRaisesRegex(PacketShapeError, "uninterpreted bytes"):
            ServerOpcode323PositionedEffectRecord.parse(
                records[-1][0].to_bytes() + b"\x00"
            )

    def test_remote_player_lifecycle_round_trip_and_redacts_identity(
        self,
    ) -> None:
        entered = RemotePlayerEnterField(
            object_id=302_104,
            level=12,
            name="小慧22",
            opaque_body=b"\x00" * 309,
        )
        left = RemotePlayerLeaveField(object_id=302_104)

        encoded_entry = entered.to_bytes()
        self.assertEqual(len(encoded_entry), 326)
        self.assertTrue(
            encoded_entry.hex().startswith(
                "bd00189c04000c04000f5c676132003200"
            )
        )
        self.assertEqual(RemotePlayerEnterField.parse(encoded_entry), entered)
        self.assertEqual(left.to_bytes().hex(), "be00189c0400")
        self.assertEqual(RemotePlayerLeaveField.parse(left.to_bytes()), left)
        self.assertNotIn("302104", str(entered.safe_dict()))
        self.assertNotIn("小慧22", str(entered.safe_dict()))

        with self.assertRaisesRegex(PacketShapeError, "cannot be empty"):
            replace(entered, opaque_body=b"").to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "needs 8 bytes"):
            RemotePlayerEnterField.parse(bytes.fromhex("bd00010000000c0400"))

    def test_remote_player_mob_value_record_round_trip(self) -> None:
        payload = bytes.fromhex(
            "e000cf1e0400ff0100000034fc010000000001000000"
        )
        record = RemotePlayerMobValueRecord(
            object_id=270_031,
            value=1,
            mob_template_id=130_100,
            flag=0,
            repeated_value=1,
        )

        self.assertEqual(record.to_bytes(), payload)
        self.assertEqual(RemotePlayerMobValueRecord.parse(payload), record)
        self.assertNotIn("270031", str(record.safe_dict()))
        self.assertTrue(record.safe_dict()["repeated_value_matches"])

        with self.assertRaisesRegex(PacketShapeError, "marker must be"):
            replace(record, marker=0).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "zero or one"):
            replace(record, flag=2).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "reserved u16"):
            replace(record, reserved_u16=1).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "must repeat"):
            replace(record, repeated_value=2).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "needs 4 bytes"):
            RemotePlayerMobValueRecord.parse(payload[:-1])

    def test_neutral_server_records_round_trip_and_redact_primary_values(
        self,
    ) -> None:
        records = (
            ServerOpcode69Record(
                header_value=7,
                opaque_tail=b"\x00" * ServerOpcode69Record.OPAQUE_TAIL_LENGTH,
            ),
            ServerOpcode93Record(
                values=(9_000_017, 2_041_017, 1_022_101, 9_000_021)
            ),
            ServerOpcode94Record(
                flag=True,
                primary_value=2_380_000,
                secondary_value=2,
            ),
            ServerOpcode201Record(
                primary_value=302_104,
                secondary_value=0,
                flag_a=1,
                flag_b=1,
                opaque_tail=bytes.fromhex(
                    "6e4b4c000000009028150000000000480220f5004d02"
                ),
            ),
            ServerOpcode205Record(
                primary_value=302_104,
                secondary_value=0,
                numeric_value=1_386_640,
                trailing_value=0,
            ),
            ServerOpcode379Record(variant=35),
            ServerOpcode379Record(
                variant=36,
                time_values=(
                    150_842_304_000_000_000,
                    150_842_304_000_000_000,
                    94_354_848_000_000_000,
                    94_354_848_000_000_000,
                ),
            ),
        )
        expected_hex = (
            "450007000000" + "00" * 263,
            "5d000451548900b9241f0095980f0055548900",
            "5e0001e050240002000000",
            "c900189c04000000000001016e4b4c000000009028150000000000480220f5004d02",
            "cd00189c040000000000902815000000000000",
            "7b0123",
            "7b0124008005bb46e61702008005bb46e617020040e0fd3b374f010040e0fd3b374f01",
        )

        for record, expected in zip(records, expected_hex, strict=True):
            with self.subTest(opcode=record.opcode):
                encoded = record.to_bytes()
                self.assertEqual(encoded.hex(), expected)
                self.assertEqual(type(record).parse(encoded), record)
                self.assertNotIn("302104", str(record.safe_dict()))

        with self.assertRaisesRegex(PacketShapeError, "exactly 263"):
            replace(records[0], opaque_tail=b"\x00" * 262).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "exactly 22"):
            replace(records[3], opaque_tail=b"\x00" * 21).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "zero or one"):
            ServerOpcode94Record.parse(
                bytes.fromhex("5e0002e050240002000000")
            )
        with self.assertRaisesRegex(PacketShapeError, "requires exactly 4"):
            replace(records[-1], time_values=()).to_bytes()

    def test_server_opcode_148_envelope_round_trip_and_partial_record_body(
        self,
    ) -> None:
        records = (
            ServerOpcode148Envelope(variant=9, record_count=0),
            ServerOpcode148Envelope(variant=10),
            ServerOpcode148Envelope(
                variant=12, primary_value=4, secondary_value=5
            ),
            ServerOpcode148Envelope(
                variant=13, primary_value=3, secondary_value=24
            ),
            ServerOpcode148Envelope(
                variant=9,
                record_count=12,
                records_blob=b"\xa5" * 1_632,
            ),
        )
        expected_prefixes = (
            "94000900000000",
            "94000a",
            "94000c0400000005000000",
            "94000d0300000018000000",
            "9400090c000000",
        )

        for record, expected_prefix in zip(
            records, expected_prefixes, strict=True
        ):
            with self.subTest(variant=record.variant, count=record.record_count):
                encoded = record.to_bytes()
                self.assertTrue(encoded.hex().startswith(expected_prefix))
                self.assertEqual(ServerOpcode148Envelope.parse(encoded), record)
                self.assertNotIn("primary_value", str(record.safe_dict()))
                self.assertNotIn("secondary_value", str(record.safe_dict()))

        self.assertTrue(records[0].fully_bounded)
        self.assertFalse(records[-1].fully_bounded)
        self.assertEqual(records[-1].safe_dict()["opaque_tail_length"], 1_632)
        with self.assertRaisesRegex(PacketShapeError, "captured value"):
            ServerOpcode148Envelope.parse(bytes.fromhex("94000b"))
        with self.assertRaisesRegex(PacketShapeError, "zero-record"):
            replace(records[0], records_blob=b"\x00").to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "requires a body"):
            replace(records[-1], records_blob=b"").to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "requires two"):
            replace(records[2], secondary_value=None).to_bytes()

    def test_variable_server_records_round_trip(self) -> None:
        records = fixture_variable_server_records()

        for record in records:
            encoded = record.to_bytes()
            self.assertEqual(VariableServerRecord.parse(encoded), record)

        with self.assertRaisesRegex(PacketShapeError, "unsupported"):
            VariableServerRecord(
                opcode=156,
                variant=2,
                opaque_tail=b"",
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "expected 89"):
            replace(records[2], entries=()).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "exactly 3"):
            replace(records[1], values=(1, 2)).to_bytes()
        self.assertEqual(
            records[2].keyboard_skill_bindings,
            {29: 2_001_005, 71: 2_001_002},
        )
        self.assertEqual(records[2].left_ctrl_skill_id, 2_001_005)
        self.assertEqual(records[2].nonzero_keyboard_selector_count, 3)
        self.assertEqual(records[3].keyboard_skill_bindings, {})

    def test_bounded_gameplay_envelopes_preserve_opaque_tails(self) -> None:
        stage = FieldLoadStage(
            stage=0,
            trailing=1,
            opaque_tail=b"nine-byte",
        )
        update = NpcStateUpdate(
            object_id=NPC_OBJECT_ID,
            action=2,
            parameter=3,
            opaque_tail=b"capture-backed-tail",
        )
        compact_records = ClientOpcode217RecordSet(
            opaque_prefix=b"short!",
        )
        format_zero_records = ClientOpcode217RecordSet(
            opaque_prefix=b"prefix-000",
            record_format=0,
            records=(b"a" * 14, b"b" * 14),
            opaque_trailer=b"trailer!",
        )
        format_two_records = ClientOpcode217RecordSet(
            opaque_prefix=b"prefix-002",
            record_format=2,
            records=(b"c" * 11, b"d" * 11),
            opaque_trailer=b"trailer?",
        )

        self.assertEqual(FieldLoadStage.parse(stage.to_bytes()), stage)
        self.assertEqual(NpcStateUpdate.parse(update.to_bytes()), update)
        for record_set in (
            compact_records,
            format_zero_records,
            format_two_records,
        ):
            self.assertEqual(
                ClientOpcode217RecordSet.parse(record_set.to_bytes()),
                record_set,
            )
        self.assertEqual(len(compact_records.to_bytes()), 8)
        self.assertEqual(len(format_zero_records.to_bytes()), 50)
        self.assertEqual(len(format_two_records.to_bytes()), 44)
        with self.assertRaisesRegex(PacketShapeError, "needs 14 bytes"):
            ClientOpcode217RecordSet(
                opaque_prefix=b"prefix-000",
                record_format=0,
                records=(b"short",),
                opaque_trailer=b"trailer!",
            ).to_bytes()
        captured_stage = bytes.fromhex(
            "9e0000000000010000002a00000001e8030000"
        )
        self.assertEqual(
            FieldLoadStage.parse(captured_stage).to_bytes(), captured_stage
        )

    def test_world_entry_request_types_character_id_after_entry_value(self) -> None:
        request = WorldEntryRequest(
            entry_value=4,
            character_id=CHARACTER_ID,
            opaque_ticket=b"sanitized-ticket".ljust(56, b"\x00"),
        )
        encoded = request.to_bytes()

        self.assertEqual(WorldEntryRequest.parse(encoded), request)
        self.assertEqual(encoded[2:6], (4).to_bytes(4, "little"))
        self.assertEqual(
            encoded[6:10], CHARACTER_ID.to_bytes(4, "little")
        )
        self.assertEqual(len(encoded), 66)

    def test_compact_field_transition_round_trip(self) -> None:
        transition = fixture_compact_field_transition()

        self.assertEqual(len(transition.to_bytes()), 95)
        self.assertEqual(
            CompactFieldTransition.parse(transition.to_bytes()), transition
        )
        with self.assertRaisesRegex(PacketShapeError, "marker"):
            replace(transition, marker=24).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "16 characters"):
            replace(transition, opaque_text_3="short").to_bytes()

    def test_npc_spawn_round_trip(self) -> None:
        spawn = fixture_npc()

        self.assertEqual(len(spawn.to_bytes()), 22)
        self.assertEqual(NpcSpawn.parse(spawn.to_bytes()), spawn)

    def test_npc_spawn_preserves_facing_value_and_rejects_range(self) -> None:
        variant = replace(fixture_npc(), facing_value=5)
        self.assertEqual(NpcSpawn.parse(variant.to_bytes()), variant)

        with self.assertRaisesRegex(PacketShapeError, "facing value"):
            replace(fixture_npc(), facing_value=0x100).to_bytes()

        with self.assertRaisesRegex(PacketShapeError, "reversed"):
            NpcSpawn(
                object_id=1,
                template_id=2,
                x=0,
                cy=0,
                facing_value=0,
                foothold_id=0,
                range_left=10,
                range_right=-10,
                hidden=False,
            ).to_bytes()

    def test_npc_lifecycle_control_round_trip(self) -> None:
        spawn = NpcSpawn(
            object_id=23_607,
            template_id=2_102,
            x=-59,
            cy=95,
            facing_value=1,
            foothold_id=35,
            range_left=-109,
            range_right=-9,
            hidden=True,
        )
        lifecycle_spawn = NpcLifecycleControl(
            object_id=spawn.object_id,
            control_value=NpcLifecycleControl.SPAWN,
            spawn=spawn,
        )
        lifecycle_remove = NpcLifecycleControl(
            object_id=spawn.object_id,
            control_value=NpcLifecycleControl.REMOVE,
        )

        self.assertEqual(
            lifecycle_spawn.to_bytes().hex(),
            "2e0101375c000036080000c5ff5f0001230093fff7ff01",
        )
        self.assertEqual(
            NpcLifecycleControl.parse(lifecycle_spawn.to_bytes()),
            lifecycle_spawn,
        )
        self.assertEqual(
            lifecycle_remove.to_bytes().hex(), "2e0100375c0000"
        )
        self.assertEqual(
            NpcLifecycleControl.parse(lifecycle_remove.to_bytes()),
            lifecycle_remove,
        )
        self.assertNotIn("23607", str(lifecycle_spawn.safe_dict()))

        with self.assertRaisesRegex(PacketShapeError, "lifecycle control"):
            replace(lifecycle_remove, control_value=2).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "requires spawn"):
            replace(lifecycle_spawn, spawn=None).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "cannot include spawn"):
            replace(lifecycle_remove, spawn=spawn).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "object id"):
            replace(
                lifecycle_spawn,
                spawn=replace(spawn, object_id=spawn.object_id + 1),
            ).to_bytes()

    def test_player_movement_submission_and_broadcast_round_trip(self) -> None:
        path = fixture_player_movement_path()
        submission = PlayerMovementSubmission(
            control_value=0,
            movement=path,
            trailer_marker=0,
            path_start_x=90,
            path_start_y=-205,
            path_end_x=132,
            path_end_y=-168,
        )
        broadcast = PlayerMovementBroadcast(
            object_id=PLAYER_OBJECT_ID,
            control_value=1,
            movement=path,
        )
        life_path = fixture_life_movement_path()
        life_submission = LifeMovementSubmission(
            local_object_index=7,
            client_token=123_456,
            control_value=0,
            movement=life_path,
            tail_type=17,
            opaque_tail_state=b"\x00" * 8,
            tail_marker=4,
            path_start_x=90,
            path_start_y=-205,
            path_end_x=132,
            path_end_y=-168,
        )
        life_broadcast = LifeMovementBroadcast(
            object_id=PLAYER_OBJECT_ID,
            movement=life_path,
        )

        self.assertEqual(
            PlayerMovementSubmission.parse(submission.to_bytes()), submission
        )
        self.assertEqual(
            PlayerMovementBroadcast.parse(broadcast.to_bytes()), broadcast
        )
        self.assertEqual(
            LifeMovementSubmission.parse(life_submission.to_bytes()),
            life_submission,
        )
        self.assertEqual(
            LifeMovementBroadcast.parse(life_broadcast.to_bytes()),
            life_broadcast,
        )
        self.assertEqual(len(life_submission.to_bytes()), 84)
        self.assertEqual(len(life_broadcast.to_bytes()), 61)
        self.assertEqual(
            [command.command_type for command in life_path.commands],
            [0, 2, 10, 14, 15],
        )
        self.assertEqual(
            [command.byte_length for command in path.commands],
            [14, 8, 6, 14, 14],
        )
        self.assertEqual(path.final_position, (130, -170))
        self.assertEqual(
            path.commands[2].safe_dict(),
            {
                "type": 3,
                "kind": "compact_opaque",
                "opaque_payload_bytes": 5,
            },
        )
        with self.assertRaisesRegex(PacketShapeError, "expected one of"):
            PlayerMovementPath(
                reference_x=0,
                reference_y=0,
                commands=(PlayerMovementCommand(4, b""),),
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "needs 5 opaque bytes"):
            PlayerMovementCommand.compact(b"four").to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "must contain a command"):
            PlayerMovementPath(
                reference_x=0,
                reference_y=0,
                commands=(),
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "needs 13 opaque bytes"):
            LifeMovementCommand(command_type=0, opaque_payload=b"").to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "tail type 17 needs 8"):
            LifeMovementSubmission(
                local_object_index=0,
                client_token=0,
                control_value=0,
                movement=life_path,
                tail_type=17,
                opaque_tail_state=b"short",
                tail_marker=0,
                path_start_x=0,
                path_start_y=0,
                path_end_x=0,
                path_end_y=0,
            ).to_bytes()

    def test_movement_header_and_ack_round_trip(self) -> None:
        movement_path = MobMovementPath(
            opaque_control=b"opaque-control".ljust(19, b"\x00"),
            reference_x=-12,
            reference_y=34,
            commands=(
                MobMovementCommand.absolute(
                    position_x=-10,
                    position_y=35,
                    velocity_x=3,
                    velocity_y=-4,
                    foothold_id=5,
                    stance=6,
                    duration_ms=90,
                ),
                MobMovementCommand.relative(
                    command_type=1,
                    velocity_x=100,
                    velocity_y=-555,
                    stance=7,
                    duration_ms=0,
                ),
                MobMovementCommand.relative(
                    command_type=2,
                    velocity_x=-117,
                    velocity_y=-54,
                    stance=3,
                    duration_ms=0,
                ),
            ),
            trailer_marker=0,
            path_start_x=-20,
            path_start_y=30,
            path_end_x=-4,
            path_end_y=38,
        )
        submission = MobMovementSubmission(
            object_id=MOB_OBJECT_ID,
            sequence=42,
            opaque_movement=movement_path.to_bytes(),
        )
        acknowledgement = MobMovementAcknowledgement(
            object_id=MOB_OBJECT_ID,
            sequence=42,
            status_flag=1,
            status_value=35,
            status_auxiliary_1=0,
            status_auxiliary_2=0,
        )

        self.assertEqual(
            MobMovementSubmission.parse(submission.to_bytes()), submission
        )
        parsed_path = MobMovementSubmission.parse(
            submission.to_bytes()
        ).movement_path
        self.assertEqual(parsed_path, movement_path)
        self.assertEqual(
            [command.byte_length for command in parsed_path.commands],
            [14, 8, 8],
        )
        self.assertEqual(
            parsed_path.commands[0].safe_dict(),
            {
                "type": 0,
                "kind": "absolute",
                "position_x": -10,
                "position_y": 35,
                "velocity_x": 3,
                "velocity_y": -4,
                "foothold_id": 5,
                "stance": 6,
                "duration_ms": 90,
            },
        )
        self.assertEqual(
            parsed_path.commands[1].safe_dict(),
            {
                "type": 1,
                "kind": "relative",
                "velocity_x": 100,
                "velocity_y": -555,
                "stance": 7,
                "duration_ms": 0,
            },
        )
        self.assertEqual(
            MobMovementAcknowledgement.parse(acknowledgement.to_bytes()),
            acknowledgement,
        )
        self.assertEqual(acknowledgement.status_flag, 1)
        self.assertEqual(acknowledgement.status_value, 35)
        self.assertEqual(acknowledgement.status_auxiliary_1, 0)
        self.assertEqual(acknowledgement.status_auxiliary_2, 0)
        with self.assertRaises(PacketShapeError):
            replace(
                acknowledgement, status_flag=2
            ).to_bytes()

    def test_movement_path_rejects_unmodeled_or_truncated_commands(self) -> None:
        encoded = bytearray(fixture_movement_path().to_bytes())
        encoded[24] = 3
        with self.assertRaises(PacketShapeError):
            MobMovementPath.parse(bytes(encoded))

        with self.assertRaises(PacketShapeError):
            MobMovementPath.parse(fixture_movement_path().to_bytes()[:-1])

        encoded = bytearray(fixture_movement_path().to_bytes())
        encoded[-9] = 1
        with self.assertRaises(PacketShapeError):
            MobMovementPath.parse(bytes(encoded))

    def test_mob_temporary_stat_set_and_reset_round_trip(self) -> None:
        set_payload = bytes.fromhex(
            "1d01ea114300000000000000000000000000800000000100"
            "4d512f000600760401"
        )
        reset_payload = bytes.fromhex(
            "1e01ea1143000000000000000000000000008000000001"
        )
        stat_set = MobTemporaryStatSet(
            object_id=4_395_498,
            value=1,
            source_skill_id=3_101_005,
            source_level=6,
            duration_value=1_142,
        )
        stat_reset = MobTemporaryStatReset(object_id=4_395_498)

        self.assertTrue(MobTemporaryStatSet.is_captured_shape(set_payload))
        self.assertTrue(
            MobTemporaryStatReset.is_captured_shape(reset_payload)
        )
        self.assertEqual(stat_set.to_bytes(), set_payload)
        self.assertEqual(MobTemporaryStatSet.parse(set_payload), stat_set)
        self.assertEqual(stat_reset.to_bytes(), reset_payload)
        self.assertEqual(
            MobTemporaryStatReset.parse(reset_payload), stat_reset
        )
        self.assertEqual(stat_set.enabled_bit_indices, (103,))
        self.assertEqual(stat_reset.enabled_bit_indices, (103,))
        self.assertNotIn("4395498", str(stat_set.safe_dict()))
        self.assertNotIn("4395498", str(stat_reset.safe_dict()))

        with self.assertRaisesRegex(PacketShapeError, "captured single-bit"):
            replace(stat_set, mask_words=(0, 0, 0, 0x40)).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "captured value one"):
            replace(stat_set, value=2).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "captured value one"):
            replace(stat_reset, flag=0).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "needs 1 bytes"):
            MobTemporaryStatSet.parse(set_payload[:-1])

    def test_mob_lifecycle_and_broadcast_round_trip(self) -> None:
        entered = MobEnterField(
            object_id=MOB_OBJECT_ID,
            spawn=fixture_mob_spawn(),
        )
        extended_enter = MobEnterField(
            object_id=MOB_OBJECT_ID,
            spawn=fixture_mob_spawn(extended_status=True),
        )
        left = MobLeaveField(object_id=MOB_OBJECT_ID, reason=1)
        health = MobHealthPercentageUpdate(
            object_id=MOB_OBJECT_ID,
            health_percentage=42,
        )
        released = MobControllerChange(
            control_level=0,
            object_id=MOB_OBJECT_ID,
        )
        controlled = MobControllerChange(
            control_level=2,
            object_id=MOB_OBJECT_ID,
            spawn=fixture_mob_spawn(),
        )
        broadcast = MobMovementBroadcast(
            object_id=MOB_OBJECT_ID,
            opaque_control=b"\x00\x00\xff\x00\x00\x00\x00",
            reference_x=100,
            reference_y=-200,
            commands=fixture_movement_path().commands,
        )

        for packet_type, packet in (
            (MobEnterField, entered),
            (MobEnterField, extended_enter),
            (MobLeaveField, left),
            (MobHealthPercentageUpdate, health),
            (MobControllerChange, released),
            (MobControllerChange, controlled),
            (MobMovementBroadcast, broadcast),
        ):
            self.assertEqual(packet_type.parse(packet.to_bytes()), packet)
        self.assertEqual(len(entered.to_bytes()), 48)
        self.assertEqual(len(extended_enter.to_bytes()), 56)
        self.assertEqual(len(left.to_bytes()), 7)
        self.assertEqual(len(health.to_bytes()), 7)
        self.assertEqual(len(released.to_bytes()), 7)
        self.assertEqual(len(controlled.to_bytes()), 49)
        self.assertEqual(len(broadcast.to_bytes()), 32)
        with self.assertRaises(PacketShapeError):
            MobControllerChange(
                control_level=0,
                object_id=MOB_OBJECT_ID,
                spawn=fixture_mob_spawn(),
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "between zero and 100"):
            replace(health, health_percentage=101).to_bytes()

    def test_world_session_termination_round_trip(self) -> None:
        termination = WorldSessionTermination(opaque_reason=b"ended!!")

        self.assertEqual(len(termination.to_bytes()), 9)
        self.assertEqual(
            WorldSessionTermination.parse(termination.to_bytes()), termination
        )

    def test_transport_envelopes_and_heartbeat_round_trip(self) -> None:
        probe = HeartbeatProbe()
        response = HeartbeatResponse(opaque_token=b"response")
        notification = ServerOpcode426Notification()
        acknowledgement = ClientOpcode309Acknowledgement()
        opcode_101_record = ClientOpcode101Record(
            header_value=0,
            primary_value=0x0A00_0014,
            flag_value=0,
            secondary_value=0,
            tail_value=0,
        )
        opcode_54_record = ClientOpcode54AttackAction(
            control_value=364_201,
            flag_1=255,
            flag_2=0,
            value_1=1,
            value_2=100_100,
            target_object_id=MOB_OBJECT_ID,
            tail_value=1,
        )
        client_attack_actions = [
            ClientAttackAction(
                opcode=opcode,
                local_object_index=7,
                variant=variant,
                client_token=987_654_321,
                control_value=364_201,
                opaque_common_state=b"state",
                value_1=1,
                value_2=MOB_OBJECT_ID if variant >= 17 else 0,
                opaque_suffix=b"\x00" * suffix_length,
            )
            for opcode, variant, suffix_length in (
                (50, 1, 0),
                (50, 17, 26),
                (52, 1, 1),
                (52, 2, 1),
                (52, 17, 27),
                (52, 18, 31),
            )
        ]
        server_attack_relays = [
            ServerAttackRelay(
                opcode=opcode,
                object_id=PLAYER_OBJECT_ID,
                packed_counts=packed_counts,
                opaque_body=fixture_attack_relay_body(
                    prefix_length=prefix_length,
                    target_count=packed_counts >> 4,
                    hit_count=packed_counts & 0x0F,
                    tail_length=4 if opcode == 219 else 0,
                    zero_targets=opcode == 218 and prefix_length == 6,
                ),
            )
            for opcode, packed_counts, prefix_length in (
                (218, 0x01, 11),
                (218, 0x11, 6),
                (218, 0x11, 11),
                (219, 0x01, 11),
                (219, 0x02, 15),
                (219, 0x11, 11),
                (219, 0x11, 15),
                (219, 0x12, 15),
                (219, 0x21, 15),
                (219, 0x31, 15),
                (219, 0x41, 15),
            )
        ]
        fixed_envelope = Opcode13Type1Envelope(opaque_payload=b"fixed123")
        variable_envelope = Opcode13Envelope(
            message_type=6,
            opaque_payload=b"variable",
        )

        self.assertEqual(HeartbeatProbe.parse(probe.to_bytes()), probe)
        self.assertEqual(
            HeartbeatResponse.parse(response.to_bytes()), response
        )
        self.assertEqual(
            ServerOpcode426Notification.parse(notification.to_bytes()),
            notification,
        )
        self.assertEqual(
            ClientOpcode309Acknowledgement.parse(
                acknowledgement.to_bytes()
            ),
            acknowledgement,
        )
        self.assertEqual(
            ClientOpcode101Record.parse(opcode_101_record.to_bytes()),
            opcode_101_record,
        )
        self.assertEqual(len(opcode_101_record.to_bytes()), 11)
        self.assertEqual(
            ClientOpcode54AttackAction.parse(opcode_54_record.to_bytes()),
            opcode_54_record,
        )
        self.assertEqual(len(opcode_54_record.to_bytes()), 24)
        client_attack_actions[-1] = replace(
            client_attack_actions[-1],
            opaque_suffix=(
                b"\x06"
                + b"\x00" * 13
                + struct.pack("<II", 0x8000_0028, 41)
                + b"\x00" * 9
            ),
        )
        for attack_action in client_attack_actions:
            self.assertEqual(
                ClientAttackAction.parse(attack_action.to_bytes()),
                attack_action,
            )
        two_hit_client_attack = client_attack_actions[-1]
        self.assertEqual(two_hit_client_attack.target_count, 1)
        self.assertEqual(two_hit_client_attack.hit_count, 2)
        self.assertEqual(two_hit_client_attack.damage_values, (40, 41))
        self.assertEqual(
            two_hit_client_attack.high_bit_markers, (True, False)
        )
        self.assertEqual(
            two_hit_client_attack.safe_dict()["opaque_target_prefix_bytes"],
            14,
        )
        self.assertEqual(
            two_hit_client_attack.safe_dict()["opaque_target_tail_bytes"],
            9,
        )
        for attack_relay in server_attack_relays:
            self.assertEqual(
                ServerAttackRelay.parse(attack_relay.to_bytes()),
                attack_relay,
            )
        two_hit_relay = server_attack_relays[7]
        self.assertEqual(two_hit_relay.target_count, 1)
        self.assertEqual(two_hit_relay.hit_count, 2)
        self.assertEqual(len(two_hit_relay.targets), 1)
        self.assertEqual(two_hit_relay.targets[0].object_id, MOB_OBJECT_ID)
        self.assertEqual(two_hit_relay.targets[0].damage_values, (40, 41))
        self.assertEqual(
            two_hit_relay.targets[0].high_bit_markers, (True, False)
        )
        full_melee_metadata = server_attack_relays[2].melee_metadata
        self.assertIsNotNone(full_melee_metadata)
        assert full_melee_metadata is not None
        self.assertEqual(full_melee_metadata.relay_tag, 8)
        self.assertEqual(full_melee_metadata.skill_level, 0)
        self.assertEqual(full_melee_metadata.unknown_value, 0)
        self.assertEqual(full_melee_metadata.display, 5)
        self.assertEqual(full_melee_metadata.facing_flags, 0)
        self.assertEqual(full_melee_metadata.attack_speed, 4)
        self.assertEqual(full_melee_metadata.mastery, 0)
        self.assertEqual(full_melee_metadata.auxiliary_value, 0)
        self.assertFalse(full_melee_metadata.short_zero_target_form)
        short_melee_metadata = server_attack_relays[1].melee_metadata
        self.assertIsNotNone(short_melee_metadata)
        assert short_melee_metadata is not None
        self.assertTrue(short_melee_metadata.short_zero_target_form)
        self.assertIsNone(short_melee_metadata.mastery)
        self.assertIsNone(short_melee_metadata.auxiliary_value)
        ranged_metadata = two_hit_relay.ranged_metadata
        self.assertIsNotNone(ranged_metadata)
        assert ranged_metadata is not None
        self.assertEqual(ranged_metadata.relay_tag, 16)
        self.assertEqual(ranged_metadata.skill_level, 8)
        self.assertEqual(ranged_metadata.skill_id, 4_001_344)
        self.assertEqual(ranged_metadata.unknown_value, 0)
        self.assertEqual(ranged_metadata.display, 0x1A)
        self.assertEqual(ranged_metadata.facing_flags, 0x80)
        self.assertEqual(ranged_metadata.attack_speed, 6)
        self.assertEqual(ranged_metadata.mastery, 0)
        self.assertEqual(ranged_metadata.projectile_id, 2_070_000)
        self.assertEqual(
            (ranged_metadata.position_x, ranged_metadata.position_y),
            (122, -198),
        )
        basic_ranged_metadata = server_attack_relays[5].ranged_metadata
        self.assertIsNotNone(basic_ranged_metadata)
        assert basic_ranged_metadata is not None
        self.assertEqual(basic_ranged_metadata.skill_level, 0)
        self.assertIsNone(basic_ranged_metadata.skill_id)
        self.assertIsNone(two_hit_relay.melee_metadata)
        self.assertIsNone(server_attack_relays[0].ranged_metadata)
        self.assertEqual(two_hit_relay.safe_dict()["skill_id"], 4_001_344)
        self.assertNotIn("object_id", two_hit_relay.safe_dict())
        self.assertNotIn("object_id", two_hit_relay.targets[0].safe_dict())
        with self.assertRaisesRegex(PacketShapeError, "suffix needs 26 bytes"):
            replace(
                client_attack_actions[1], opaque_suffix=b"\x00" * 25
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "expected one of"):
            replace(server_attack_relays[0], opaque_body=b"\x00" * 12).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "imply a 7-byte prefix"):
            replace(server_attack_relays[2], packed_counts=0x12).to_bytes()
        invalid_skill_prefix = bytearray(server_attack_relays[6].opaque_body)
        invalid_skill_prefix[1] = 0
        with self.assertRaisesRegex(
            PacketShapeError, "skill level 0 requires a 11-byte prefix"
        ):
            replace(
                server_attack_relays[6],
                opaque_body=bytes(invalid_skill_prefix),
            ).to_bytes()
        invalid_melee_skill = bytearray(server_attack_relays[2].opaque_body)
        invalid_melee_skill[1] = 1
        with self.assertRaisesRegex(
            PacketShapeError, "expected captured value 0"
        ):
            replace(
                server_attack_relays[2],
                opaque_body=bytes(invalid_melee_skill),
            ).to_bytes()
        invalid_short_target = bytearray(server_attack_relays[1].opaque_body)
        invalid_short_target[6] = 1
        with self.assertRaisesRegex(PacketShapeError, "one all-zero target"):
            replace(
                server_attack_relays[1],
                opaque_body=bytes(invalid_short_target),
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "flag_1 must fit"):
            ClientOpcode54AttackAction(
                control_value=364_201,
                flag_1=256,
                flag_2=0,
                value_1=1,
                value_2=100_100,
                target_object_id=MOB_OBJECT_ID,
                tail_value=1,
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "tail_value must fit"):
            ClientOpcode101Record(
                header_value=0,
                primary_value=20,
                flag_value=0,
                secondary_value=3,
                tail_value=256,
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "uninterpreted bytes"):
            ServerOpcode426Notification.parse(
                notification.to_bytes() + b"\x00"
            )
        self.assertEqual(
            Opcode13Type1Envelope.parse(fixed_envelope.to_bytes()),
            fixed_envelope,
        )
        self.assertEqual(
            Opcode13Envelope.parse(variable_envelope.to_bytes()),
            variable_envelope,
        )
        with self.assertRaisesRegex(PacketShapeError, "needs 8 opaque bytes"):
            Opcode13Type1Envelope(opaque_payload=b"short").to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "expected 1"):
            Opcode13Type1Envelope(
                opaque_payload=b"fixed123",
                message_type=2,
            ).to_bytes()


class GameplayStateFoldTest(unittest.TestCase):
    def test_player_mob_proximity_predicate_is_edge_triggered(self) -> None:
        with self.assertRaisesRegex(ValueError, "radius must be in 1..4096"):
            PlayerMobProximityPredicate(radius=0)
        with self.assertRaisesRegex(ValueError, "radius must be in 1..4096"):
            PlayerMobProximityPredicate(radius=4097)
        predicate = PlayerMobProximityPredicate(radius=10)

        self.assertFalse(
            predicate.observe(player_x=0, player_y=0, mob_x=20, mob_y=0)
        )
        self.assertTrue(
            predicate.observe(player_x=11, player_y=0, mob_x=20, mob_y=0)
        )
        self.assertFalse(
            predicate.observe(player_x=10, player_y=0, mob_x=20, mob_y=0)
        )
        self.assertFalse(
            predicate.observe(player_x=0, player_y=0, mob_x=20, mob_y=0)
        )
        self.assertTrue(
            predicate.observe(player_x=20, player_y=0, mob_x=20, mob_y=0)
        )

        self.assertEqual(
            predicate.safe_dict(),
            {
                "radius": 10,
                "events_observed": 5,
                "entries_observed": 2,
                "player_was_within_radius": True,
                "last_observation": {
                    "player": {"x": 20, "y": 0},
                    "mob": {"x": 20, "y": 0},
                    "manhattan_distance": 0,
                    "within_radius": True,
                    "entered_radius": True,
                },
            },
        )

    def test_correlates_client_damage_array_with_mob_health_update(
        self,
    ) -> None:
        fold = GameplayStateFold()
        spawn_payload = MobEnterField(
            object_id=MOB_OBJECT_ID,
            spawn=fixture_mob_spawn(),
        ).to_bytes()
        attack_payload = ClientAttackAction(
            opcode=52,
            local_object_index=7,
            variant=18,
            client_token=987_654_324,
            control_value=807_666,
            opaque_common_state=b"state",
            value_1=3,
            value_2=MOB_OBJECT_ID,
            opaque_suffix=(
                b"\x06"
                + b"\x00" * 13
                + struct.pack("<II", 0x8000_0028, 41)
                + b"\x00" * 9
            ),
        ).to_bytes()
        initial_health_payload = MobHealthPercentageUpdate(
            object_id=MOB_OBJECT_ID,
            health_percentage=100,
        ).to_bytes()
        first_health_payload = MobHealthPercentageUpdate(
            object_id=MOB_OBJECT_ID,
            health_percentage=18,
        ).to_bytes()
        second_health_payload = MobHealthPercentageUpdate(
            object_id=MOB_OBJECT_ID,
            health_percentage=0,
        ).to_bytes()

        frames = (
            PlainFrame(
                index=0,
                direction_index=0,
                timestamp_ns=1_000_000_000,
                direction="server_to_client",
                wire_offset=0,
                wire_length=len(spawn_payload),
                plaintext=spawn_payload,
            ),
            PlainFrame(
                index=1,
                direction_index=1,
                timestamp_ns=1_010_000_000,
                direction="server_to_client",
                wire_offset=len(spawn_payload),
                wire_length=len(initial_health_payload),
                plaintext=initial_health_payload,
            ),
            PlainFrame(
                index=2,
                direction_index=0,
                timestamp_ns=1_020_000_000,
                direction="client_to_server",
                wire_offset=0,
                wire_length=len(attack_payload),
                plaintext=attack_payload,
            ),
            PlainFrame(
                index=3,
                direction_index=2,
                timestamp_ns=1_120_000_000,
                direction="server_to_client",
                wire_offset=len(spawn_payload) + len(initial_health_payload),
                wire_length=len(first_health_payload),
                plaintext=first_health_payload,
            ),
            PlainFrame(
                index=4,
                direction_index=3,
                timestamp_ns=1_130_000_000,
                direction="server_to_client",
                wire_offset=(
                    len(spawn_payload)
                    + len(initial_health_payload)
                    + len(first_health_payload)
                ),
                wire_length=len(second_health_payload),
                plaintext=second_health_payload,
            ),
        )
        observations = tuple(fold.consume(frame) for frame in frames)

        self.assertEqual(fold.state.client_attack_damage_actions, 1)
        self.assertEqual(fold.state.client_attack_damage_entries, 2)
        self.assertEqual(fold.state.client_attack_damage_total, 81)
        self.assertEqual(fold.state.client_attack_zero_damage_entries, 0)
        self.assertEqual(fold.state.client_attack_health_matches, 2)
        self.assertEqual(fold.state.client_attack_health_predictions, 2)
        self.assertEqual(
            fold.state.client_attack_health_prediction_matches, 1
        )
        self.assertEqual(
            fold.state.client_attack_health_prediction_mismatches, 1
        )
        self.assertEqual(
            fold.state.client_attack_health_one_hp_differences, 1
        )
        self.assertEqual(
            fold.state.client_attack_predictions_with_relay_hits, 0
        )
        self.assertEqual(
            fold.state.client_attack_mismatches_without_relays, 1
        )
        self.assertEqual(
            fold.state.client_attack_health_mismatch_damage_deltas,
            {1: 1},
        )
        self.assertEqual(
            fold.state.client_attack_health_predictions_by_template,
            {210_100: 2},
        )
        self.assertEqual(fold.state.client_attack_effects_cleared, 0)
        self.assertEqual(fold.state.pending_client_attack_effects, 0)
        self.assertEqual(
            fold.state.last_client_attack_health_response_ms, 110.0
        )
        self.assertEqual(
            fold.state.max_client_attack_health_response_ms, 110.0
        )
        first_health_details = observations[-2].details
        second_health_details = observations[-1].details
        self.assertTrue(first_health_details["matched_client_attack"])
        self.assertEqual(first_health_details["client_attack_frame"], 2)
        self.assertEqual(first_health_details["submitted_hit_index"], 0)
        self.assertEqual(first_health_details["submitted_damage"], 40)
        self.assertEqual(
            first_health_details["predicted_health_percentage_min"], 20
        )
        self.assertEqual(
            first_health_details["predicted_health_percentage_max"], 20
        )
        self.assertFalse(first_health_details["health_prediction_matches"])
        self.assertEqual(first_health_details["predicted_hp_min"], 10)
        self.assertEqual(first_health_details["predicted_hp_max"], 10)
        self.assertEqual(first_health_details["health_prediction_hp_delta"], -1)
        self.assertEqual(first_health_details["health_hp_min"], 9)
        self.assertEqual(
            first_health_details["inferred_authoritative_damage_min"], 41
        )
        self.assertEqual(
            first_health_details["inferred_authoritative_damage_max"], 41
        )
        self.assertEqual(
            first_health_details[
                "authoritative_minus_submitted_damage_min"
            ],
            1,
        )
        self.assertEqual(
            first_health_details[
                "authoritative_minus_submitted_damage_max"
            ],
            1,
        )
        self.assertEqual(
            first_health_details["intervening_attack_relay_hits"], 0
        )
        self.assertEqual(second_health_details["submitted_hit_index"], 1)
        self.assertEqual(second_health_details["submitted_damage"], 41)
        self.assertEqual(
            second_health_details["submitted_damage_values"], [40, 41]
        )
        self.assertEqual(second_health_details["submitted_damage_total"], 81)
        self.assertEqual(
            second_health_details["submitted_high_bit_markers"], [True, False]
        )
        self.assertEqual(
            second_health_details["client_attack_response_ms"], 110.0
        )

    def test_predicts_floor_percentage_from_reference_mob_hp(self) -> None:
        self.assertEqual(mob_hp_bounds_for_percentage(40, 67), (27, 27))
        self.assertEqual(
            predict_mob_health_percentage_range(
                max_hp=40,
                previous_percentage=67,
                damage=17,
            ),
            (25, 25),
        )
        self.assertEqual(
            predict_mob_health_percentage_range(
                max_hp=300,
                previous_percentage=78,
                damage=19,
            ),
            (71, 72),
        )

    def test_zero_damage_hit_needs_no_health_response(self) -> None:
        fold = GameplayStateFold()
        payloads = (
            MobEnterField(
                object_id=MOB_OBJECT_ID,
                spawn=fixture_mob_spawn(),
            ).to_bytes(),
            MobHealthPercentageUpdate(
                object_id=MOB_OBJECT_ID,
                health_percentage=100,
            ).to_bytes(),
            ClientAttackAction(
                opcode=52,
                local_object_index=7,
                variant=18,
                client_token=987_654_324,
                control_value=807_666,
                opaque_common_state=b"state",
                value_1=3,
                value_2=MOB_OBJECT_ID,
                opaque_suffix=(
                    b"\x06"
                    + b"\x00" * 13
                    + struct.pack("<II", 0, 19)
                    + b"\x00" * 9
                ),
            ).to_bytes(),
            MobHealthPercentageUpdate(
                object_id=MOB_OBJECT_ID,
                health_percentage=62,
            ).to_bytes(),
        )
        directions = (
            "server_to_client",
            "server_to_client",
            "client_to_server",
            "server_to_client",
        )
        observations = tuple(
            fold.consume(
                PlainFrame(
                    index=index,
                    direction_index=index,
                    timestamp_ns=1_000_000_000 + index * 10_000_000,
                    direction=direction,
                    wire_offset=0,
                    wire_length=len(payload),
                    plaintext=payload,
                )
            )
            for index, (direction, payload) in enumerate(
                zip(directions, payloads, strict=True)
            )
        )

        self.assertEqual(fold.state.client_attack_damage_entries, 2)
        self.assertEqual(fold.state.client_attack_zero_damage_entries, 1)
        self.assertEqual(fold.state.client_attack_health_matches, 1)
        self.assertEqual(fold.state.pending_client_attack_effects, 0)
        self.assertEqual(observations[-1].details["submitted_hit_index"], 1)
        self.assertEqual(observations[-1].details["submitted_damage"], 19)
        self.assertTrue(
            observations[-1].details["health_prediction_matches"]
        )

    def test_reactive_mob_health_policy_adopts_typed_spawn(self) -> None:
        policy = MobHealthResponsePolicy(mobs={}, field_epoch=1)
        policy.apply_server_packet(
            MobEnterField(
                object_id=MOB_OBJECT_ID,
                spawn=fixture_mob_spawn(),
            ).to_bytes()
        )

        mob = policy.mobs[MOB_OBJECT_ID]
        self.assertEqual(mob.template_id, 210_100)
        self.assertEqual(mob.current_hp, 50)
        self.assertEqual(mob.max_hp, 50)
        safe_mob = policy.safe_dict()["active_mobs"][0]
        self.assertEqual(safe_mob["entity"], "mob:runtime:1")

        policy.apply_server_packet(
            MobEnterField(
                object_id=MOB_OBJECT_ID,
                spawn=replace(fixture_mob_spawn(), template_id=999_998),
            ).to_bytes()
        )
        self.assertNotIn(MOB_OBJECT_ID, policy.mobs)

    def test_reactive_mob_health_policy_skips_post_terminal_hit(self) -> None:
        policy = MobHealthResponsePolicy(mobs={}, field_epoch=1)
        policy.apply_server_packet(
            MobEnterField(
                object_id=MOB_OBJECT_ID,
                spawn=replace(fixture_mob_spawn(), template_id=100_100),
            ).to_bytes()
        )
        attack = ClientAttackAction(
            opcode=52,
            local_object_index=7,
            variant=18,
            client_token=987_654_324,
            control_value=807_666,
            opaque_common_state=b"state",
            value_1=3,
            value_2=MOB_OBJECT_ID,
            opaque_suffix=(
                b"\x06"
                + b"\x00" * 13
                + struct.pack("<II", 27, 32)
                + b"\x00" * 9
            ),
        )

        response = policy.respond(attack)

        self.assertEqual((response.hp_before, response.hp_after), (8, 0))
        self.assertEqual(response.health_percentages, (0,))
        self.assertEqual(response.terminal_hits_skipped, 1)
        self.assertTrue(response.removed)
        self.assertEqual(
            [
                int.from_bytes(packet[:2], "little")
                for packet in response.plaintexts
            ],
            [293, 280],
        )
        self.assertNotIn(MOB_OBJECT_ID, policy.mobs)

    def test_derives_typed_item_pickup_response_from_separate_evidence(
        self,
    ) -> None:
        evidence = fixture_gameplay_transcript(item_pickup=True)
        replay = fixture_gameplay_transcript(
            initial_snapshot=True,
            inventory_changes=True,
            active_item_drop=True,
        )
        policy = derive_item_pickup_response_policy(
            replay,
            evidence_transcript=evidence,
        )

        modeled = policy.safe_dict()["modeled_drops"]
        self.assertEqual(len(modeled), 1)
        self.assertEqual(modeled[0]["item_id"], 4_010_003)
        self.assertEqual(modeled[0]["inventory"], "etc")
        self.assertEqual(modeled[0]["quantity"], 1)
        request = ItemPickupRequest(
            control_value=0,
            field_epoch=1,
            client_tick=102_100,
            position_x=633,
            position_y=-2677,
            drop_object_id=40_004,
            item_validation_token=1_352_639_939,
        )
        plan = policy.respond(request)

        self.assertEqual(plan.drop_alias, "drop:1")
        self.assertEqual(plan.quantity_before, 1)
        self.assertEqual(plan.quantity_delta, 1)
        self.assertEqual(plan.quantity_after, 2)
        self.assertEqual(
            tuple(int.from_bytes(payload[:2], "little") for payload in plan.plaintexts),
            (39, 49, 312),
        )
        self.assertEqual(
            InventoryChangeSet.parse(plan.plaintexts[0]).modifications[0].quantity,
            2,
        )
        self.assertEqual(PickupGainNotice.parse(plan.plaintexts[1]).quantity, 1)
        removal = FieldDropRemoval.parse(plan.plaintexts[2])
        self.assertEqual(removal.reason, 5)
        self.assertEqual(removal.actor_id, CHARACTER_ID)
        self.assertEqual(removal.trailing_value, 0)
        self.assertEqual(policy.inventory_items["etc"][2].quantity, 2)
        self.assertEqual(policy.active_drops, {})
        with self.assertRaisesRegex(ValueError, "unknown active drop"):
            policy.respond(request)

    def test_plans_typed_final_field_drop_position_rewrite(self) -> None:
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            inventory_changes=True,
            active_item_drop=True,
        )
        plan = plan_final_field_drop_position_rewrite(transcript, 633, -2677)

        self.assertEqual(plan.drop_alias, "drop:1")
        self.assertEqual(plan.item_id, 4_010_003)
        self.assertEqual(
            (plan.original_position_x, plan.original_position_y),
            (-863, -1742),
        )
        self.assertEqual(
            (plan.rewritten_position_x, plan.rewritten_position_y),
            (633, -2677),
        )
        self.assertEqual(
            FieldDropSpawn.parse(plan.replacement.to_bytes()),
            plan.replacement,
        )
        self.assertEqual(
            plan.safe_dict()["prediction"]["drop_position"], "rewritten"
        )

    def test_plans_identifier_free_final_field_drop_owner_rewrite(self) -> None:
        foreign_owner = CHARACTER_ID + 1
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            inventory_changes=True,
            active_item_drop=True,
            active_item_drop_owner=foreign_owner,
        )

        plan = plan_final_field_drop_owner_to_player_rewrite(transcript)

        self.assertEqual(plan.drop_alias, "drop:1")
        self.assertEqual(plan.item_id, 4_010_003)
        self.assertEqual(plan.replacement.owner_value_1, CHARACTER_ID)
        self.assertEqual(plan.replacement.owner_value_2, CHARACTER_ID)
        safe = plan.safe_dict()
        self.assertEqual(
            safe["prediction"]["drop_owner_fields"],
            "match_initial_player",
        )
        self.assertEqual(
            safe["prediction"]["pickup_eligibility"],
            "requires_additional_client_conditions",
        )
        self.assertNotIn(str(CHARACTER_ID), str(safe))
        self.assertNotIn(str(foreign_owner), str(safe))

    def test_generated_item_pickup_response_matches_gameplay_fold(self) -> None:
        evidence = fixture_gameplay_transcript(item_pickup=True)
        replay = fixture_gameplay_transcript(
            initial_snapshot=True,
            inventory_changes=True,
            active_item_drop=True,
        )
        policy = derive_item_pickup_response_policy(
            replay,
            evidence_transcript=evidence,
        )
        request = ItemPickupRequest(
            control_value=0,
            field_epoch=1,
            client_tick=102_100,
            position_x=633,
            position_y=-2677,
            drop_object_id=40_004,
            item_validation_token=1_352_639_939,
        )
        response = policy.respond(request)
        baseline = analyze_gameplay_transcript(replay)
        ivs = {
            "client_to_server": FIRST_IV,
            "server_to_client": SECOND_IV,
        }
        for direction in ivs:
            for _ in range(
                sum(
                    frame.direction == direction
                    for frame in baseline.decoded.frames
                )
            ):
                ivs[direction] = shuffle_iv(ivs[direction])
        events = [event for event in replay.events if event.event != "close"]
        timestamp_ns = events[-1].timestamp_ns + 1

        def append(direction: str, plaintext: bytes) -> None:
            nonlocal timestamp_ns
            iv = ivs[direction]
            events.append(
                TranscriptEvent(
                    event="data",
                    timestamp_ns=timestamp_ns,
                    direction=direction,
                    data=(
                        encode_frame_header(
                            len(plaintext),
                            iv,
                            3 if direction == "client_to_server" else ~300,
                        )
                        + crypt_payload(plaintext, iv)
                    ),
                )
            )
            ivs[direction] = shuffle_iv(iv)
            timestamp_ns += 1

        append("client_to_server", request.to_bytes())
        for plaintext in response.plaintexts:
            append("server_to_client", plaintext)
        events.append(TranscriptEvent(event="close", timestamp_ns=timestamp_ns))
        observed = Transcript(
            path=Path("generated-item-pickup.jsonl"),
            events=tuple(events),
        )
        analysis = analyze_gameplay_transcript(observed)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.item_pickup_known_drops, 1)
        self.assertEqual(analysis.state.item_pickup_spawn_result_matches, 1)
        self.assertEqual(analysis.state.item_pickup_effect_matches, 1)
        self.assertEqual(analysis.state.item_pickup_removal_matches, 1)
        self.assertEqual(analysis.state.pending_item_pickups, 0)
        self.assertEqual(analysis.state.field_drops, {})
        item = next(
            item
            for item in analysis.state.inventory_items["etc"]
            if item.slot == 2
        )
        self.assertEqual(item.quantity, 2)

    def test_plans_typed_initial_player_hp_rewrite(self) -> None:
        transcript = fixture_gameplay_transcript(initial_snapshot=True)
        plan = plan_initial_player_hp_rewrite(transcript, 1)

        self.assertEqual(plan.server_frame_index, 0)
        self.assertEqual(plan.original_current_hp, 70)
        self.assertEqual(plan.rewritten_current_hp, 1)
        self.assertEqual(plan.max_hp, 222)
        self.assertEqual(plan.replacement.character.current_hp, 1)
        self.assertEqual(
            InitialFieldSnapshot.parse(plan.replacement.to_bytes()),
            plan.replacement,
        )
        self.assertEqual(plan.safe_dict()["prediction"]["phase"], "unchanged")
        with self.assertRaisesRegex(ValueError, "between 0 and 222"):
            plan_initial_player_hp_rewrite(transcript, 223)

    def test_plans_lossless_typed_initial_field_snapshot_emission(self) -> None:
        transcript = fixture_gameplay_transcript(initial_snapshot=True)

        plan = plan_initial_field_snapshot_replay(transcript)
        emitted = plan.replacement.to_bytes()
        typed = TypedInitialFieldSnapshot.parse(emitted)

        self.assertEqual(plan.original_current_hp, 70)
        self.assertEqual(plan.rewritten_current_hp, 70)
        self.assertEqual(typed, plan.typed_state)
        self.assertEqual(typed.inventory_item_count, 1)
        self.assertEqual(len(typed.inventory_groups), 9)
        self.assertEqual(typed.progression.variant, 1)
        self.assertEqual(plan.safe_dict()["emitter"], "typed_initial_field_snapshot")

    def test_plans_lossless_compact_initial_field_snapshot_emission(self) -> None:
        snapshot = fixture_compact_initial_field_snapshot()
        transcript = fixture_gameplay_transcript(
            initial_snapshot_payload=snapshot.to_bytes()
        )

        plan = plan_initial_field_snapshot_replay(transcript)

        self.assertEqual(plan.replacement.to_bytes(), snapshot.to_bytes())
        self.assertIsInstance(
            plan.typed_state.progression,
            CompactInitialProgressionSnapshot,
        )
        self.assertEqual(plan.safe_dict()["progression_shape"], "compact")
        self.assertEqual(plan.safe_dict()["skill_level_count"], 1)

    def test_plans_lossless_typed_field_npc_spawn_emission(self) -> None:
        transcript = fixture_gameplay_transcript(initial_snapshot=True)

        plan = plan_field_npc_spawn_replay(transcript)

        self.assertEqual(len(plan.frames), 1)
        frame = plan.frames[0]
        self.assertEqual(frame.server_frame_index, 1)
        self.assertEqual(frame.entity, "npc:1")
        self.assertEqual(NpcSpawn.parse(frame.spawn.to_bytes()), frame.spawn)
        safe = plan.safe_dict()
        self.assertEqual(safe["emitter"], "typed_npc_spawn")
        self.assertEqual(safe["frame_count"], 1)
        self.assertEqual(safe["field_epochs"], [1])
        self.assertEqual(
            safe["spawns"][0]["template_id"], fixture_npc().template_id
        )
        self.assertNotIn(str(NPC_OBJECT_ID), repr(safe))

    def test_folds_npc_lifecycle_spawn_update_and_removal(self) -> None:
        spawn = NpcSpawn(
            object_id=23_607,
            template_id=2_102,
            x=-59,
            cy=95,
            facing_value=1,
            foothold_id=35,
            range_left=-109,
            range_right=-9,
            hidden=True,
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=(
                NpcLifecycleControl(
                    object_id=spawn.object_id,
                    control_value=NpcLifecycleControl.SPAWN,
                    spawn=spawn,
                ).to_bytes(),
                NpcStateUpdate(
                    object_id=spawn.object_id,
                    action=3,
                    parameter=1,
                ).to_bytes(),
                NpcLifecycleControl(
                    object_id=spawn.object_id,
                    control_value=NpcLifecycleControl.REMOVE,
                ).to_bytes(),
                NpcLifecycleControl(
                    object_id=spawn.object_id,
                    control_value=NpcLifecycleControl.REMOVE,
                ).to_bytes(),
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.npc_lifecycle_spawns, 1)
        self.assertEqual(analysis.state.npc_lifecycle_removals, 2)
        self.assertEqual(analysis.state.npc_lifecycle_unknown_removals, 1)
        self.assertEqual(analysis.state.npc_spawns, 2)
        self.assertEqual(analysis.state.npc_state_updates, 2)
        self.assertEqual(list(analysis.state.npcs), [NPC_OBJECT_ID])
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind.startswith("npc_lifecycle_")
        ]
        self.assertEqual(
            [observation.kind for observation in observations],
            [
                "npc_lifecycle_spawn",
                "npc_lifecycle_removal",
                "npc_lifecycle_removal",
            ],
        )
        self.assertTrue(
            all(
                observation.coverage.value == "full"
                for observation in observations
            )
        )
        event_kinds = [event.kind for event in analysis.events]
        self.assertEqual(event_kinds.count("npc_spawned"), 2)
        self.assertEqual(event_kinds.count("npc_removed"), 2)
        safe = analysis.safe_dict()
        self.assertNotIn("23607", str(safe))
        self.assertIn(
            "lifecycle_spawns:1 lifecycle_removals:2 "
            "lifecycle_unknown_removals:1",
            render_gameplay_analysis(analysis),
        )

    def test_folds_and_plans_fixed_server_record_emission(self) -> None:
        records = fixture_fixed_server_records()
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=tuple(
                record.to_bytes() for record in records
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)
        plan = plan_fixed_server_record_replay(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.fixed_server_records, len(records))
        self.assertEqual(analysis.state.initial_character_contexts, 1)
        self.assertEqual(
            analysis.state.fixed_server_records_by_opcode,
            {record.opcode: 1 for record in records},
        )
        self.assertEqual(len(plan.frames), len(records))
        self.assertEqual(
            [frame.record.opcode for frame in plan.frames],
            [record.opcode for record in records],
        )
        self.assertTrue(
            all(
                type(frame.record).parse(frame.record.to_bytes())
                == frame.record
                for frame in plan.frames
            )
        )
        safe = plan.safe_dict()
        self.assertEqual(safe["emitter"], "typed_fixed_server_record")
        self.assertNotIn(str(CHARACTER_ID), repr(safe))
        context = next(
            frame
            for frame in safe["frames"]
            if frame["kind"] == "initial_character_context"
        )
        self.assertTrue(context["entry_character_match"])

    def test_folds_and_plans_variable_server_record_emission(self) -> None:
        records = fixture_variable_server_records()
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=tuple(
                record.to_bytes() for record in records
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)
        plan = plan_variable_server_record_replay(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.variable_server_records, 4)
        self.assertEqual(
            analysis.state.variable_server_records_by_opcode,
            {156: 2, 385: 2},
        )
        self.assertEqual(
            analysis.state.variable_server_variants,
            {"156:0": 1, "156:1": 1, "385:0": 1, "385:1": 1},
        )
        self.assertEqual(analysis.state.variable_server_typed_entries, 89)
        self.assertEqual(analysis.state.variable_server_typed_values, 3)
        self.assertEqual(analysis.state.variable_server_opaque_bytes, 0)
        self.assertEqual(analysis.state.keyboard_binding_snapshots, 1)
        self.assertEqual(
            analysis.state.keyboard_binding_selector_counts,
            {0: 86, 1: 2, 4: 1},
        )
        self.assertEqual(
            analysis.state.keyboard_skill_bindings,
            {29: 2_001_005, 71: 2_001_002},
        )
        self.assertEqual(analysis.state.keyboard_known_skill_bindings, 2)
        self.assertEqual(analysis.state.left_ctrl_skill_id, 2_001_005)
        self.assertTrue(analysis.state.left_ctrl_skill_known)
        self.assertEqual([frame.record for frame in plan.frames], list(records))
        safe = plan.safe_dict()
        self.assertEqual(safe["emitter"], "typed_variable_server_record")
        self.assertEqual(
            [frame["opaque_tail_length"] for frame in safe["frames"]],
            [0, 0, 0, 0],
        )
        self.assertEqual(
            [frame["entry_count"] for frame in safe["frames"]],
            [0, 0, 89, 0],
        )
        self.assertEqual(
            [frame["text_code_units"] for frame in safe["frames"]],
            [0, 1, 0, 0],
        )
        self.assertEqual(
            [frame["flag"] for frame in safe["frames"]],
            [None, False, None, None],
        )
        self.assertEqual(
            [frame["value_count"] for frame in safe["frames"]],
            [0, 3, 0, 0],
        )
        self.assertEqual(safe["prediction"]["typed_value_count"], 3)
        self.assertEqual(safe["prediction"]["keyboard_binding_snapshots"], 1)
        self.assertEqual(
            safe["prediction"]["final_left_ctrl_skill_id"], 2_001_005
        )
        self.assertEqual(safe["frames"][2]["skill_binding_count"], 2)
        self.assertEqual(
            safe["frames"][2]["left_ctrl_skill_id"], 2_001_005
        )
        keyboard_state = analysis.safe_dict()["state"]["keyboard_bindings"]
        self.assertEqual(keyboard_state["key_code_space"], "linux_evdev")
        self.assertEqual(
            keyboard_state["validated_key_codes"], {"left_ctrl": 29}
        )
        self.assertEqual(
            keyboard_state["skill_bindings"],
            {29: 2_001_005, 71: 2_001_002},
        )
        self.assertEqual(
            sum(
                event.kind == "keyboard_bindings_loaded"
                for event in analysis.events
            ),
            1,
        )
        self.assertNotIn("11111111", repr(safe))
        self.assertNotIn("22222222", repr(safe))

    def test_folds_client_skill_use_against_progression_and_bindings(
        self,
    ) -> None:
        keyboard = fixture_variable_server_records()[2]
        requests = (
            ClientSkillUseRequest(
                client_tick=393_636,
                skill_id=2_001_002,
                skill_level=1,
                trailing_value=0,
            ),
            ClientSkillUseRequest(
                client_tick=623_660,
                skill_id=2_001_002,
                skill_level=1,
                trailing_value=0,
            ),
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=(keyboard.to_bytes(),),
            extra_client_plaintexts=tuple(
                request.to_bytes() for request in requests
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.client_skill_use_requests, 2)
        self.assertEqual(
            analysis.state.client_skill_use_requests_by_skill_id,
            {2_001_002: 2},
        )
        self.assertEqual(
            analysis.state.client_skill_use_level_values, {1: 2}
        )
        self.assertEqual(
            analysis.state.client_skill_use_trailing_values, {0: 2}
        )
        self.assertEqual(analysis.state.client_skill_use_known_skills, 2)
        self.assertEqual(analysis.state.client_skill_use_unknown_skills, 0)
        self.assertEqual(analysis.state.client_skill_use_level_matches, 2)
        self.assertEqual(analysis.state.client_skill_use_level_mismatches, 0)
        self.assertEqual(analysis.state.client_skill_use_binding_matches, 2)
        self.assertEqual(analysis.state.client_skill_use_binding_mismatches, 0)
        self.assertEqual(analysis.state.last_client_skill_tick, 623_660)
        self.assertEqual(analysis.state.client_skill_tick_decreases, 0)
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "client_skill_use_request"
        ]
        self.assertEqual(len(observations), 2)
        self.assertTrue(
            all(
                observation.coverage.value == "full"
                for observation in observations
            )
        )
        self.assertEqual(observations[0].details["bound_key_codes"], [71])
        self.assertTrue(observations[0].details["skill_level_matches_model"])
        self.assertEqual(observations[1].details["client_tick_delta"], 230_024)
        self.assertEqual(
            sum(
                event.kind == "client_skill_use_submitted"
                for event in analysis.events
            ),
            2,
        )
        safe = analysis.safe_dict()["state"]["client_skill_uses"]
        self.assertEqual(safe["requests_by_skill_id"], {2_001_002: 2})
        self.assertEqual(safe["level_matches"], 2)
        self.assertIn(
            "client_skill_uses=requests:2",
            render_gameplay_analysis(analysis),
        )

    def test_folds_local_temporary_stat_zero_mask_without_state_change(
        self,
    ) -> None:
        header = LocalTemporaryStatSetHeader(
            mask_words=(0, 0, 0, 0),
            zero_mask_flag_a=0,
            zero_mask_flag_b=0,
            zero_mask_trailing_i16=0,
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=(header.to_bytes(),),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.current_hp, 70)
        self.assertEqual(analysis.state.current_mp, 136)
        self.assertEqual(analysis.state.local_temporary_stat_sets, 1)
        self.assertEqual(analysis.state.local_temporary_stat_zero_masks, 1)
        self.assertEqual(analysis.state.local_temporary_stat_nonzero_masks, 0)
        self.assertEqual(analysis.state.local_temporary_stat_enabled_bits, 0)
        self.assertEqual(
            analysis.state.local_temporary_stat_mask_patterns,
            {"00000000:00000000:00000000:00000000": 1},
        )
        observation = next(
            observation
            for observation in analysis.observations
            if observation.kind == "local_temporary_stat_set_header"
        )
        self.assertEqual(observation.coverage.value, "partial")
        self.assertEqual(observation.details["modeled_state_change"], "none")
        self.assertFalse(observation.details["network_progression_proven"])
        event = next(
            event
            for event in analysis.events
            if event.kind == "local_temporary_stat_set_received"
        )
        self.assertEqual(event.details["enabled_bit_count"], 0)
        safe = analysis.safe_dict()["state"]["local_temporary_stat_sets"]
        self.assertEqual(safe["packet_count"], 1)
        self.assertEqual(safe["zero_mask_flag_a_values"], {0: 1})
        self.assertIn(
            "local_temporary_stat_sets=packets:1 zero_masks:1",
            render_gameplay_analysis(analysis),
        )

    def test_folds_server_opcode_77_without_exposing_text(self) -> None:
        envelopes = (
            ServerOpcode77Envelope(
                variant=3,
                primary_text="sensitive chat text",
                control_bytes=(0, 4, 1),
            ),
            ServerOpcode77Envelope(variant=4, control_bytes=(0,)),
            ServerOpcode77Envelope(
                variant=5,
                primary_text="SID_WORLDNOTICE_WEDDING_CATHEDRAL",
                secondary_text="sensitive sender",
                tertiary_text="sensitive recipient",
                control_bytes=ServerOpcode77Envelope.VARIANT_5_CONTROLS,
                terminal_u32=28,
            ),
            ServerOpcode77Envelope(
                variant=8,
                primary_text="sensitive child text",
                opaque_tail=b"\x00\x07\x00\x00",
            ),
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=tuple(
                envelope.to_bytes() for envelope in envelopes
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.current_hp, 70)
        self.assertEqual(analysis.state.current_mp, 136)
        self.assertEqual(analysis.state.server_opcode_77_packets, 4)
        self.assertEqual(
            analysis.state.server_opcode_77_by_variant,
            {3: 1, 4: 1, 5: 1, 8: 1},
        )
        self.assertEqual(analysis.state.server_opcode_77_text_fields, 5)
        expected_code_units = sum(
            sum(envelope.text_code_unit_counts) for envelope in envelopes
        )
        self.assertEqual(
            analysis.state.server_opcode_77_text_code_units,
            expected_code_units,
        )
        self.assertEqual(analysis.state.server_opcode_77_opaque_bytes, 4)
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "server_opcode_77_envelope"
        ]
        self.assertEqual(
            [observation.coverage.value for observation in observations],
            ["full", "full", "full", "partial"],
        )
        events = [
            event
            for event in analysis.events
            if event.kind == "server_opcode_77_received"
        ]
        self.assertEqual(len(events), 4)
        safe = str(analysis.safe_dict())
        self.assertNotIn("sensitive", safe)
        self.assertIn(
            "server_opcode_77=packets:4 variants:",
            render_gameplay_analysis(analysis),
        )

    def test_folds_non_pickup_server_opcode_49_without_pickup_effects(
        self,
    ) -> None:
        envelopes = (
            ServerOpcode49Envelope(
                variant=1,
                key=1_039,
                value_kind=ServerOpcode49Envelope.TEXT_VALUE,
                text_value="sensitive keyed value",
            ),
            ServerOpcode49Envelope(
                variant=1,
                key=1_039,
                value_kind=ServerOpcode49Envelope.U64_VALUE,
                numeric_value=134_152_909_663_840_000,
            ),
            ServerOpcode49Envelope(
                variant=3,
                record_marker=1,
                record_value=8,
                opaque_tail=b"\x00" * 28,
            ),
            ServerOpcode49Envelope(variant=4, opaque_tail=b"\x00\x00\x01"),
            ServerOpcode49Envelope(variant=6, numeric_value=200),
            ServerOpcode49Envelope(
                variant=10,
                reserved_value=0,
                text_value="sensitive system text",
            ),
            ServerOpcode49Envelope(
                variant=12,
                key=29_400,
                text_value="sensitive keyed text",
            ),
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=tuple(
                envelope.to_bytes() for envelope in envelopes
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.item_pickup_results, 0)
        self.assertEqual(analysis.state.server_opcode_49_packets, 7)
        self.assertEqual(
            analysis.state.server_opcode_49_by_variant,
            {1: 2, 3: 1, 4: 1, 6: 1, 10: 1, 12: 1},
        )
        self.assertEqual(analysis.state.server_opcode_49_text_fields, 3)
        self.assertEqual(
            analysis.state.server_opcode_49_text_code_units,
            sum(
                envelope.text_code_unit_count or 0 for envelope in envelopes
            ),
        )
        self.assertEqual(analysis.state.server_opcode_49_opaque_bytes, 31)
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "server_opcode_49_envelope"
        ]
        self.assertEqual(
            [observation.coverage.value for observation in observations],
            ["full", "full", "partial", "partial", "full", "full", "full"],
        )
        self.assertEqual(
            len(
                [
                    event
                    for event in analysis.events
                    if event.kind == "server_opcode_49_received"
                ]
            ),
            7,
        )
        safe = str(analysis.safe_dict())
        self.assertNotIn("sensitive", safe)
        self.assertIn(
            "server_opcode_49=packets:7 variants:",
            render_gameplay_analysis(analysis),
        )

    def test_folds_tutorial_ui_instructions_without_exposing_text(
        self,
    ) -> None:
        instructions = (
            TutorialUiInstruction(
                text="$SCRIPTSTRING_TUTORIAL_0$",
                value_1=150,
                value_2=5,
                control_value=1,
            ),
            TutorialUiInstruction(
                text="$SCRIPTSTRING_TUTORIAL_10$",
                value_1=100,
                value_2=5,
                control_value=0,
                extended_values=(7, 8),
            ),
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=tuple(
                instruction.to_bytes() for instruction in instructions
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.tutorial_ui_instructions, 2)
        self.assertEqual(
            analysis.state.tutorial_ui_text_code_units,
            {25: 1, 26: 1},
        )
        self.assertEqual(analysis.state.tutorial_ui_value_1, {150: 1, 100: 1})
        self.assertEqual(analysis.state.tutorial_ui_value_2, {5: 2})
        self.assertEqual(analysis.state.tutorial_ui_control_values, {1: 1, 0: 1})
        self.assertEqual(analysis.state.tutorial_ui_extended_instructions, 1)
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "tutorial_ui_instruction"
        ]
        self.assertEqual(
            [observation.coverage.value for observation in observations],
            ["full", "full"],
        )
        self.assertEqual(
            len(
                [
                    event
                    for event in analysis.events
                    if event.kind == "tutorial_ui_instruction_received"
                ]
            ),
            2,
        )
        self.assertNotIn("SCRIPTSTRING", str(analysis.safe_dict()))
        self.assertIn(
            "tutorial_ui_instructions=packets:2",
            render_gameplay_analysis(analysis),
        )

    def test_folds_server_opcode_244_dialogue_instructions(self) -> None:
        records = (
            ServerOpcode244DialogueInstruction(
                value_1=1036,
                value_2=2003,
                value_3=0,
            ),
            ServerOpcode244DialogueInstruction(
                value_1=1032,
                value_2=2001,
                value_3=1033,
            ),
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=tuple(record.to_bytes() for record in records),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.instructional_dialogue_requests, 2)
        self.assertEqual(
            analysis.state.instructional_dialogue_value_1,
            {1036: 1, 1032: 1},
        )
        self.assertEqual(
            analysis.state.instructional_dialogue_value_2,
            {2003: 1, 2001: 1},
        )
        self.assertEqual(
            analysis.state.instructional_dialogue_value_3,
            {0: 1, 1033: 1},
        )
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "server_opcode_244_dialogue_instruction"
        ]
        self.assertEqual(len(observations), 2)
        self.assertTrue(
            all(
                observation.coverage.value == "full"
                for observation in observations
            )
        )
        self.assertEqual(
            len(
                [
                    event
                    for event in analysis.events
                    if event.kind
                    == "instructional_dialogue_requested"
                ]
            ),
            2,
        )
        self.assertIn(
            "instructional_dialogue_requests=packets:2",
            render_gameplay_analysis(analysis),
        )

    def test_folds_server_opcode_239_envelope_variants(self) -> None:
        records = (
            ServerOpcode239Envelope(selector=9),
            ServerOpcode239Envelope(selector=13),
            ServerOpcode239Envelope(
                selector=3,
                records=(
                    ServerOpcode239ValueRecord(key=2_345_678, value=5),
                    ServerOpcode239ValueRecord(key=2_345_679, value=5),
                    ServerOpcode239ValueRecord(key=4_123_456, value=-1),
                ),
            ),
            ServerOpcode239Envelope(
                selector=21,
                text="UI/tutorial/28",
                trailing_value=1,
            ),
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=tuple(record.to_bytes() for record in records),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.server_opcode_239_packets, 4)
        self.assertEqual(
            analysis.state.server_opcode_239_selectors,
            {3: 1, 9: 1, 13: 1, 21: 1},
        )
        self.assertEqual(analysis.state.server_opcode_239_records, 3)
        self.assertEqual(
            analysis.state.server_opcode_239_record_values,
            {5: 2, -1: 1},
        )
        self.assertEqual(
            analysis.state.server_opcode_239_text_code_units,
            {14: 1},
        )
        self.assertEqual(
            analysis.state.server_opcode_239_trailing_values,
            {1: 1},
        )
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "server_opcode_239_envelope"
        ]
        self.assertEqual(len(observations), 4)
        self.assertTrue(
            all(
                observation.coverage.value == "full"
                for observation in observations
            )
        )
        self.assertEqual(
            sum(
                event.kind == "server_opcode_239_received"
                for event in analysis.events
            ),
            4,
        )
        safe = str(analysis.safe_dict())
        self.assertNotIn("UI/tutorial/28", safe)
        self.assertNotIn("2345678", safe)
        self.assertIn(
            "server_opcode_239=packets:4 selectors:{3: 1, 9: 1, 13: 1, 21: 1}",
            render_gameplay_analysis(analysis),
        )

    def test_folds_client_opcode_43_neutral_envelopes(self) -> None:
        envelopes = (
            ClientOpcode43Envelope(
                sequence=4,
                opaque_compact_body=bytes(range(9)),
            ),
            ClientOpcode43Envelope(
                sequence=35,
                opaque_identifier=3_456_789,
                opaque_text="sensitive-label",
                opaque_tail=b"ABCDEF",
            ),
        )
        server = ServerOpcode43Envelope(
            message_type=0,
            opaque_body=bytes(range(16)),
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=(server.to_bytes(),),
            extra_client_plaintexts=tuple(
                envelope.to_bytes() for envelope in envelopes
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.client_opcode_43_packets, 2)
        self.assertEqual(analysis.state.client_opcode_43_sequences, {4: 1, 35: 1})
        self.assertEqual(
            analysis.state.client_opcode_43_variants,
            {"compact": 1, "identified_text": 1},
        )
        self.assertEqual(
            analysis.state.client_opcode_43_text_code_units,
            {0: 1, 15: 1},
        )
        self.assertEqual(analysis.state.client_opcode_43_opaque_bytes, 15)
        self.assertEqual(analysis.state.server_opcode_43_packets, 1)
        self.assertEqual(analysis.state.server_opcode_43_message_types, {0: 1})
        self.assertEqual(analysis.state.server_opcode_43_opaque_bytes, 16)
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "client_opcode_43_envelope"
        ]
        self.assertEqual(len(observations), 2)
        self.assertTrue(
            all(
                observation.coverage.value == "partial"
                for observation in observations
            )
        )
        self.assertEqual(
            sum(
                event.kind == "client_opcode_43_submitted"
                for event in analysis.events
            ),
            2,
        )
        server_observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "server_opcode_43_envelope"
        ]
        self.assertEqual(len(server_observations), 1)
        self.assertEqual(server_observations[0].coverage.value, "partial")
        self.assertEqual(
            sum(
                event.kind == "server_opcode_43_received"
                for event in analysis.events
            ),
            1,
        )
        safe = str(analysis.safe_dict())
        self.assertNotIn("3456789", safe)
        self.assertNotIn("sensitive-label", safe)
        self.assertNotIn(bytes(range(16)).hex(), safe)
        self.assertIn(
            "client_opcode_43=packets:2 sequences:{4: 1, 35: 1}",
            render_gameplay_analysis(analysis),
        )
        self.assertIn(
            "server_opcode_43=packets:1 message_types:{0: 1} opaque_bytes:16",
            render_gameplay_analysis(analysis),
        )

    def test_folds_client_opcode_114_redacted_text_envelopes(self) -> None:
        envelopes = (
            ClientOpcode114TextEnvelope(
                control_value=1,
                opaque_text="hidden-one",
                opaque_value=3_456_789,
            ),
            ClientOpcode114TextEnvelope(
                control_value=32,
                opaque_text="secret02",
                opaque_value=4_567_890,
            ),
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_client_plaintexts=tuple(
                envelope.to_bytes() for envelope in envelopes
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.client_opcode_114_packets, 2)
        self.assertEqual(
            analysis.state.client_opcode_114_control_values,
            {1: 1, 32: 1},
        )
        self.assertEqual(
            analysis.state.client_opcode_114_text_code_units,
            {10: 1, 8: 1},
        )
        self.assertEqual(analysis.state.client_opcode_114_redacted_values, 2)
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "client_opcode_114_text_envelope"
        ]
        self.assertEqual(len(observations), 2)
        self.assertTrue(
            all(
                observation.coverage.value == "partial"
                for observation in observations
            )
        )
        self.assertEqual(
            sum(
                event.kind == "client_opcode_114_submitted"
                for event in analysis.events
            ),
            2,
        )
        safe = str(analysis.safe_dict())
        self.assertNotIn("hidden-one", safe)
        self.assertNotIn("secret02", safe)
        self.assertNotIn("3456789", safe)
        self.assertNotIn("4567890", safe)
        self.assertIn(
            "client_opcode_114=packets:2 control_values:{1: 1, 32: 1}",
            render_gameplay_analysis(analysis),
        )

    def test_folds_client_opcode_122_captured_variants(self) -> None:
        records = (
            ClientOpcode122Envelope(
                selector=1,
                opaque_values=(2_132, 1_032_001),
            ),
            ClientOpcode122Envelope(
                selector=1,
                opaque_values=(1_031, 2_101, 0x01E5_FF43),
            ),
            ClientOpcode122Envelope(
                selector=2,
                opaque_values=(2_132, 1_032_001, 0xFFFF_FFFF),
            ),
            ClientOpcode122Envelope(
                selector=2,
                opaque_values=(1_031, 2_100, 0x016D_038B, 0xFFFF_FFFF),
            ),
            ClientOpcode122Envelope(
                selector=4,
                opaque_values=(1_048, 9_010_000, 0xFFE7_00A5),
            ),
            ClientOpcode122Envelope(
                selector=5,
                opaque_values=(29_900, 9_000_040, 0xF4F7_FD1D),
            ),
        )
        unsupported = struct.pack("<HB3I", 122, 3, 1, 2, 3)
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_client_plaintexts=(
                *(record.to_bytes() for record in records),
                unsupported,
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.client_opcode_122_packets, 6)
        self.assertEqual(
            analysis.state.client_opcode_122_selectors,
            {1: 2, 2: 2, 4: 1, 5: 1},
        )
        self.assertEqual(
            analysis.state.client_opcode_122_shapes,
            {
                "selector=1:values=2": 1,
                "selector=1:values=3": 1,
                "selector=2:values=3": 1,
                "selector=2:values=4": 1,
                "selector=4:values=3": 1,
                "selector=5:values=3": 1,
            },
        )
        self.assertEqual(
            analysis.state.client_opcode_122_terminal_sentinels, 2
        )
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "client_opcode_122_envelope"
        ]
        self.assertEqual(len(observations), 6)
        self.assertTrue(
            all(
                observation.coverage.value == "full"
                for observation in observations
            )
        )
        self.assertEqual(
            sum(
                event.kind == "client_opcode_122_submitted"
                for event in analysis.events
            ),
            6,
        )
        self.assertEqual(
            sum(
                observation.kind == "client_opcode_122"
                and observation.coverage.value == "unknown"
                for observation in analysis.observations
            ),
            1,
        )
        safe = str([observation.details for observation in observations])
        self.assertNotIn("9010000", safe)
        self.assertNotIn("4294967295", safe)
        self.assertIn(
            "client_opcode_122=packets:6 selectors:{1: 2, 2: 2, 4: 1, 5: 1}",
            render_gameplay_analysis(analysis),
        )

    def test_folds_server_opcode_348_text_envelope_variants(self) -> None:
        envelopes = (
            ServerOpcode348TextEnvelope(
                category=4,
                primary_value=3_456_789,
                selector=0,
                value=0,
                text="redacted-extended",
                control_1=0,
                control_2=1,
            ),
            ServerOpcode348TextEnvelope(
                category=4,
                primary_value=3_456_790,
                selector=0,
                value=0,
                text="redacted-second",
                control_1=0,
                control_2=0,
            ),
            ServerOpcode348TextEnvelope(
                category=4,
                primary_value=3_456_791,
                selector=3,
                value=0,
                text="simple-3",
            ),
            ServerOpcode348TextEnvelope(
                category=4,
                primary_value=3_456_792,
                selector=6,
                value=0,
                text="simple-6",
            ),
            ServerOpcode348TextEnvelope(
                category=4,
                primary_value=3_456_793,
                selector=17,
                value=0,
                text="simple-17",
            ),
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=tuple(
                envelope.to_bytes() for envelope in envelopes
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.server_opcode_348_packets, 5)
        self.assertEqual(analysis.state.server_opcode_348_categories, {4: 5})
        self.assertEqual(
            analysis.state.server_opcode_348_selectors,
            {0: 2, 3: 1, 6: 1, 17: 1},
        )
        self.assertEqual(analysis.state.server_opcode_348_values, {0: 5})
        self.assertEqual(
            analysis.state.server_opcode_348_control_pairs,
            {"0:1": 1, "0:0": 1},
        )
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "server_opcode_348_text_envelope"
        ]
        self.assertEqual(len(observations), 5)
        self.assertTrue(
            all(
                observation.coverage.value == "full"
                for observation in observations
            )
        )
        self.assertEqual(
            sum(
                event.kind == "server_opcode_348_received"
                for event in analysis.events
            ),
            5,
        )
        safe = str(analysis.safe_dict())
        self.assertNotIn("redacted-extended", safe)
        self.assertNotIn("3456789", safe)
        self.assertIn(
            "server_opcode_348=packets:5 categories:{4: 5} "
            "selectors:{0: 2, 3: 1, 6: 1, 17: 1}",
            render_gameplay_analysis(analysis),
        )

    def test_folds_positioned_effect_records(self) -> None:
        records = (
            ServerOpcode322PositionedEffectRecord(
                primary_value=12_597,
                numeric_value=2000,
                control_value=0,
                x=2609,
                y=-372,
                trailing_value=0,
            ),
            ServerOpcode320PositionedEffectRecord(
                primary_value=12_597,
                control_value=1,
                x=2600,
                y=-370,
                numeric_value=305,
                secondary_control_value=0,
                trailing_value=5,
            ),
            ServerOpcode323PositionedEffectRecord(
                primary_value=12_597,
                control_value=2,
                x=2590,
                y=-368,
            ),
            ServerOpcode323PositionedEffectRecord(
                primary_value=99_999,
                control_value=3,
                x=10,
                y=20,
            ),
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=tuple(record.to_bytes() for record in records),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.positioned_effect_records, 4)
        self.assertEqual(
            analysis.state.positioned_effect_records_by_opcode,
            {322: 1, 320: 1, 323: 2},
        )
        self.assertEqual(analysis.state.positioned_effect_new_entities, 2)
        self.assertEqual(analysis.state.positioned_effect_updates, 2)
        self.assertEqual(analysis.state.positioned_effect_unknown_updates, 1)
        self.assertEqual(len(analysis.state.positioned_effect_entities), 2)
        entity = analysis.state.positioned_effect_entities[12_597]
        self.assertEqual((entity.x, entity.y, entity.last_opcode), (2590, -368, 323))
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "positioned_effect_record"
        ]
        self.assertEqual(len(observations), 4)
        self.assertTrue(
            all(observation.coverage.value == "full" for observation in observations)
        )
        self.assertEqual(
            len(
                [
                    event
                    for event in analysis.events
                    if event.kind == "positioned_effect_observed"
                ]
            ),
            4,
        )
        safe = analysis.safe_dict()
        self.assertNotIn("12597", str(safe))
        self.assertEqual(
            safe["state"]["positioned_effect_entities"][0]["entity"],
            "effect:1",
        )
        self.assertIn(
            "positioned_effect_records=packets:4",
            render_gameplay_analysis(analysis),
        )

    def test_folds_neutral_server_records_with_bounded_opaque_tails(
        self,
    ) -> None:
        records = (
            ServerOpcode69Record(
                header_value=7,
                opaque_tail=b"\x00" * ServerOpcode69Record.OPAQUE_TAIL_LENGTH,
            ),
            ServerOpcode93Record(
                values=(9_000_017, 2_041_017, 1_022_101, 9_000_021)
            ),
            ServerOpcode94Record(
                flag=True,
                primary_value=2_380_000,
                secondary_value=2,
            ),
            ServerOpcode201Record(
                primary_value=302_104,
                secondary_value=0,
                flag_a=1,
                flag_b=1,
                opaque_tail=b"\x00" * ServerOpcode201Record.OPAQUE_TAIL_LENGTH,
            ),
            ServerOpcode205Record(
                primary_value=302_104,
                secondary_value=0,
                numeric_value=1_386_640,
                trailing_value=0,
            ),
            ServerOpcode379Record(variant=35),
            ServerOpcode379Record(
                variant=36,
                time_values=(
                    150_842_304_000_000_000,
                    150_842_304_000_000_000,
                    94_354_848_000_000_000,
                    94_354_848_000_000_000,
                ),
            ),
            ServerOpcode148Envelope(variant=9, record_count=0),
            ServerOpcode148Envelope(variant=10),
            ServerOpcode148Envelope(
                variant=12, primary_value=4, secondary_value=5
            ),
            ServerOpcode148Envelope(
                variant=13, primary_value=3, secondary_value=24
            ),
            ServerOpcode148Envelope(
                variant=9,
                record_count=12,
                records_blob=b"\xa5" * 1_632,
            ),
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=tuple(record.to_bytes() for record in records),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.neutral_server_records, 12)
        self.assertEqual(
            analysis.state.neutral_server_records_by_opcode,
            {69: 1, 93: 1, 94: 1, 148: 5, 201: 1, 205: 1, 379: 2},
        )
        self.assertEqual(analysis.state.neutral_server_typed_values, 33)
        self.assertEqual(analysis.state.neutral_server_opaque_bytes, 1_917)
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "neutral_server_record"
        ]
        self.assertEqual(
            [observation.coverage.value for observation in observations],
            [
                "partial",
                "full",
                "full",
                "partial",
                "full",
                "full",
                "full",
                "full",
                "full",
                "full",
                "full",
                "partial",
            ],
        )
        self.assertEqual(
            len(
                [
                    event
                    for event in analysis.events
                    if event.kind == "neutral_server_record_received"
                ]
            ),
            12,
        )
        self.assertNotIn("302104", str(analysis.safe_dict()))
        self.assertIn(
            "neutral_server_records=packets:12 opcodes:",
            render_gameplay_analysis(analysis),
        )

    def test_folds_keyboard_skill_binding_reload_sequence(self) -> None:
        original = fixture_variable_server_records()[2]
        entries = list(original.entries)
        entries[29] = replace(entries[29], value=2_001_004)
        rebound = replace(original, entries=tuple(entries))
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=(
                original.to_bytes(),
                rebound.to_bytes(),
                original.to_bytes(),
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        loaded = [
            event
            for event in analysis.events
            if event.kind == "keyboard_bindings_loaded"
        ]
        self.assertEqual(
            [event.details["left_ctrl_skill_id"] for event in loaded],
            [2_001_005, 2_001_004, 2_001_005],
        )
        self.assertEqual(
            [event.details["left_ctrl_skill_known"] for event in loaded],
            [True, False, True],
        )
        self.assertEqual(analysis.state.keyboard_binding_snapshots, 3)
        self.assertEqual(analysis.state.left_ctrl_skill_id, 2_001_005)
        self.assertTrue(analysis.state.left_ctrl_skill_known)

    def test_plans_typed_post_transcript_hp_stat_update(self) -> None:
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            stat_updates=True,
        )
        plan = plan_current_hp_stat_update(transcript, 1)

        self.assertEqual(plan.original_current_hp, 77)
        self.assertEqual(plan.emitted_current_hp, 1)
        self.assertEqual(plan.max_hp, 222)
        self.assertEqual(plan.field_epoch, 1)
        self.assertEqual(
            plan.update,
            CharacterStatUpdate(
                request_flag=0,
                stat_mask=CharacterStatUpdate.CURRENT_HP,
                current_hp=1,
            ),
        )
        self.assertEqual(plan.safe_dict()["prediction"]["current_hp"], 1)
        with self.assertRaisesRegex(ValueError, "between 0 and 222"):
            plan_current_hp_stat_update(transcript, 223)

    def test_plans_typed_inventory_quantity_update(self) -> None:
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            inventory_changes=True,
        )
        plan = plan_inventory_quantity_update(transcript, "use", 1, 1)

        self.assertEqual(plan.inventory, "use")
        self.assertEqual(plan.slot, 1)
        self.assertEqual(plan.item_id, 2_000_000)
        self.assertEqual(plan.original_quantity, 5)
        self.assertEqual(plan.emitted_quantity, 1)
        self.assertEqual(
            InventoryChangeSet.parse(plan.update.to_bytes()), plan.update
        )
        self.assertEqual(
            plan.safe_dict()["prediction"]["inventory_item_count_delta"], 0
        )
        with self.assertRaisesRegex(ValueError, "no slot 2"):
            plan_inventory_quantity_update(transcript, "use", 2, 1)
        with self.assertRaisesRegex(ValueError, "between 1 and 65535"):
            plan_inventory_quantity_update(transcript, "use", 1, 0)

    def test_folds_initial_snapshot_character_prefix_into_player_state(self) -> None:
        analysis = analyze_gameplay_transcript(
            fixture_gameplay_transcript(initial_snapshot=True)
        )

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.state.initial_field_snapshots, 1)
        self.assertEqual(analysis.state.character_level, 12)
        self.assertEqual(analysis.state.job_id, 200)
        self.assertEqual(analysis.state.map_id, 101_000_000)
        self.assertEqual(analysis.state.portal_index, 1)
        self.assertEqual(analysis.state.current_hp, 70)
        self.assertEqual(analysis.state.max_hp, 222)
        self.assertEqual(analysis.state.current_mp, 136)
        self.assertEqual(analysis.state.max_mp, 342)
        observation = next(
            item
            for item in analysis.observations
            if item.kind == "initial_field_snapshot"
        )
        self.assertEqual(observation.coverage.value, "partial")
        self.assertEqual(
            observation.details["variant"], "initial_character_snapshot"
        )
        self.assertEqual(observation.details["character_name_code_units"], 6)
        self.assertEqual(observation.details["map_id"], 101_000_000)
        self.assertEqual(observation.details["inventory_item_counts"]["use"], 1)
        self.assertEqual(analysis.state.inventory_items["use"][0].quantity, 3)
        self.assertEqual(analysis.state.skill_levels, {2_001_002: 1, 2_001_005: 6})
        self.assertEqual(analysis.state.progression_variant, 1)
        self.assertEqual(analysis.state.progression_shape, "keyed_properties")
        self.assertEqual(
            analysis.state.server_local_filetime_ticks,
            134_306_812_493_680_000,
        )
        self.assertIn("partially opaque", observation.issues[0])
        self.assertNotIn('"name": "player"', analysis.to_json())

    def test_folds_compact_initial_progression_into_player_state(self) -> None:
        snapshot = fixture_compact_initial_field_snapshot()
        analysis = analyze_gameplay_transcript(
            fixture_gameplay_transcript(
                initial_snapshot_payload=snapshot.to_bytes()
            )
        )

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.state.initial_field_snapshots, 1)
        self.assertEqual(analysis.state.progression_shape, "compact")
        self.assertEqual(analysis.state.progression_variant, None)
        self.assertEqual(analysis.state.skill_levels, {12: 0})
        self.assertEqual(analysis.state.extended_property_code_units, {})
        self.assertEqual(
            analysis.safe_dict()["state"]["progression"]["shape"],
            "compact",
        )
        observation = next(
            item
            for item in analysis.observations
            if item.kind == "initial_field_snapshot"
        )
        self.assertEqual(observation.coverage.value, "partial")
        self.assertEqual(observation.details["progression_shape"], "compact")
        self.assertEqual(
            observation.details["compact_variant_header_hex"], "00" * 7
        )
        self.assertIn("partially opaque", observation.issues[0])

    def test_folds_skill_record_request_update_acknowledgement_lifecycle(
        self,
    ) -> None:
        analysis = analyze_gameplay_transcript(
            fixture_gameplay_transcript(
                initial_snapshot=True,
                skill_record_lifecycle=True,
            )
        )

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.warnings, ())
        self.assertEqual(analysis.state.skill_levels[2_001_005], 7)
        self.assertEqual(analysis.state.skill_level_change_requests, 1)
        self.assertEqual(analysis.state.skill_record_updates, 2)
        self.assertEqual(analysis.state.skill_record_update_records, 1)
        self.assertEqual(analysis.state.skill_record_request_matches, 1)
        self.assertEqual(analysis.state.skill_record_request_mismatches, 0)
        self.assertEqual(analysis.state.skill_record_updates_without_request, 0)
        self.assertEqual(analysis.state.pending_skill_level_change_requests, 0)
        self.assertEqual(
            analysis.state.skill_record_update_acknowledgements, 2
        )
        self.assertEqual(
            analysis.state.matched_skill_record_update_acknowledgements, 2
        )
        self.assertEqual(
            analysis.state.unmatched_skill_record_update_acknowledgements, 0
        )
        self.assertEqual(
            analysis.state.pending_skill_record_update_acknowledgements, 0
        )
        self.assertEqual(
            analysis.state.skill_record_updates_by_flags,
            {"1:0": 1, "0:0": 1},
        )
        self.assertEqual(
            analysis.state.skill_record_acknowledgement_control_values,
            {346: 2},
        )
        kinds = [event.kind for event in analysis.events]
        self.assertEqual(kinds.count("skill_level_change_requested"), 1)
        self.assertEqual(kinds.count("skill_records_updated"), 2)
        self.assertEqual(kinds.count("skill_record_update_acknowledged"), 2)
        progression = analysis.safe_dict()["state"]["progression"]
        self.assertEqual(
            progression["skill_record_updates"]["request_matches"], 1
        )
        observations = {
            item.kind: item
            for item in analysis.observations
            if item.kind
            in {
                "skill_level_change_request",
                "skill_record_update",
                "skill_record_update_acknowledgement",
            }
        }
        self.assertTrue(
            all(
                observation.coverage.value == "full"
                for observation in observations.values()
            )
        )

    def test_folds_remote_player_entry_refresh_and_leave_lifecycle(
        self,
    ) -> None:
        player_a = RemotePlayerEnterField(
            object_id=987_654_321,
            level=12,
            name="CaptureName",
            opaque_body=b"\xaa\xbb",
        )
        player_b = RemotePlayerEnterField(
            object_id=123_456_789,
            level=9,
            name="Other",
            opaque_body=b"\xcc",
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=(
                player_a.to_bytes(),
                replace(player_a, level=13, opaque_body=b"\xdd").to_bytes(),
                player_b.to_bytes(),
                RemotePlayerLeaveField(
                    object_id=player_a.object_id
                ).to_bytes(),
                RemotePlayerLeaveField(object_id=777_777_777).to_bytes(),
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.remote_player_entries, 3)
        self.assertEqual(analysis.state.remote_player_refreshes, 1)
        self.assertEqual(analysis.state.remote_player_entry_opaque_bytes, 4)
        self.assertEqual(analysis.state.remote_player_leaves, 2)
        self.assertEqual(analysis.state.remote_player_unknown_leaves, 1)
        self.assertEqual(list(analysis.state.observed_players), [player_b.object_id])
        remaining = analysis.state.observed_players[player_b.object_id]
        self.assertEqual(remaining.level, 9)
        self.assertEqual(remaining.name_code_units, 5)
        self.assertIsNone(remaining.x)
        self.assertIsNone(remaining.y)
        lifecycle = [
            observation
            for observation in analysis.observations
            if observation.kind
            in {"remote_player_enter_field", "remote_player_leave_field"}
        ]
        self.assertEqual(
            [observation.coverage.value for observation in lifecycle],
            ["partial", "partial", "partial", "full", "full"],
        )
        safe = analysis.safe_dict()
        self.assertNotIn("987654321", str(safe))
        self.assertNotIn("CaptureName", str(safe))
        self.assertEqual(safe["state"]["observed_remote_player_count"], 1)
        event_kinds = [event.kind for event in analysis.events]
        self.assertEqual(event_kinds.count("remote_player_entered_field"), 3)
        self.assertEqual(event_kinds.count("remote_player_left_field"), 2)

    def test_folds_mob_temporary_stat_set_reset_lifecycle(self) -> None:
        relay = ServerAttackRelay(
            object_id=PLAYER_OBJECT_ID,
            packed_counts=0x11,
            opaque_body=fixture_attack_relay_body(
                prefix_length=15,
                target_count=1,
                hit_count=1,
                tail_length=4,
            ),
            opcode=219,
        )
        first_set = MobTemporaryStatSet(
            object_id=MOB_OBJECT_ID,
            value=1,
            source_skill_id=4_001_344,
            source_level=8,
            duration_value=1_000,
        )
        refreshed_set = replace(first_set, duration_value=900)
        reset = MobTemporaryStatReset(object_id=MOB_OBJECT_ID)
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=(
                relay.to_bytes(),
                first_set.to_bytes(),
                refreshed_set.to_bytes(),
                reset.to_bytes(),
                reset.to_bytes(),
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        state = analysis.state
        self.assertEqual(state.mob_temporary_stat_sets, 2)
        self.assertEqual(state.mob_temporary_stat_resets, 2)
        self.assertEqual(state.mob_temporary_stat_sets_for_known_mobs, 2)
        self.assertEqual(state.mob_temporary_stat_sets_for_unknown_mobs, 0)
        self.assertEqual(state.mob_temporary_stat_resets_for_known_mobs, 2)
        self.assertEqual(state.mob_temporary_stat_resets_for_unknown_mobs, 0)
        self.assertEqual(state.mob_temporary_stat_set_refreshes, 1)
        self.assertEqual(state.mob_temporary_stat_resets_with_modeled_set, 1)
        self.assertEqual(
            state.mob_temporary_stat_resets_without_modeled_set, 1
        )
        self.assertEqual(state.mob_temporary_stat_attack_relay_matches, 2)
        self.assertEqual(
            state.mob_temporary_stat_mask_patterns,
            {"00000000:00000000:00000000:00000080": 4},
        )
        self.assertEqual(state.mob_temporary_stat_source_skills, {4_001_344: 2})
        self.assertEqual(state.mob_temporary_stat_source_levels, {8: 2})
        self.assertEqual(
            state.mob_temporary_stat_duration_values,
            {900: 1, 1_000: 1},
        )
        self.assertFalse(state.mobs[MOB_OBJECT_ID].temporary_stats)
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind
            in {"mob_temporary_stat_set", "mob_temporary_stat_reset"}
        ]
        self.assertEqual(len(observations), 4)
        self.assertTrue(
            all(
                observation.coverage.value == "full"
                for observation in observations
            )
        )
        self.assertEqual(
            sum(
                event.kind == "mob_temporary_stat_set_received"
                for event in analysis.events
            ),
            2,
        )
        safe = str([observation.details for observation in observations])
        self.assertNotIn(str(MOB_OBJECT_ID), safe)
        self.assertIn(
            "mob_temporary_stats=active:0 sets:2 resets:2",
            render_gameplay_analysis(analysis),
        )

    def test_folds_remote_player_mob_value_records(self) -> None:
        player = RemotePlayerEnterField(
            object_id=987_654_321,
            level=12,
            name="CaptureName",
            opaque_body=b"\xaa",
        )
        records = (
            RemotePlayerMobValueRecord(
                object_id=player.object_id,
                value=11,
                mob_template_id=210_100,
                flag=0,
                repeated_value=11,
            ),
            RemotePlayerMobValueRecord(
                object_id=777_777_777,
                value=10,
                mob_template_id=210_100,
                flag=1,
                repeated_value=10,
            ),
            RemotePlayerMobValueRecord(
                object_id=player.object_id,
                value=1,
                mob_template_id=999_999,
                flag=0,
                repeated_value=1,
            ),
        )
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            extra_server_plaintexts=(
                player.to_bytes(),
                *(record.to_bytes() for record in records),
            ),
        )

        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.remote_player_mob_value_records, 3)
        self.assertEqual(
            analysis.state.remote_player_mob_values_for_known_players, 2
        )
        self.assertEqual(
            analysis.state.remote_player_mob_values_for_unknown_players, 1
        )
        self.assertEqual(
            analysis.state.remote_player_mob_values_with_active_template, 2
        )
        self.assertEqual(
            analysis.state.remote_player_mob_values_with_inactive_template, 1
        )
        self.assertEqual(
            analysis.state.remote_player_mob_values,
            {1: 1, 10: 1, 11: 1},
        )
        self.assertEqual(
            analysis.state.remote_player_mob_templates,
            {210_100: 2, 999_999: 1},
        )
        self.assertEqual(
            analysis.state.remote_player_mob_value_flags,
            {0: 2, 1: 1},
        )
        observations = [
            observation
            for observation in analysis.observations
            if observation.kind == "remote_player_mob_value_record"
        ]
        self.assertEqual(len(observations), 3)
        self.assertTrue(
            all(
                observation.coverage.value == "full"
                for observation in observations
            )
        )
        self.assertEqual(
            sum(
                event.kind == "remote_player_mob_value_received"
                for event in analysis.events
            ),
            3,
        )
        safe = str([observation.details for observation in observations])
        self.assertNotIn("987654321", safe)
        self.assertNotIn("777777777", safe)
        self.assertIn(
            "remote_player_mob_values=packets:3 known_players:2 "
            "unknown_players:1 active_templates:2 inactive_templates:1",
            render_gameplay_analysis(analysis),
        )

    def test_remote_player_attack_before_first_movement_has_no_position(
        self,
    ) -> None:
        entered_payload = RemotePlayerEnterField(
            object_id=PLAYER_OBJECT_ID,
            level=12,
            name="Player",
            opaque_body=b"\x00",
        ).to_bytes()
        relay_payload = ServerAttackRelay(
            opcode=219,
            object_id=PLAYER_OBJECT_ID,
            packed_counts=0x12,
            opaque_body=fixture_attack_relay_body(
                prefix_length=15,
                target_count=1,
                hit_count=2,
                tail_length=4,
            ),
        ).to_bytes()
        fold = GameplayStateFold()
        frames = (
            PlainFrame(
                index=0,
                direction_index=0,
                timestamp_ns=1_000_000_000,
                direction="server_to_client",
                wire_offset=0,
                wire_length=len(entered_payload),
                plaintext=entered_payload,
            ),
            PlainFrame(
                index=1,
                direction_index=1,
                timestamp_ns=1_010_000_000,
                direction="server_to_client",
                wire_offset=len(entered_payload),
                wire_length=len(relay_payload),
                plaintext=relay_payload,
            ),
        )

        observations = tuple(fold.consume(frame) for frame in frames)

        self.assertEqual(fold.state.server_attack_relays_for_known_players, 1)
        self.assertEqual(
            fold.state.server_ranged_attack_positions_for_known_players,
            0,
        )
        self.assertIsNone(fold.state.observed_players[PLAYER_OBJECT_ID].x)
        self.assertNotIn("actor_position_x", observations[-1].details)

    def test_folds_player_movement_into_local_and_remote_state(self) -> None:
        analysis = analyze_gameplay_transcript(
            fixture_gameplay_transcript(player_movement=True)
        )

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.state.player_x, 132)
        self.assertEqual(analysis.state.player_y, -168)
        self.assertEqual(analysis.state.player_movement_submissions, 1)
        self.assertEqual(analysis.state.player_movement_commands, 5)
        self.assertEqual(
            analysis.state.player_movement_commands_by_type,
            {0: 2, 1: 1, 3: 1, 5: 1},
        )
        self.assertEqual(analysis.state.remote_player_movement_broadcasts, 1)
        self.assertEqual(
            analysis.state.remote_player_movement_broadcasts_for_known_players,
            0,
        )
        self.assertEqual(
            analysis.state.remote_player_movement_broadcasts_for_unknown_players,
            1,
        )
        self.assertEqual(analysis.state.remote_player_movement_commands, 5)
        self.assertEqual(
            analysis.state.remote_player_movement_commands_by_type,
            {0: 2, 1: 1, 3: 1, 5: 1},
        )
        self.assertEqual(analysis.state.life_movement_submissions, 1)
        self.assertEqual(analysis.state.life_movement_submission_commands, 5)
        self.assertEqual(
            analysis.state.life_movement_submission_commands_by_type,
            {0: 1, 2: 1, 10: 1, 14: 1, 15: 1},
        )
        self.assertEqual(analysis.state.life_movement_tail_types, {17: 1})
        self.assertEqual(analysis.state.life_movement_tail_markers, {4: 1})
        self.assertEqual(analysis.state.life_movement_broadcasts, 1)
        self.assertEqual(analysis.state.life_movement_broadcast_commands, 5)
        self.assertEqual(
            analysis.state.life_movement_broadcast_commands_by_type,
            {0: 1, 2: 1, 10: 1, 14: 1, 15: 1},
        )
        self.assertEqual(
            analysis.state.life_movement_broadcasts_for_known_players, 1
        )
        self.assertEqual(
            analysis.state.life_movement_broadcasts_for_unknown_players, 0
        )
        self.assertEqual(
            (
                analysis.state.observed_players[PLAYER_OBJECT_ID].x,
                analysis.state.observed_players[PLAYER_OBJECT_ID].y,
            ),
            (130, -170),
        )
        event_kinds = [event.kind for event in analysis.events]
        self.assertIn("player_movement_submitted", event_kinds)
        self.assertIn("remote_player_movement_broadcast", event_kinds)
        self.assertIn("life_movement_submitted", event_kinds)
        self.assertIn("life_movement_broadcast_received", event_kinds)
        life_submission_event = next(
            event
            for event in analysis.events
            if event.kind == "life_movement_submitted"
        )
        self.assertNotIn("client_token", life_submission_event.details)
        self.assertTrue(life_submission_event.details["client_token_present"])
        report = analysis.safe_dict()
        self.assertEqual(report["state"]["player"]["x"], 132)
        self.assertEqual(report["state"]["observed_remote_player_count"], 1)
        self.assertNotIn(
            "object_id", report["state"]["observed_remote_players"][0]
        )

    def test_folds_character_stat_updates_into_player_state(self) -> None:
        analysis = analyze_gameplay_transcript(
            fixture_gameplay_transcript(stat_updates=True)
        )

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.state.current_hp, 77)
        self.assertEqual(analysis.state.experience, 2_000)
        self.assertEqual(analysis.state.mesos, 9_001)
        self.assertEqual(analysis.state.player_stat_updates, 2)
        self.assertEqual(
            analysis.state.player_stat_updates_by_mask,
            {
                CharacterStatUpdate.CURRENT_HP
                | CharacterStatUpdate.EXPERIENCE: 1,
                CharacterStatUpdate.MESOS: 1,
            },
        )
        self.assertEqual(
            analysis.state.player_stat_fields_updated,
            {"current_hp": 1, "experience": 1, "mesos": 1},
        )
        self.assertEqual(analysis.state.player_stat_request_flags, {0: 1, 1: 1})
        events = [
            event for event in analysis.events if event.kind == "player_stats_updated"
        ]
        self.assertEqual(len(events), 2)
        self.assertEqual(
            events[0].details["changes"]["current_hp"],
            {"previous": None, "current": 77},
        )
        report = analysis.safe_dict()
        self.assertEqual(report["state"]["player"]["mesos"], 9_001)
        self.assertEqual(
            report["state"]["player_stat_updates_by_mask"],
            {"0x00010400": 1, "0x00040000": 1},
        )

    def test_folds_inventory_changes_into_item_state(self) -> None:
        analysis = analyze_gameplay_transcript(
            fixture_gameplay_transcript(
                initial_snapshot=True,
                inventory_changes=True,
            )
        )

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.warnings, ())
        self.assertEqual(analysis.state.inventory_change_packets, 1)
        self.assertEqual(analysis.state.inventory_modifications, 4)
        self.assertEqual(
            analysis.state.inventory_modifications_by_operation,
            {"update_quantity": 1, "add": 2, "move": 1},
        )
        self.assertEqual(analysis.state.inventory_update_flags, {0: 1})
        self.assertEqual(analysis.state.inventory_unknown_slot_modifications, 0)
        self.assertEqual(analysis.state.inventory_items["use"][0].quantity, 5)
        self.assertEqual(len(analysis.state.inventory_items["etc"]), 1)
        self.assertEqual(
            analysis.state.inventory_items["etc"][0].item_id, 4_010_003
        )
        self.assertEqual(len(analysis.state.inventory_items["equip"]), 1)
        self.assertEqual(analysis.state.inventory_items["equip"][0].slot, -11)
        event = next(
            event
            for event in analysis.events
            if event.kind == "inventory_change_set_received"
        )
        self.assertEqual(event.details["applied_modifications"], 4)
        self.assertEqual(
            event.details["modifications"][0]["previous_quantity"], 3
        )
        report = analysis.safe_dict()
        self.assertEqual(report["state"]["inventory"]["item_counts"]["etc"], 1)
        self.assertEqual(report["state"]["inventory_modifications"], 4)

    def test_correlates_item_use_request_inventory_and_stat_effects(self) -> None:
        transcript = fixture_gameplay_transcript(
            initial_snapshot=True,
            item_use=True,
        )
        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.warnings, ())
        self.assertEqual(analysis.state.item_use_requests, 1)
        self.assertEqual(
            analysis.state.item_use_requests_by_item, {2_000_000: 1}
        )
        self.assertEqual(analysis.state.item_use_inventory_matches, 1)
        self.assertEqual(analysis.state.item_use_effect_matches, 1)
        self.assertEqual(analysis.state.item_use_inventory_mismatches, 0)
        self.assertEqual(analysis.state.item_use_effect_mismatches, 0)
        self.assertEqual(analysis.state.pending_item_uses, 0)
        self.assertEqual(analysis.state.inventory_items["use"][0].quantity, 2)
        self.assertEqual(analysis.state.current_hp, 120)
        request_event = next(
            event for event in analysis.events if event.kind == "item_use_requested"
        )
        self.assertEqual(request_event.details["predicted_quantity"], 2)
        self.assertEqual(request_event.details["predicted_effect_value"], 120)
        stat_event = next(
            event for event in analysis.events if event.kind == "player_stats_updated"
        )
        self.assertTrue(stat_event.details["item_use_effect"]["matches"])

        policy = derive_item_use_response_policy(transcript)
        response = policy.respond(
            ItemUseRequest(client_tick=102_100, slot=1, item_id=2_000_000)
        )
        self.assertEqual(response.quantity_before, 2)
        self.assertEqual(response.quantity_after, 1)
        self.assertEqual(response.effect_before, 120)
        self.assertEqual(response.effect_after, 170)
        self.assertEqual(
            InventoryChangeSet.parse(response.plaintexts[0]).modifications[0].quantity,
            1,
        )
        self.assertEqual(
            CharacterStatUpdate.parse(response.plaintexts[1]).current_hp, 170
        )
        self.assertEqual(policy.use_items[1].quantity, 1)
        self.assertEqual(policy.current_hp, 170)
        with self.assertRaisesRegex(ValueError, "last-item removal"):
            policy.respond(
                ItemUseRequest(client_tick=102_101, slot=1, item_id=2_000_000)
            )

    def test_correlates_item_pickup_effect_notice_and_removal_chains(self) -> None:
        analysis = analyze_gameplay_transcript(
            fixture_gameplay_transcript(
                initial_snapshot=True,
                item_pickup=True,
            )
        )

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.warnings, ())
        self.assertEqual(analysis.state.item_pickup_requests, 3)
        self.assertEqual(analysis.state.item_pickup_base_requests, 2)
        self.assertEqual(analysis.state.item_pickup_extended_requests, 1)
        self.assertEqual(analysis.state.item_pickup_field_epoch_matches, 3)
        self.assertEqual(analysis.state.item_pickup_field_epoch_mismatches, 0)
        self.assertEqual(analysis.state.item_pickup_known_drops, 3)
        self.assertEqual(analysis.state.item_pickup_unknown_drops, 0)
        self.assertEqual(analysis.state.item_pickup_results, 3)
        self.assertEqual(
            analysis.state.item_pickup_results_by_kind,
            {"item": 1, "mesos": 1, "special": 1},
        )
        self.assertEqual(analysis.state.item_pickup_effect_matches, 3)
        self.assertEqual(analysis.state.item_pickup_effect_mismatches, 0)
        self.assertEqual(
            analysis.state.item_pickup_inferred_mesos_baselines, 1
        )
        self.assertEqual(analysis.state.item_pickup_spawn_result_matches, 3)
        self.assertEqual(analysis.state.item_pickup_spawn_result_mismatches, 0)
        self.assertEqual(
            analysis.state.item_pickup_item_effects_by_template,
            {4_010_003: {("etc", 1)}},
        )
        self.assertEqual(analysis.state.item_pickup_removal_matches, 3)
        self.assertEqual(analysis.state.item_pickup_removal_mismatches, 0)
        self.assertEqual(analysis.state.pending_item_pickups, 0)
        self.assertEqual(analysis.state.field_drop_removals, 3)
        self.assertEqual(analysis.state.field_drop_removals_by_reason, {5: 3})
        self.assertEqual(analysis.state.field_drop_spawn_packets, 5)
        self.assertEqual(analysis.state.field_drop_spawns, 3)
        self.assertEqual(analysis.state.field_drop_refreshes, 2)
        self.assertEqual(analysis.state.field_drop_refresh_mismatches, 0)
        self.assertEqual(
            analysis.state.field_drop_spawns_by_mode, {0: 2, 1: 2, 2: 1}
        )
        self.assertEqual(
            analysis.state.field_drop_spawns_by_kind,
            {"item": 2, "mesos": 1},
        )
        self.assertEqual(
            analysis.state.field_drop_spawns_with_known_source_mob, 4
        )
        self.assertEqual(
            analysis.state.field_drop_spawns_with_unknown_source_mob, 0
        )
        self.assertEqual(analysis.state.field_drop_removals_for_known_drop, 3)
        self.assertEqual(analysis.state.field_drop_removals_for_unknown_drop, 0)
        self.assertEqual(analysis.state.field_drops, {})
        self.assertEqual(analysis.state.mesos, 16)
        picked_item = next(
            item
            for item in analysis.state.inventory_items["etc"]
            if item.slot == 20
        )
        self.assertEqual((picked_item.item_id, picked_item.quantity), (4_010_003, 1))

        request_events = [
            event
            for event in analysis.events
            if event.kind == "item_pickup_requested"
        ]
        result_events = [
            event
            for event in analysis.events
            if event.kind == "item_pickup_result_received"
        ]
        removal_events = [
            event
            for event in analysis.events
            if event.kind == "field_drop_removed"
            and event.details["matched_pickup_request"]
        ]
        self.assertEqual(len(request_events), 3)
        self.assertEqual(len(result_events), 3)
        self.assertEqual(len(removal_events), 3)
        self.assertEqual(
            sum(event.kind == "field_drop_spawned" for event in analysis.events),
            3,
        )
        self.assertEqual(
            sum(event.kind == "field_drop_refreshed" for event in analysis.events),
            2,
        )
        self.assertTrue(
            all(event.details["effect_matches_notice"] for event in result_events)
        )
        self.assertTrue(
            all(event.details["spawn_matches_notice"] for event in result_events)
        )
        self.assertTrue(
            all(event.details["pickup_removal_matches"] for event in removal_events)
        )
        safe = analysis.safe_dict()
        self.assertNotIn("drop_object_id", str(safe["events"]))
        self.assertNotIn("drop_object_id", str(safe["packets"]))
        self.assertNotIn("actor_id", str(safe["events"]))
        self.assertNotIn("actor_id", str(safe["packets"]))

    def test_folds_safe_runtime_annotations_into_ordered_events(self) -> None:
        transcript = fixture_gameplay_transcript()
        close_event = transcript.events[-1]
        annotated_close = replace(
            close_event,
            metadata={
                "runtime_events_written": 1,
                "runtime_events_dropped": 2,
            },
        )
        runtime_event = TranscriptEvent(
            event="runtime_event",
            timestamp_ns=close_event.timestamp_ns,
            metadata={
                "kind": "mob_movement_policy_trigger_rejected",
                "details": {
                    "trigger": "matched_heartbeat",
                    "reason": "cooldown",
                    "cooldown_remaining_seconds": 3.5,
                },
            },
        )
        annotated = Transcript(
            path=Path("annotated-gameplay.jsonl"),
            events=(
                *transcript.events[:-1],
                runtime_event,
                annotated_close,
            ),
        )

        analysis = analyze_gameplay_transcript(annotated)

        self.assertTrue(analysis.valid)
        event = next(
            event
            for event in analysis.events
            if event.kind == "mob_movement_policy_trigger_rejected"
        )
        self.assertEqual(event.direction, "runtime")
        self.assertEqual(event.frame_index, analysis.decoded.frames[-1].index)
        self.assertEqual(event.details["reason"], "cooldown")
        self.assertEqual(
            [event.index for event in analysis.events],
            list(range(len(analysis.events))),
        )
        self.assertIn(
            "mob_movement_policy_trigger_rejected",
            str(analysis.safe_dict()["events"]),
        )
        self.assertTrue(
            any(
                "transcript dropped 2 runtime event annotations" in warning
                for warning in analysis.warnings
            )
        )

        invalid_annotation = replace(
            runtime_event,
            metadata={"kind": "invalid kind", "details": {}},
        )
        invalid_close = replace(
            close_event,
            metadata={"runtime_events_written": -1},
        )
        invalid_analysis = analyze_gameplay_transcript(
            replace(
                annotated,
                events=(
                    *transcript.events[:-1],
                    invalid_annotation,
                    invalid_close,
                ),
            )
        )
        self.assertFalse(invalid_analysis.valid)
        self.assertTrue(
            any(
                "runtime transcript event kind" in issue
                for issue in invalid_analysis.issues
            )
        )
        self.assertTrue(
            any(
                "runtime_events_written must be a non-negative integer"
                in issue
                for issue in invalid_analysis.issues
            )
        )

        unmatched_rejection = replace(
            runtime_event,
            metadata={
                "kind": "item_use_request_rejected",
                "details": {
                    "client_tick": 1,
                    "slot": 15,
                    "item_id": 2_000_000,
                    "reason": "test rejection",
                },
            },
        )
        unmatched_analysis = analyze_gameplay_transcript(
            replace(
                annotated,
                events=(
                    *transcript.events[:-1],
                    unmatched_rejection,
                    close_event,
                ),
            )
        )
        self.assertFalse(unmatched_analysis.valid)
        self.assertTrue(
            any(
                "runtime item-use rejection had no matching observed request"
                in issue
                for issue in unmatched_analysis.issues
            )
        )

    def test_folds_packets_into_field_state_and_timestamped_events(self) -> None:
        analysis = analyze_gameplay_transcript(fixture_gameplay_transcript())

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.state.phase, GameplayPhase.ACTIVE)
        self.assertEqual(analysis.state.field_epoch, 1)
        self.assertEqual(analysis.state.field_load_stage, 2)
        self.assertEqual(len(analysis.state.npcs), 1)
        self.assertEqual(analysis.state.npc_spawns, 1)
        self.assertEqual(analysis.state.npc_state_updates, 1)
        self.assertEqual(len(analysis.state.mobs), 1)
        self.assertEqual(analysis.state.mobs[MOB_OBJECT_ID].controller_level, 1)
        self.assertEqual(analysis.state.mob_entries, 1)
        self.assertEqual(analysis.state.mob_controller_changes, 1)
        self.assertEqual(analysis.state.mob_movement_broadcasts, 1)
        self.assertEqual(analysis.state.mob_health_percentage_updates, 3)
        self.assertEqual(analysis.state.mob_health_zero_updates, 1)
        self.assertEqual(analysis.state.mob_health_increases, 0)
        self.assertEqual(analysis.state.mob_health_updates_for_unknown_mobs, 0)
        self.assertEqual(
            analysis.state.mobs[MOB_OBJECT_ID].health_percentage, 0
        )
        self.assertEqual(analysis.state.mob_broadcast_commands, 1)
        self.assertEqual(analysis.state.mob_broadcast_commands_by_type, {0: 1})
        self.assertEqual(analysis.state.unknown_mob_broadcasts, 0)
        self.assertEqual(analysis.state.unknown_mob_leaves, 0)
        self.assertEqual(analysis.state.movement_submissions, 1)
        self.assertEqual(analysis.state.movement_submissions_for_unknown_mobs, 0)
        self.assertEqual(
            analysis.state.movement_submissions_with_unknown_template, 0
        )
        self.assertEqual(analysis.state.movement_commands, 1)
        self.assertEqual(analysis.state.movement_commands_by_type, {0: 1})
        self.assertEqual(analysis.state.matched_movement_acknowledgements, 1)
        self.assertEqual(
            analysis.state.movement_acknowledgements_for_unknown_mobs, 0
        )
        self.assertEqual(
            analysis.state.movement_acknowledgement_statuses,
            {(0, 35, 0, 0): 1},
        )
        self.assertEqual(analysis.state.movement_acknowledgement_flag_matches, 1)
        self.assertEqual(
            analysis.state.movement_acknowledgement_flag_mismatches, 0
        )
        self.assertEqual(
            analysis.state.movement_acknowledgement_zero_auxiliary_pairs, 1
        )
        self.assertEqual(
            analysis.state.movement_acknowledgements_with_known_template, 1
        )
        self.assertEqual(
            analysis.state.movement_acknowledgement_values_by_template,
            {210_100: {35}},
        )
        self.assertEqual(analysis.state.pending_movements, 0)
        self.assertEqual(analysis.state.heartbeat_probes, 1)
        self.assertEqual(analysis.state.heartbeat_responses, 1)
        self.assertEqual(analysis.state.matched_heartbeat_responses, 1)
        self.assertEqual(analysis.state.unmatched_heartbeat_responses, 0)
        self.assertEqual(analysis.state.pending_heartbeat_probes, 0)
        self.assertEqual(analysis.state.last_heartbeat_round_trip_ms, 1e-6)
        event_kinds = [event.kind for event in analysis.events]
        self.assertIn("field_snapshot_received", event_kinds)
        self.assertIn("npc_spawned", event_kinds)
        self.assertIn("npc_state_updated", event_kinds)
        self.assertIn("mob_entered_field", event_kinds)
        self.assertIn("mob_controller_changed", event_kinds)
        self.assertIn("mob_movement_broadcast", event_kinds)
        self.assertIn("mob_health_percentage_updated", event_kinds)
        self.assertIn("field_became_active", event_kinds)
        self.assertIn("mob_movement_submitted", event_kinds)
        self.assertIn("mob_movement_acknowledged", event_kinds)
        self.assertEqual(event_kinds[-1], "session_ended")
        self.assertEqual(
            [event.index for event in analysis.events],
            list(range(len(analysis.events))),
        )

    def test_folds_compact_transition_into_map_state(self) -> None:
        analysis = analyze_gameplay_transcript(
            fixture_gameplay_transcript(
                compact_transition=True,
                player_movement=True,
            )
        )

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.state.phase, GameplayPhase.FIELD_LOADING)
        self.assertEqual(analysis.state.field_epoch, 2)
        self.assertEqual(analysis.state.compact_field_transitions, 1)
        self.assertEqual(analysis.state.transition_sequence, 2)
        self.assertEqual(analysis.state.map_id, 100_050_000)
        self.assertEqual(analysis.state.portal_index, 15)
        self.assertEqual(analysis.state.current_hp, 70)
        self.assertEqual(len(analysis.state.npcs), 0)
        self.assertEqual(len(analysis.state.mobs), 0)
        self.assertIsNone(analysis.state.player_x)
        self.assertIsNone(analysis.state.player_y)
        self.assertEqual(len(analysis.state.observed_players), 0)
        self.assertEqual(analysis.state.player_movement_submissions, 1)
        self.assertEqual(analysis.state.remote_player_movement_broadcasts, 1)
        observation = next(
            item
            for item in analysis.observations
            if item.kind == "compact_field_transition"
        )
        self.assertEqual(observation.coverage.value, "full")
        self.assertEqual(observation.details["map_id"], 100_050_000)
        self.assertEqual(
            observation.details["opaque_text_character_counts"], [1, 1, 16]
        )
        self.assertNotIn("sanitized-field!", analysis.to_json())

    def test_safe_output_uses_correlatable_aliases_and_redacts_raw_ids(self) -> None:
        analysis = analyze_gameplay_transcript(fixture_gameplay_transcript())

        safe_json = analysis.to_json()
        identified = analysis.safe_dict(show_identifiers=True)
        self.assertNotIn(str(CHARACTER_ID), safe_json)
        self.assertNotIn(str(NPC_OBJECT_ID), safe_json)
        self.assertNotIn(str(MOB_OBJECT_ID), safe_json)
        self.assertIn('"entity": "npc:1"', safe_json)
        self.assertEqual(identified["state"]["entry_character_id"], CHARACTER_ID)
        self.assertEqual(identified["state"]["npcs"][0]["object_id"], NPC_OBJECT_ID)
        self.assertEqual(identified["state"]["mobs"][0]["object_id"], MOB_OBJECT_ID)

    def test_text_report_can_emit_events_and_packet_shapes(self) -> None:
        analysis = analyze_gameplay_transcript(
            fixture_gameplay_transcript(
                player_movement=True,
                attack_actions=True,
                opcode_101_records=True,
                opcode_13_messages=True,
                opcode_217_records=True,
                opcode_426_acknowledgement=True,
            )
        )

        report = render_gameplay_analysis(
            analysis,
            show_events=True,
            show_packets=True,
        )

        self.assertIn("kind=npc_spawned", report)
        self.assertIn("opcode=300 kind=npc_spawn coverage=full", report)
        self.assertIn("opcode=279 kind=mob_enter_field coverage=partial", report)
        self.assertIn("mobs=active:1 entries:1 leaves:0", report)
        self.assertIn("matched_submission\":true", report)
        self.assertIn("command_types\":[0]", report)
        self.assertIn('commands:1 command_types:{"0": 1}', report)
        self.assertIn(
            'life_movement=submitted:1 submission_commands:5 '
            'submission_command_types:{"0": 1, "2": 1, "10": 1, '
            '"14": 1, "15": 1} tail_types:{"17": 1} '
            'tail_markers:{"4": 1}',
            report,
        )
        self.assertIn(
            "opcode=47 kind=life_movement_submission coverage=partial",
            report,
        )
        self.assertEqual(analysis.state.client_opcode_13_messages, 3)
        self.assertEqual(
            analysis.state.client_opcode_13_messages_by_type,
            {1: 1, 6: 1, 13: 1},
        )
        self.assertEqual(analysis.state.client_opcode_13_opaque_bytes, 37)
        self.assertIn(
            'client_opcode_13=messages:3 message_types:{"1": 1, "6": 1, '
            '"13": 1} opaque_bytes:37',
            report,
        )
        self.assertIn(
            "opcode=13 kind=client_opcode_13_message coverage=partial",
            report,
        )
        self.assertEqual(analysis.state.client_opcode_217_packets, 3)
        self.assertEqual(analysis.state.client_opcode_217_compact_packets, 1)
        self.assertEqual(analysis.state.client_opcode_217_record_sets, 2)
        self.assertEqual(analysis.state.client_opcode_217_records, 4)
        self.assertEqual(
            analysis.state.client_opcode_217_records_by_format,
            {0: 2, 2: 2},
        )
        self.assertEqual(
            analysis.state.client_opcode_217_record_counts,
            {2: 2},
        )
        self.assertIn(
            'client_opcode_217=packets:3 compact:1 record_sets:2 records:4 '
            'records_by_format:{"0": 2, "2": 2} record_counts:{"2": 2}',
            report,
        )
        self.assertIn(
            "opcode=217 kind=client_opcode_217_record_set coverage=partial",
            report,
        )
        self.assertNotIn("prefix-002", report)
        self.assertEqual(analysis.state.opcode_426_notifications, 1)
        self.assertEqual(analysis.state.opcode_309_acknowledgements, 1)
        self.assertEqual(
            analysis.state.matched_opcode_309_acknowledgements, 1
        )
        self.assertEqual(
            analysis.state.unmatched_opcode_309_acknowledgements, 0
        )
        self.assertEqual(analysis.state.pending_opcode_426_notifications, 0)
        self.assertIn(
            "opcode_426_309=notified:1 acknowledged:1 matched:1 "
            "unmatched:0 pending:0",
            report,
        )
        self.assertIn(
            "opcode=426 kind=opcode_426_notification coverage=full",
            report,
        )
        self.assertIn(
            "opcode=309 kind=opcode_309_acknowledgement coverage=full",
            report,
        )
        self.assertEqual(analysis.state.client_attack_actions, 5)
        self.assertEqual(
            analysis.state.client_attack_actions_by_opcode,
            {50: 2, 52: 2, 54: 1},
        )
        self.assertEqual(
            analysis.state.client_attack_shapes,
            {
                "50:variant=1": 1,
                "50:variant=17": 1,
                "52:variant=2": 1,
                "52:variant=18": 1,
                "54:flags=255:0": 1,
            },
        )
        self.assertEqual(analysis.state.client_attack_targeted_actions, 3)
        self.assertEqual(analysis.state.client_attack_untargeted_actions, 2)
        self.assertEqual(
            analysis.state.client_attack_targets_for_active_mobs, 3
        )
        self.assertEqual(
            analysis.state.client_attack_targets_for_known_mobs, 3
        )
        self.assertEqual(
            analysis.state.client_attack_targets_for_unknown_mobs, 0
        )
        self.assertEqual(analysis.state.client_attack_damage_actions, 2)
        self.assertEqual(analysis.state.client_attack_damage_entries, 3)
        self.assertEqual(analysis.state.client_attack_damage_total, 121)
        self.assertEqual(analysis.state.client_attack_damage_min, 40)
        self.assertEqual(analysis.state.client_attack_damage_max, 41)
        self.assertEqual(
            analysis.state.client_attack_damage_high_bit_markers, 2
        )
        self.assertEqual(analysis.state.client_attack_zero_damage_entries, 0)
        self.assertEqual(analysis.state.client_attack_health_matches, 0)
        self.assertEqual(analysis.state.client_attack_health_predictions, 0)
        self.assertEqual(analysis.state.client_attack_effects_cleared, 0)
        self.assertEqual(analysis.state.pending_client_attack_effects, 3)
        self.assertEqual(analysis.state.server_attack_relays, 2)
        self.assertEqual(
            analysis.state.server_attack_relays_by_opcode, {218: 1, 219: 1}
        )
        self.assertEqual(analysis.state.server_attack_target_counts, {1: 2})
        self.assertEqual(analysis.state.server_attack_hit_counts, {1: 1, 2: 1})
        self.assertEqual(
            analysis.state.server_attack_relays_for_known_players, 2
        )
        self.assertEqual(
            analysis.state.server_attack_relays_for_unknown_players, 0
        )
        self.assertEqual(analysis.state.server_melee_attack_relays, 1)
        self.assertEqual(
            analysis.state.server_melee_attack_short_zero_target_forms, 0
        )
        self.assertEqual(analysis.state.server_melee_attack_tags, {8: 1})
        self.assertEqual(
            analysis.state.server_melee_attack_skill_levels, {0: 1}
        )
        self.assertEqual(
            analysis.state.server_melee_attack_unknown_values, {0: 1}
        )
        self.assertEqual(
            analysis.state.server_melee_attack_displays, {5: 1}
        )
        self.assertEqual(
            analysis.state.server_melee_attack_facing_flags, {0: 1}
        )
        self.assertEqual(
            analysis.state.server_melee_attack_speeds, {4: 1}
        )
        self.assertEqual(
            analysis.state.server_melee_attack_mastery_values, {0: 1}
        )
        self.assertEqual(
            analysis.state.server_melee_attack_auxiliary_values, {0: 1}
        )
        self.assertEqual(analysis.state.server_ranged_attack_relays, 1)
        self.assertEqual(analysis.state.server_ranged_attack_tags, {16: 1})
        self.assertEqual(
            analysis.state.server_ranged_attack_skill_levels, {8: 1}
        )
        self.assertEqual(
            analysis.state.server_ranged_attack_skill_ids, {4_001_344: 1}
        )
        self.assertEqual(
            analysis.state.server_ranged_attack_unknown_values, {0: 1}
        )
        self.assertEqual(
            analysis.state.server_ranged_attack_displays, {0x1A: 1}
        )
        self.assertEqual(
            analysis.state.server_ranged_attack_facing_flags, {0x80: 1}
        )
        self.assertEqual(
            analysis.state.server_ranged_attack_speeds, {6: 1}
        )
        self.assertEqual(
            analysis.state.server_ranged_attack_mastery_values, {0: 1}
        )
        self.assertEqual(
            analysis.state.server_ranged_attack_projectile_ids,
            {2_070_000: 1},
        )
        self.assertEqual(
            analysis.state.server_ranged_attack_positions_for_known_players,
            1,
        )
        self.assertEqual(
            analysis.state.server_ranged_attack_position_delta_x_min, -8
        )
        self.assertEqual(
            analysis.state.server_ranged_attack_position_delta_x_max, -8
        )
        self.assertEqual(
            analysis.state.server_ranged_attack_position_delta_y_min, -28
        )
        self.assertEqual(
            analysis.state.server_ranged_attack_position_delta_y_max, -28
        )
        self.assertEqual(analysis.state.server_attack_target_records, 2)
        self.assertEqual(analysis.state.server_attack_zero_object_targets, 0)
        self.assertEqual(
            analysis.state.server_attack_targets_for_active_mobs, 2
        )
        self.assertEqual(
            analysis.state.server_attack_targets_for_known_mobs, 2
        )
        self.assertEqual(
            analysis.state.server_attack_targets_for_unknown_mobs, 0
        )
        self.assertEqual(analysis.state.server_attack_hit_actions, {6: 2})
        self.assertEqual(analysis.state.server_attack_damage_entries, 3)
        self.assertEqual(analysis.state.server_attack_damage_total, 121)
        self.assertEqual(analysis.state.server_attack_damage_min, 40)
        self.assertEqual(analysis.state.server_attack_damage_max, 41)
        self.assertEqual(
            analysis.state.server_attack_damage_high_bit_markers, 2
        )
        active_mob = analysis.state.mobs[MOB_OBJECT_ID]
        self.assertEqual(active_mob.client_attack_submitted_hits, 3)
        self.assertEqual(active_mob.client_attack_submitted_damage, 121)
        self.assertEqual(
            active_mob.client_attack_submitted_high_bit_markers, 2
        )
        self.assertEqual(active_mob.attack_relay_hits, 3)
        self.assertEqual(active_mob.attack_relay_damage, 121)
        self.assertEqual(active_mob.attack_relay_high_bit_markers, 2)
        self.assertEqual(active_mob.last_attack_hit_action, 6)
        safe_mob = analysis.safe_dict()["state"]["mobs"][0]
        self.assertEqual(safe_mob["client_attack_submitted_hits"], 3)
        self.assertEqual(safe_mob["client_attack_submitted_damage"], 121)
        self.assertEqual(safe_mob["attack_relay_hits"], 3)
        self.assertEqual(safe_mob["attack_relay_damage"], 121)
        self.assertIn(
            'combat=client_actions:5 client_opcodes:{"50": 2, "52": 2, '
            '"54": 1}',
            report,
        )
        self.assertIn(
            "client_damage_entries:3 client_damage_actions:2 "
            "client_damage_total:121 "
            "client_damage_range:40..41 client_damage_high_bits:2 "
            "client_zero_damage_entries:0 client_health_matches:0 "
            "client_health_predictions:0 "
            "client_health_prediction_matches:0 "
            "client_health_prediction_mismatches:0 "
            "client_health_prediction_one_hp_differences:0 "
            "client_health_predictions_with_relay_hits:0 "
            "client_health_mismatches_without_relay_hits:0 "
            "client_health_mismatch_damage_deltas:{} "
            "cleared_client_effects:0 pending_client_effects:3",
            report,
        )
        self.assertIn(
            "opcode=50 kind=client_attack_action coverage=partial",
            report,
        )
        self.assertIn(
            "opcode=52 kind=client_attack_action coverage=partial",
            report,
        )
        self.assertIn(
            "opcode=54 kind=client_attack_action coverage=partial",
            report,
        )
        self.assertIn(
            "opcode=218 kind=server_attack_relay coverage=partial",
            report,
        )
        self.assertIn(
            "opcode=219 kind=server_attack_relay coverage=partial",
            report,
        )
        self.assertIn("kind=client_attack_submitted", report)
        self.assertIn("kind=server_attack_relay_received", report)
        self.assertIn(
            'melee_relays:1 melee_short_zero_targets:0 '
            'melee_tags:{"8": 1} melee_displays:{"5": 1}',
            report,
        )
        self.assertIn(
            'ranged_relays:1 ranged_skill_levels:{"8": 1} '
            'ranged_skill_ids:{"4001344": 1} '
            'ranged_projectiles:{"2070000": 1}',
            report,
        )
        self.assertIn('"position_delta_x":-8', report)
        self.assertIn('"position_delta_y":-28', report)
        self.assertIn('"projectile_id":2070000', report)
        self.assertIn('"damage_values":[40,41]', report)
        self.assertIn('"high_bit_markers":[true,false]', report)
        self.assertNotIn("987654321", report)
        self.assertNotIn(str(MOB_OBJECT_ID), report)
        self.assertNotIn(str(PLAYER_OBJECT_ID), report)
        self.assertEqual(analysis.state.client_opcode_101_packets, 2)
        self.assertEqual(
            analysis.state.client_opcode_101_header_values, {0: 2}
        )
        self.assertEqual(
            analysis.state.client_opcode_101_primary_values,
            {20: 1, 0x0A00_0014: 1},
        )
        self.assertEqual(
            analysis.state.client_opcode_101_flag_values, {0: 2}
        )
        self.assertEqual(
            analysis.state.client_opcode_101_secondary_values, {0: 1, 3: 1}
        )
        self.assertEqual(
            analysis.state.client_opcode_101_tail_values, {0: 2}
        )
        self.assertIn(
            'client_opcode_101=packets:2 header_values:{"0": 2} '
            'primary_values:{"20": 1, "167772180": 1} '
            'flag_values:{"0": 2} secondary_values:{"0": 1, "3": 1} '
            'tail_values:{"0": 2}',
            report,
        )
        self.assertIn(
            "opcode=101 kind=client_opcode_101_record coverage=partial",
            report,
        )
        self.assertNotIn("variable-thirteen", report)
        self.assertNotIn("123456", report)
        self.assertIn(
            "movement_ack_policy=flag_matches:1 flag_mismatches:0",
            report,
        )

    def test_derives_identifier_free_movement_acknowledgement_policy(self) -> None:
        policy = derive_mob_movement_acknowledgement_policy(
            fixture_gameplay_transcript()
        )
        submission = MobMovementSubmission(
            object_id=MOB_OBJECT_ID,
            sequence=10,
            opaque_movement=fixture_movement_path().to_bytes(),
        )

        self.assertEqual(
            policy.acknowledge(submission),
            MobMovementAcknowledgement(
                object_id=MOB_OBJECT_ID,
                sequence=10,
                status_flag=0,
                status_value=35,
                status_auxiliary_1=0,
                status_auxiliary_2=0,
            ),
        )
        safe = policy.safe_dict()
        self.assertEqual(
            safe["status_values_by_template"],
            [
                {
                    "template_id": 210_100,
                    "status_value": 35,
                    "observations": 1,
                }
            ],
        )
        self.assertEqual(safe["active_known_mob_count"], 1)
        self.assertEqual(safe["field_known_mob_count"], 1)
        self.assertNotIn(str(MOB_OBJECT_ID), str(safe))
        nonzero_control_path = replace(
            fixture_movement_path(),
            opaque_control=(
                b"\x01" + fixture_movement_path().opaque_control[1:]
            ),
        )
        flagged = policy.acknowledge(
            MobMovementSubmission(
                object_id=MOB_OBJECT_ID,
                sequence=11,
                opaque_movement=nonzero_control_path.to_bytes(),
            )
        )
        self.assertEqual(flagged.status_flag, 1)

    def test_movement_policy_uses_separate_evidence_and_runtime_spawn(
        self,
    ) -> None:
        policy = derive_mob_movement_acknowledgement_policy(
            fixture_gameplay_transcript(compact_transition=True),
            evidence_transcript=fixture_gameplay_transcript(),
        )
        self.assertEqual(policy.known_mob_templates, {})
        self.assertEqual(policy.safe_dict()["active_known_mob_count"], 0)

        policy.apply_server_packet(
            MobControllerChange(
                control_level=1,
                object_id=MOB_OBJECT_ID,
                spawn=fixture_mob_spawn(),
            ).to_bytes()
        )
        acknowledgement = policy.acknowledge(
            MobMovementSubmission(
                object_id=MOB_OBJECT_ID,
                sequence=12,
                opaque_movement=fixture_movement_path().to_bytes(),
            )
        )

        self.assertEqual(acknowledgement.status_value, 35)
        self.assertEqual(policy.safe_dict()["field_known_mob_count"], 1)
        self.assertEqual(policy.safe_dict()["active_known_mob_count"], 1)
        policy.apply_server_packet(
            MobLeaveField(object_id=MOB_OBJECT_ID, reason=1).to_bytes()
        )
        self.assertEqual(policy.safe_dict()["active_known_mob_count"], 0)
        self.assertEqual(
            policy.known_mob_templates[MOB_OBJECT_ID], 210_100
        )

    def test_plans_stationary_mob_broadcast_from_runtime_spawn(self) -> None:
        stationary_evidence = MobMovementBroadcast(
            object_id=MOB_OBJECT_ID,
            opaque_control=b"\x00\x00\xff\x00\x00\x00\x00",
            reference_x=100,
            reference_y=-200,
            commands=(
                MobMovementCommand.absolute(
                    position_x=100,
                    position_y=-200,
                    velocity_x=0,
                    velocity_y=0,
                    foothold_id=7,
                    stance=4,
                    duration_ms=1_080,
                ),
            ),
        ).to_bytes()
        post_spawn = MobEnterField(
            object_id=MOB_OBJECT_ID,
            spawn=fixture_mob_spawn(),
        ).to_bytes()
        post_controller = MobControllerChange(
            control_level=1,
            object_id=MOB_OBJECT_ID,
            spawn=fixture_mob_spawn(),
        ).to_bytes()
        plan = plan_mob_movement_broadcast(
            fixture_gameplay_transcript(compact_transition=True),
            post_transcript_server_frames=(post_spawn, post_controller),
            evidence_transcript=fixture_gameplay_transcript(
                extra_server_plaintexts=(stationary_evidence,)
            ),
            target_x=200,
            target_y=-200,
            foothold_id=8,
        )

        self.assertEqual(plan.entity, "mob:runtime:1")
        self.assertEqual(plan.template_id, 210_100)
        self.assertEqual((plan.previous_x, plan.previous_y), (100, -200))
        self.assertEqual(plan.exact_stationary_shape_evidence, 1)
        self.assertEqual(plan.mode, "stationary")
        self.assertEqual(plan.matching_displacement_path_evidence, 0)
        self.assertEqual(plan.matching_displacement_shape_evidence, 0)
        broadcast = MobMovementBroadcast.parse(plan.broadcast.to_bytes())
        self.assertEqual(
            (broadcast.reference_x, broadcast.reference_y),
            (200, -200),
        )
        self.assertEqual(broadcast.opaque_control.hex(), "0000ff00000000")
        self.assertEqual(broadcast.commands[0].position, (200, -200))
        self.assertEqual(broadcast.commands[0].velocity, (0, 0))
        self.assertEqual(broadcast.commands[0].foothold_id, 8)
        self.assertEqual(broadcast.commands[0].duration_ms, 1_080)
        self.assertNotIn("object_id", plan.safe_dict())

        folded = analyze_gameplay_transcript(
            fixture_gameplay_transcript(
                extra_server_plaintexts=(plan.broadcast.to_bytes(),)
            )
        )
        self.assertTrue(folded.valid)
        self.assertEqual(
            (
                folded.state.mobs[MOB_OBJECT_ID].x,
                folded.state.mobs[MOB_OBJECT_ID].y,
            ),
            (200, -200),
        )
        self.assertEqual(folded.state.mobs[MOB_OBJECT_ID].foothold_id, 8)
        self.assertEqual(folded.state.mobs[MOB_OBJECT_ID].stance, 4)
        self.assertEqual(
            folded.safe_dict()["state"]["mobs"][0]["foothold_id"],
            8,
        )

        with self.assertRaisesRegex(ValueError, "exactly one active"):
            plan_mob_movement_broadcast(
                fixture_gameplay_transcript(compact_transition=True),
                evidence_transcript=fixture_gameplay_transcript(
                    extra_server_plaintexts=(stationary_evidence,)
                ),
                target_x=200,
                target_y=-200,
                foothold_id=8,
            )

    def test_translates_captured_multi_command_mob_path(self) -> None:
        source_path = MobMovementBroadcast(
            object_id=MOB_OBJECT_ID,
            opaque_control=b"\x00\x00\xff\x00\x00\x00\x00",
            reference_x=100,
            reference_y=-200,
            commands=(
                MobMovementCommand.absolute(
                    position_x=120,
                    position_y=-200,
                    velocity_x=20,
                    velocity_y=0,
                    foothold_id=7,
                    stance=2,
                    duration_ms=500,
                ),
                MobMovementCommand.absolute(
                    position_x=140,
                    position_y=-202,
                    velocity_x=20,
                    velocity_y=-5,
                    foothold_id=8,
                    stance=2,
                    duration_ms=300,
                ),
                MobMovementCommand.absolute(
                    position_x=150,
                    position_y=-200,
                    velocity_x=10,
                    velocity_y=5,
                    foothold_id=9,
                    stance=4,
                    duration_ms=280,
                ),
            ),
        ).to_bytes()
        evidence = fixture_gameplay_transcript(
            extra_server_plaintexts=(source_path,)
        )
        source_frame = next(
            frame.direction_index
            for frame in analyze_gameplay_transcript(evidence).decoded.frames
            if frame.direction == "server_to_client"
            and frame.plaintext == source_path
        )
        translated_spawn = replace(
            fixture_mob_spawn(),
            x=200,
            foothold_id=8,
        )
        post_spawn = MobEnterField(
            object_id=MOB_OBJECT_ID,
            spawn=translated_spawn,
        ).to_bytes()
        plan = plan_mob_movement_broadcast(
            fixture_gameplay_transcript(compact_transition=True),
            post_transcript_server_frames=(post_spawn,),
            evidence_transcript=evidence,
            target_x=250,
            target_y=-200,
            foothold_id=8,
            path_evidence_server_frame_index=source_frame,
        )

        self.assertEqual(plan.mode, "translated_captured_path")
        self.assertEqual(plan.source_server_frame_index, source_frame)
        self.assertEqual(plan.exact_relative_motion_shape_evidence, 1)
        self.assertEqual(plan.matching_displacement_path_evidence, 1)
        self.assertEqual(plan.matching_displacement_shape_evidence, 1)
        self.assertEqual((plan.previous_x, plan.previous_y), (200, -200))
        broadcast = MobMovementBroadcast.parse(plan.broadcast.to_bytes())
        self.assertEqual(
            (broadcast.reference_x, broadcast.reference_y),
            (200, -200),
        )
        self.assertEqual(
            tuple(command.position for command in broadcast.commands),
            ((220, -200), (240, -202), (250, -200)),
        )
        self.assertEqual(
            tuple(command.velocity for command in broadcast.commands),
            ((20, 0), (20, -5), (10, 5)),
        )
        self.assertEqual(
            tuple(command.duration_ms for command in broadcast.commands),
            (500, 300, 280),
        )
        self.assertEqual(
            tuple(command.foothold_id for command in broadcast.commands),
            (8, 8, 8),
        )
        self.assertEqual(plan.stance, 4)

        folded = analyze_gameplay_transcript(
            fixture_gameplay_transcript(
                extra_server_plaintexts=(plan.broadcast.to_bytes(),)
            )
        )
        self.assertTrue(folded.valid)
        self.assertEqual(
            (
                folded.state.mobs[MOB_OBJECT_ID].x,
                folded.state.mobs[MOB_OBJECT_ID].y,
            ),
            (250, -200),
        )
        self.assertEqual(folded.state.mobs[MOB_OBJECT_ID].foothold_id, 8)

        automatic_plan = plan_mob_movement_broadcast(
            fixture_gameplay_transcript(compact_transition=True),
            post_transcript_server_frames=(post_spawn,),
            evidence_transcript=evidence,
            target_x=250,
            target_y=-200,
            foothold_id=8,
            auto_select_captured_path=True,
        )
        self.assertEqual(
            automatic_plan.mode,
            "auto_selected_captured_path",
        )
        self.assertEqual(
            automatic_plan.source_server_frame_index,
            source_frame,
        )
        self.assertEqual(
            automatic_plan.broadcast.to_bytes(),
            plan.broadcast.to_bytes(),
        )
        planning_context = build_mob_movement_planning_context(
            fixture_gameplay_transcript(compact_transition=True), evidence
        )
        self.assertGreater(
            planning_context.safe_dict()["captured_path_count"], 0
        )
        self.assertGreater(
            planning_context.safe_dict()["evidence_frame_count"], 0
        )

        sequence_plan = plan_composed_mob_movement_broadcasts(
            fixture_gameplay_transcript(compact_transition=True),
            post_transcript_server_frames=(post_spawn,),
            evidence_transcript=evidence,
            target_x=300,
            target_y=-200,
            foothold_id=8,
            max_steps=2,
        )
        self.assertEqual(len(sequence_plan.steps), 2)
        self.assertEqual(sequence_plan.usable_displacements, 1)
        self.assertEqual(sequence_plan.ambiguous_displacements, 0)
        self.assertEqual(sequence_plan.shortest_sequence_count, 1)
        self.assertEqual(
            tuple(
                step.source_server_frame_index
                for step in sequence_plan.steps
            ),
            (source_frame, source_frame),
        )
        self.assertEqual(
            tuple(
                (step.previous_x, step.target_x)
                for step in sequence_plan.steps
            ),
            ((200, 250), (250, 300)),
        )
        self.assertEqual(
            tuple(
                (broadcast.reference_x, broadcast.reference_y)
                for broadcast in sequence_plan.broadcasts
            ),
            ((200, -200), (250, -200)),
        )
        scheduler = MobMovementBroadcastScheduler(
            sequence_plan.steps,
            baseline_server_frames=(post_spawn,),
        )
        self.assertEqual(scheduler.packets_sent, 0)
        self.assertEqual(scheduler.packets_remaining, 2)
        self.assertEqual(scheduler.confirmed_server_frames, ())
        self.assertEqual(
            scheduler.safe_dict()["current"],
            {
                "x": 200,
                "y": -200,
                "foothold_id": 8,
                "stance": translated_spawn.stance,
            },
        )
        self.assertEqual(scheduler.safe_dict()["phase"], "planned")
        with self.assertRaisesRegex(ValueError, "next scheduled step 1"):
            scheduler.confirm_sent(
                sequence_plan.steps[1].broadcast.to_bytes()
            )
        self.assertEqual(scheduler.packets_sent, 0)

        scheduler.confirm_sent(sequence_plan.steps[0].broadcast.to_bytes())
        in_progress = scheduler.telemetry_dict()
        self.assertEqual(in_progress["packets_sent"], 1)
        self.assertEqual(in_progress["packets_remaining"], 1)
        self.assertEqual(in_progress["state"]["phase"], "in_progress")
        self.assertEqual(
            in_progress["state"]["current"],
            {
                "x": 250,
                "y": -200,
                "foothold_id": 8,
                "stance": sequence_plan.steps[0].stance,
            },
        )
        self.assertEqual(
            in_progress["state"]["last_sent_step"]["step_index"],
            1,
        )
        self.assertEqual(
            in_progress["state"]["next_step"]["step_index"],
            2,
        )
        self.assertEqual(
            scheduler.confirmed_server_frames,
            (sequence_plan.steps[0].broadcast.to_bytes(),),
        )
        replanned_from_confirmed_state = plan_mob_movement_broadcast(
            fixture_gameplay_transcript(compact_transition=True),
            post_transcript_server_frames=(
                scheduler.planning_server_frames
            ),
            evidence_transcript=evidence,
            target_x=300,
            target_y=-200,
            foothold_id=8,
            path_evidence_server_frame_index=source_frame,
        )
        self.assertEqual(
            (
                replanned_from_confirmed_state.previous_x,
                replanned_from_confirmed_state.previous_y,
            ),
            (250, -200),
        )
        scheduler.confirm_sent(sequence_plan.steps[1].broadcast.to_bytes())
        complete = scheduler.telemetry_dict()
        self.assertEqual(complete["packets_sent"], 2)
        self.assertEqual(complete["packets_remaining"], 0)
        self.assertEqual(complete["state"]["phase"], "complete")
        self.assertEqual(complete["state"]["next_step"], None)
        self.assertNotIn("object_id", str(complete))

        decision_queue = MobMovementBroadcastDecisionQueue(
            fixture_gameplay_transcript(compact_transition=True),
            (automatic_plan,),
            follow_up_targets=((2, 350, -200, 8),),
            evidence_transcript=evidence,
            planning_context=planning_context,
            baseline_server_frames=(post_spawn,),
        )
        queued = decision_queue.telemetry_dict()
        self.assertEqual(queued["packets_planned"], 1)
        self.assertEqual(queued["packets_sent"], 0)
        self.assertEqual(
            queued["state"]["decision_queue"],
            {
                "max_follow_up_decisions": 8,
                "decisions_total": 2,
                "decisions_planned": 1,
                "decisions_completed": 0,
                "decisions_remaining": 2,
                "active_decision_index": 1,
                "planning_decision_index": None,
                "relative_policy": None,
                "next_policy_target": None,
                "pending_targets": [
                    {
                        "decision_index": 2,
                        "max_steps": 2,
                        "x": 350,
                        "y": -200,
                        "foothold_id": 8,
                    }
                ],
            },
        )
        self.assertEqual(
            decision_queue.next_plaintext,
            automatic_plan.broadcast.to_bytes(),
        )

        decision_queue.confirm_sent(decision_queue.next_plaintext)
        planning = decision_queue.telemetry_dict()
        self.assertEqual(planning["packets_planned"], 1)
        self.assertEqual(planning["packets_sent"], 1)
        self.assertEqual(planning["packets_remaining"], 0)
        self.assertEqual(planning["state"]["phase"], "planning")
        self.assertEqual(planning["state"]["next_step"], None)
        self.assertEqual(
            planning["state"]["decision_queue"][
                "planning_decision_index"
            ],
            2,
        )
        self.assertEqual(
            decision_queue.planning_server_frames,
            (
                post_spawn,
                automatic_plan.broadcast.to_bytes(),
            ),
        )

        with patch(
            "maple_server.gameplay.analyze_gameplay_transcript",
            side_effect=AssertionError("cached planning refolded a transcript"),
        ):
            decision_queue.plan_next_decision()
        replanned = decision_queue.telemetry_dict()
        self.assertEqual(replanned["packets_planned"], 3)
        self.assertEqual(replanned["packets_sent"], 1)
        self.assertEqual(replanned["packets_remaining"], 2)
        self.assertEqual(replanned["state"]["phase"], "in_progress")
        self.assertEqual(
            replanned["state"]["current"],
            {
                "x": 250,
                "y": -200,
                "foothold_id": 8,
                "stance": automatic_plan.stance,
            },
        )
        self.assertEqual(
            replanned["state"]["next_step"]["decision_index"], 2
        )
        self.assertEqual(
            replanned["state"]["next_step"]["predicted"]["x"], 300
        )
        self.assertEqual(
            replanned["state"]["last_sent_step"]["decision_index"], 1
        )
        self.assertEqual(
            (
                decision_queue.active_schedule.steps[0].previous_x,
                decision_queue.active_schedule.steps[0].target_x,
            ),
            (250, 300),
        )

        while decision_queue.next_plaintext is not None:
            decision_queue.confirm_sent(decision_queue.next_plaintext)
        queue_complete = decision_queue.telemetry_dict()
        self.assertEqual(queue_complete["packets_sent"], 3)
        self.assertEqual(queue_complete["packets_remaining"], 0)
        self.assertEqual(queue_complete["state"]["phase"], "complete")
        self.assertEqual(queue_complete["state"]["next_step"], None)
        self.assertEqual(
            queue_complete["state"]["decision_queue"][
                "decisions_completed"
            ],
            2,
        )
        self.assertEqual(
            queue_complete["state"]["current"]["x"], 350
        )
        with self.assertRaisesRegex(ValueError, "exceeds its limit"):
            MobMovementBroadcastDecisionQueue(
                fixture_gameplay_transcript(compact_transition=True),
                (automatic_plan,),
                follow_up_targets=(
                    ((2, 350, -200, 8),)
                    * (MAX_MOB_MOVEMENT_FOLLOW_UP_DECISIONS + 1)
                ),
                evidence_transcript=evidence,
                baseline_server_frames=(post_spawn,),
            )

        relative_policy = MobMovementRelativeDecisionPolicy(
            decision_count=2,
            max_steps=2,
            displacement_x=100,
            displacement_y=0,
            foothold_id=8,
        )
        policy_queue = MobMovementBroadcastDecisionQueue(
            fixture_gameplay_transcript(compact_transition=True),
            (automatic_plan,),
            follow_up_policy=relative_policy,
            evidence_transcript=evidence,
            planning_context=planning_context,
            baseline_server_frames=(post_spawn,),
        )
        self.assertEqual(
            policy_queue.safe_dict()["decision_queue"]["relative_policy"],
            relative_policy.safe_dict(),
        )
        policy_queue.confirm_sent(policy_queue.next_plaintext)
        self.assertEqual(
            policy_queue.safe_dict()["decision_queue"][
                "next_policy_target"
            ]["x"],
            350,
        )
        for expected_target_x in (350, 450):
            with patch(
                "maple_server.gameplay.analyze_gameplay_transcript",
                side_effect=AssertionError(
                    "relative policy planning refolded a transcript"
                ),
            ):
                policy_queue.plan_next_decision()
            self.assertEqual(
                policy_queue.active_schedule.steps[-1].target_x,
                expected_target_x,
            )
            while policy_queue.next_plaintext is not None:
                policy_queue.confirm_sent(policy_queue.next_plaintext)
        policy_complete = policy_queue.telemetry_dict()
        self.assertEqual(policy_complete["packets_sent"], 5)
        self.assertEqual(policy_complete["state"]["phase"], "complete")
        self.assertEqual(policy_complete["state"]["current"]["x"], 450)
        self.assertEqual(
            policy_complete["state"]["decision_queue"][
                "decisions_completed"
            ],
            3,
        )
        sequence_fold = analyze_gameplay_transcript(
            fixture_gameplay_transcript(
                extra_server_plaintexts=(
                    post_spawn,
                    *(
                        broadcast.to_bytes()
                        for broadcast in sequence_plan.broadcasts
                    ),
                )
            )
        )
        self.assertTrue(sequence_fold.valid)
        self.assertEqual(
            (
                sequence_fold.state.mobs[MOB_OBJECT_ID].x,
                sequence_fold.state.mobs[MOB_OBJECT_ID].y,
            ),
            (300, -200),
        )
        baseline_fold = analyze_gameplay_transcript(
            fixture_gameplay_transcript()
        )
        self.assertEqual(
            sequence_fold.state.mob_movement_broadcasts,
            baseline_fold.state.mob_movement_broadcasts + 2,
        )
        self.assertEqual(
            sequence_fold.state.mob_broadcast_commands,
            baseline_fold.state.mob_broadcast_commands + 6,
        )

        def two_command_path(displacement_x: int) -> bytes:
            midpoint_x = 100 + displacement_x // 2
            return MobMovementBroadcast(
                object_id=MOB_OBJECT_ID,
                opaque_control=b"\x00\x00\xff\x00\x00\x00\x00",
                reference_x=100,
                reference_y=-200,
                commands=(
                    MobMovementCommand.absolute(
                        position_x=midpoint_x,
                        position_y=-200,
                        velocity_x=displacement_x // 2,
                        velocity_y=0,
                        foothold_id=7,
                        stance=2,
                        duration_ms=540,
                    ),
                    MobMovementCommand.absolute(
                        position_x=100 + displacement_x,
                        position_y=-200,
                        velocity_x=displacement_x // 2,
                        velocity_y=0,
                        foothold_id=7,
                        stance=2,
                        duration_ms=540,
                    ),
                ),
            ).to_bytes()

        ambiguous_sequence_evidence = fixture_gameplay_transcript(
            extra_server_plaintexts=(
                source_path,
                two_command_path(40),
                two_command_path(60),
            )
        )
        with self.assertRaisesRegex(ValueError, "ambiguous shortest"):
            plan_composed_mob_movement_broadcasts(
                fixture_gameplay_transcript(compact_transition=True),
                post_transcript_server_frames=(post_spawn,),
                evidence_transcript=ambiguous_sequence_evidence,
                target_x=300,
                target_y=-200,
                foothold_id=8,
                max_steps=2,
            )
        with self.assertRaisesRegex(ValueError, "no monotonic composed path"):
            plan_composed_mob_movement_broadcasts(
                fixture_gameplay_transcript(compact_transition=True),
                post_transcript_server_frames=(post_spawn,),
                evidence_transcript=evidence,
                target_x=350,
                target_y=-200,
                foothold_id=8,
                max_steps=2,
            )

        alternate_path = MobMovementBroadcast(
            object_id=MOB_OBJECT_ID,
            opaque_control=b"\x00\x00\xff\x00\x00\x00\x00",
            reference_x=100,
            reference_y=-200,
            commands=(
                MobMovementCommand.absolute(
                    position_x=125,
                    position_y=-200,
                    velocity_x=25,
                    velocity_y=0,
                    foothold_id=7,
                    stance=2,
                    duration_ms=600,
                ),
                MobMovementCommand.absolute(
                    position_x=150,
                    position_y=-200,
                    velocity_x=25,
                    velocity_y=0,
                    foothold_id=7,
                    stance=2,
                    duration_ms=480,
                ),
            ),
        ).to_bytes()
        ambiguous_evidence = fixture_gameplay_transcript(
            extra_server_plaintexts=(source_path, alternate_path)
        )
        with self.assertRaisesRegex(ValueError, "ambiguous relative motion"):
            plan_mob_movement_broadcast(
                fixture_gameplay_transcript(compact_transition=True),
                post_transcript_server_frames=(post_spawn,),
                evidence_transcript=ambiguous_evidence,
                target_x=250,
                target_y=-200,
                foothold_id=8,
                auto_select_captured_path=True,
            )

        with self.assertRaisesRegex(ValueError, "no multi-command path"):
            plan_mob_movement_broadcast(
                fixture_gameplay_transcript(compact_transition=True),
                post_transcript_server_frames=(post_spawn,),
                evidence_transcript=evidence,
                target_x=251,
                target_y=-200,
                foothold_id=8,
                auto_select_captured_path=True,
            )

        with self.assertRaisesRegex(ValueError, "translated path reference"):
            plan_mob_movement_broadcast(
                fixture_gameplay_transcript(compact_transition=True),
                post_transcript_server_frames=(
                    MobEnterField(
                        object_id=MOB_OBJECT_ID,
                        spawn=fixture_mob_spawn(),
                    ).to_bytes(),
                ),
                evidence_transcript=evidence,
                target_x=250,
                target_y=-200,
                foothold_id=7,
                path_evidence_server_frame_index=source_frame,
            )

    def test_movement_acknowledgement_policy_rejects_unknown_field_mob(
        self,
    ) -> None:
        policy = derive_mob_movement_acknowledgement_policy(
            fixture_gameplay_transcript()
        )
        unknown_submission = MobMovementSubmission(
            object_id=MOB_OBJECT_ID + 1,
            sequence=10,
            opaque_movement=fixture_movement_path().to_bytes(),
        )

        with self.assertRaisesRegex(ValueError, "no explicit field-local"):
            policy.acknowledge(unknown_submission)

    def test_movement_acknowledgement_policy_retains_template_after_leave(
        self,
    ) -> None:
        policy = derive_mob_movement_acknowledgement_policy(
            fixture_gameplay_transcript(leave_mob=True)
        )
        submission = MobMovementSubmission(
            object_id=MOB_OBJECT_ID,
            sequence=10,
            opaque_movement=fixture_movement_path().to_bytes(),
        )

        self.assertEqual(policy.safe_dict()["active_known_mob_count"], 0)
        self.assertEqual(policy.safe_dict()["field_known_mob_count"], 1)
        self.assertEqual(policy.acknowledge(submission).status_value, 35)

    def test_movement_acknowledgement_policy_rejects_capture_rule_mismatch(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValueError, "packet/state validation"):
            derive_mob_movement_acknowledgement_policy(
                fixture_gameplay_transcript(acknowledgement_flag=1)
            )
        with self.assertRaisesRegex(ValueError, "packet/state validation"):
            derive_mob_movement_acknowledgement_policy(
                fixture_gameplay_transcript(acknowledgement_auxiliary_1=1)
            )

    def test_mob_leave_removes_known_active_entity(self) -> None:
        analysis = analyze_gameplay_transcript(
            fixture_gameplay_transcript(leave_mob=True)
        )

        self.assertTrue(analysis.valid)
        self.assertEqual(len(analysis.state.mobs), 0)
        self.assertEqual(analysis.state.mob_leaves, 1)
        leave_event = next(
            event for event in analysis.events if event.kind == "mob_left_field"
        )
        self.assertTrue(leave_event.details["known_entity"])

    def test_repeated_npc_update_has_the_predicted_field_local_delta(self) -> None:
        baseline = analyze_gameplay_transcript(fixture_gameplay_transcript())
        injected = analyze_gameplay_transcript(
            fixture_gameplay_transcript(repeat_npc_update=True)
        )

        self.assertTrue(baseline.valid)
        self.assertTrue(injected.valid)
        self.assertEqual(len(injected.state.npcs), len(baseline.state.npcs))
        self.assertEqual(injected.state.phase, baseline.state.phase)
        self.assertEqual(
            injected.state.npc_state_updates,
            baseline.state.npc_state_updates + 1,
        )
        self.assertEqual(len(injected.events), len(baseline.events) + 1)

    def test_plans_identifier_free_final_field_npc_state_replay(self) -> None:
        plan = plan_final_field_npc_state_replay(
            fixture_gameplay_transcript(terminate=True)
        )

        self.assertEqual(
            plan.update,
            NpcStateUpdate(
                object_id=NPC_OBJECT_ID,
                action=3,
                parameter=1,
            ),
        )
        self.assertEqual(plan.field_epoch, 1)
        self.assertEqual(
            plan.safe_dict(),
            {
                "entity": "npc:1",
                "field_epoch": 1,
                "action": 3,
                "parameter": 1,
                "prediction": {
                    "npc_state_updates_delta": 1,
                    "events_delta": 1,
                    "active_npc_count_delta": 0,
                    "phase": "unchanged",
                },
            },
        )
        self.assertNotIn(str(NPC_OBJECT_ID), str(plan.safe_dict()))

    def test_terminal_packet_changes_phase_and_is_discoverable_for_omission(
        self,
    ) -> None:
        transcript = fixture_gameplay_transcript(terminate=True)
        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.state.phase, GameplayPhase.TERMINATED)
        self.assertTrue(analysis.state.termination_received)
        self.assertEqual(
            world_session_termination_frame_index(transcript),
            analysis.decoded.frames[-1].direction_index,
        )
        self.assertIn(
            "world_session_termination_received",
            [event.kind for event in analysis.events],
        )

    def test_live_partial_transcript_does_not_emit_session_ended(self) -> None:
        analysis = analyze_gameplay_transcript(
            fixture_gameplay_transcript(close=False)
        )

        self.assertFalse(analysis.transport_closed)
        self.assertNotIn(
            "session_ended", [event.kind for event in analysis.events]
        )

    def test_termination_discovery_rejects_capture_without_terminal_packet(
        self,
    ) -> None:
        with self.assertRaisesRegex(PacketShapeError, "no server opcode-9"):
            world_session_termination_frame_index(
                fixture_gameplay_transcript(terminate=False)
            )

    def test_heartbeat_correlation_rejects_reversed_temporal_interpretation(
        self,
    ) -> None:
        transcript = fixture_gameplay_transcript()
        events = list(transcript.events)
        probe_event = events[-3]
        response_event = events[-2]
        events[-3] = replace(
            response_event, timestamp_ns=probe_event.timestamp_ns
        )
        events[-2] = replace(
            probe_event, timestamp_ns=response_event.timestamp_ns
        )

        analysis = analyze_gameplay_transcript(
            Transcript(path=transcript.path, events=tuple(events))
        )

        self.assertEqual(analysis.state.matched_heartbeat_responses, 0)
        self.assertEqual(analysis.state.unmatched_heartbeat_responses, 1)
        self.assertEqual(analysis.state.pending_heartbeat_probes, 1)
        self.assertEqual(len(analysis.warnings), 2)

    def test_opcode_426_correlation_rejects_reversed_order(self) -> None:
        transcript = fixture_gameplay_transcript(
            opcode_426_acknowledgement=True
        )
        events = list(transcript.events)
        notification_event = events[-5]
        acknowledgement_event = events[-4]
        events[-5] = replace(
            acknowledgement_event,
            timestamp_ns=notification_event.timestamp_ns,
        )
        events[-4] = replace(
            notification_event,
            timestamp_ns=acknowledgement_event.timestamp_ns,
        )

        analysis = analyze_gameplay_transcript(
            Transcript(path=transcript.path, events=tuple(events))
        )

        self.assertEqual(
            analysis.state.matched_opcode_309_acknowledgements, 0
        )
        self.assertEqual(
            analysis.state.unmatched_opcode_309_acknowledgements, 1
        )
        self.assertEqual(analysis.state.pending_opcode_426_notifications, 1)
        self.assertEqual(len(analysis.warnings), 2)


if __name__ == "__main__":
    unittest.main()
