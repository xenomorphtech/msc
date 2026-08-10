# Status as of 2026-08-10

## Working

- The complete client and NGM are installed in the dedicated Wine prefix and
  render inside nested Sway/Xwayland on display `:1`.
- The persistent browser session and CDP helper have issued fresh authenticated
  HK launch tickets without printing credentials or ticket contents. The
  temporary Beanfun `01004` condition cleared after forcing a fresh login,
  hard-reloading the authenticated main page, and delaying both authorization
  clicks; repeated fresh tickets now succeed.
- The `mapleproxy` namespace transparently relays ordinary TCP and redirects
  login port `10282` to local port `12082` and handoff port `58880` to `12080`.
- Lossless JSONL capture, strict/non-strict replay, frame patching, IV-correct
  server-frame omission, reactive opcode replies, hold-open, and independently
  timed post-transcript frames are implemented.
- PCAP TCP reassembly, Maple endpoint identification, frame normalization,
  private PCAP-frame sourcing/transforms, and per-opcode reactive response
  timing are implemented.
- Protocol-300 greeting parsing, encrypted-frame framing, Maple AES payload
  encryption/decryption, and IV shuffling are implemented and tested.
- Login logs now fold into typed game state with full/partial/unknown/invalid
  shape confidence. The successful reference ends at validated
  `handoff_ready` state.
- The custom-server suite currently passes all 219 tests.
- The client accepts the custom NGS challenge, returns native opcode `13`, and
  accepts the synthetic opcode-`13` acknowledgment.
- GDB transition probes reached real world-selection and character-selection
  scenes, proving login controller states `1` and `2` respectively.
- The captured 12-byte server frame at index `3` is the source of the policy
  dialog: its plaintext is opcode `0` with result `2`. Replacing only that
  frame with a heartbeat removes the dialog.
- A 128-byte zero-filled opcode-`1` success payload can run the original account
  handler, initialize its world staging list, and reach the world-selection UI.
- The opcode-`2` world parser and its UTF-16 string terminator bytes have been
  recovered sufficiently to build a structurally valid one-world/one-channel
  packet. Dual transparent process-local trampolines confirm that both the
  handler and parser run without leaving GDB attached. The parsed world is
  retained in the controller wrapper's backing list with count `1`, name
  `test`, and one channel named `test-1`.
- A fresh official reference was captured through the added unrestricted HK
  SOCKS5 proxy. Its login stream contains 1,377 client bytes and 22,092 server
  bytes, followed by the expected `58880` exchange. The official account still
  receives the policy-restriction result before gameplay.
- Repository-root `./111.pcapng` supplies a separate successful
  protocol-compatible reference: login stream `83` and world stream `92`.
- Repository-root `./1-10FS.pcapng` supplies 55 minutes of level-1-to-10
  gameplay on stream `126`. PCAP normalization trims its measured 14-byte
  server and 28-byte client transport preludes before the ordinary Maple
  greeting, then decrypts 71,100 frames. The fold now recognizes its
  marker-`26` level-1 character/inventory snapshot, 36 total field epochs, 436
  drop spawns, and all 197 pickup requests with known drops and matching
  epochs. Variable NPC-state and stage-`0` field-load tails are losslessly
  bounded as partial. Strict decoding now succeeds across all 71,100 frames:
  26,661 full, 44,381 partial, 58 unknown-but-lossless, and zero invalid
  packet observations. Stream `92` now reports 13,417 full, 21,782 partial,
  8 unknown, and zero invalid; stream `114` reports 54/22/0/0. Seven
  long-corpus state-correlation warnings remain: six pickup-effect mismatches
  plus one aggregate warning for six one-HP combat prediction differences.
- Server opcodes `69`, `93`, `94`, `137`, `148`, `201`, `205`, `276`, and
  `379` are separated into neutral, capture-bounded records. All 181 reference
  packets consume and round-trip exactly; typed branches add 81 full
  observations, while the 100 records with fixed unknown regions remain
  partial and redact potentially identifying primary values from safe state,
  events, reports, and HTTP-derived analysis.
  The automatic IL2CPP dump proves opcode `94` reads `bool + i32 + i32` and
  opcode `379` reads a discriminator plus four datetimes on variant `36`; its
  delegated opcode-`148` handler supplies variants `9`/`10`/`12`/`13`. One
  legacy nonempty variant-`9` body remains explicitly opaque because it does
  not consume under the current build's mask `0x9`.
  A typed opcode-`94` live replay produced exactly one predicted neutral event,
  changed no modeled world/player/inventory/progression state, and left the
  browser-free client active with 244/244 heartbeat probes matched.
  A fresh direct-Wayland replay of empty opcode-`148` variant `10` likewise
  produced one full neutral event, left core state unchanged, advanced matched
  heartbeats from 11 to 18, and retained one active connection with no failures.
- Server opcodes `147` and `272` now use the automatic IL2CPP packet dump as
  their shape source rather than the older observed-opaque width pins. Opcode
  `147` is two four-`i32` rectangles plus a counted `i32` vector. A focused
  live primitive-reader trace closes opcode `272` as a neutral header, 11
  counted entries with two booleans and two counted triple groups, and one
  terminal `i32`. The three packets for each opcode are byte-identical across
  streams `92`, `114`, and `126`; all six round-trip natively and fold at full
  coverage with identifiers and values redacted. Two exact live opcode-`272`
  injections were accepted; the
  current transcript folds the original plus both injections as three full
  events, remains `active` on map `101000000`, keeps core state unchanged, and
  runtime status reports one active connection, zero injection failures, and
  advancing heartbeat responses. The debugger pause accounts for the one
  36.6-second heartbeat outlier.
- Server opcodes `27`, `28`, `142`, and `425` now replace their generated
  capture-width pins with seven exact semantic shapes. The generated handlers
  prove the leading `i32` counts for `27`/`28` and the boolean gate for `142`;
  cross-corpus exact parsing closes their repeated integer/text records. Three
  byte-identical opcode-`425` packets have a `u16` count of 12 and a fixed
  four-`i32` trailer; a live handler trace independently observed exactly 12
  repeated `i32` reads. All 13 relevant private-regression packets validate
  natively and round-trip through the Python codecs. Safe events expose only
  counts, text lengths, booleans, and the neutral trailer while redacting text,
  keys, and values. An exact live opcode-`425` injection produced the predicted
  second full ledger event without changing phase, map `101000000`, player,
  inventory, or progression state. A fresh browser-free direct-Wayland launch
  is back in the field with the programmatic audio-mute service active and one
  healthy world connection.
- Server opcodes `228`, `230`, `231`, `232`, `234`, and `235` share one
  generated-handler boundary: each reads exactly one leading `u32`, while the
  12 captured packets retain opcode/width-specific ignored tails. Seven
  semantic width declarations and one redacted Python envelope now preserve
  and re-emit the `1/3/4/6/7/16/20`-byte tails exactly. All 12 packets pass the
  native and Python round-trip validators; the fold emits neutral events and
  marks them partial, because the tail bytes have no handler-backed semantics.
  Primary values and tails are omitted from safe analysis. Cross-state live
  replay is intentionally deferred because the leading value may be a
  session-local identifier and the ignored tails are not yet typed.
- Server opcode `276` is now a full automatic-dump-backed boolean record. Its
  two captured payloads use raw byte `0x05`; ISIL proves the pinned reader calls
  `BitConverter.ToBoolean`, so the shared native validator now treats every
  nonzero byte as true and the typed codecs preserve noncanonical raw bytes for
  exact re-emission. The two packets validate and fold at full coverage,
  raising stream `92` to `13,411/21,760/36/0` and stream `114` to
  `50/20/6/0`. Exact live replay produced the predicted second neutral event,
  left the core-state digest, active phase, map `101000000`, and field epoch
  unchanged, and was followed by matched heartbeats with no pending probe or
  injection failure. The nested-Sway client stayed focused and its mute service
  remained active.
- Server opcode `137` now uses the automatic handler's direct `i16/i32/i32`
  prefix followed by the capture-bounded 72-byte tail shared by all three
  84-byte packets. The codec redacts both prefix and tail, round-trips all three
  packets, and folds them as partial neutral events. This moves stream `92` to
  `13,411/21,762/34/0` and stream `126` to `26,659/44,381/60/0`; live replay is
  deferred because neither the values nor delegated tail have safe
  cross-session semantics.
- Server opcode `169` now uses the automatic handler's selector dispatch rather
  than an opaque width. Native jump-table arm `3` reads exactly one
  trailing-zero UTF-16 value and returns; the sole 54-byte stream-`126` packet
  is consumed exactly with 24 code units. The redacted codec emits one full
  `server_opcode_169_text_instruction_received` event at field epoch `31` and
  publishes only selector and text length. This moves stream `126` to
  `26,660/44,381/59/0`. Live replay is deferred because the captured text is a
  client resource instruction whose cross-field effect is not yet bounded.
- Server opcode `29` now closes the automatic dump's otherwise empty direct-read
  boundary by following its delegated constructors. The outer constructor at
  `0x180CB4390` reads a `u8` count; each record constructor at `0x180CB3F20`
  reads `i32/i32`, one trailing-zero UTF-16 value, `i32`, and `i16`. The
  byte-identical 327-byte packets in streams `92` and `114` each contain four
  records with 128 total text code units and consume exactly. The redacted
  codec round-trips both packets, folds them as full
  `server_opcode_29_text_ledger` observations, and emits
  `server_opcode_29_ledger_received` without exposing text or numeric values.
  At that decoder checkpoint, strict coverage moved to
  `13,412/21,762/33/0` and
  `51/20/5/0`; stream `126` remains `26,660/44,381/59/0`. Live replay is
  deferred until the neutral bootstrap values have a bounded cross-session
  role.
- Server opcode `135` is no longer a 3,725-byte opaque bootstrap packet. The
  generated handler `aecdc2fe...` identified the four possible primitive
  readers, and a detachable trace on the local Wine client recorded 1,305
  ordered `u8/bool/i32` calls from framed cursor `6` through `3729`. The 45
  remaining cursor gaps are each exactly two bytes and align with the generated
  `i16` reader, yielding a 1,350-read, four-section grammar. The sole stream-`114`
  packet round-trips exactly with section totals `2/166`, `2/21`, `10`, and
  `21/260/260`. It now folds as a full
  `server_opcode_135_bootstrap_ledger`, emits
  `server_opcode_135_ledger_received`, and publishes only counts and redaction
  flags. Stream `114` moves to `52/20/4/0`. An exact replay through the
  loopback packet API was processed by the local Wine client without dropping
  the world socket or heartbeat exchange; numeric roles remain neutral because
  no bounded visible effect was observed.
- Server opcode `13` now folds the handler-confirmed discriminator plus the
  capture-bounded `uint32` body length for server types `7`, `12`, and `14`.
  All 23 server packets in `111.pcapng` consume and round-trip exactly; the
  level-1-to-10 capture has no server packet in this direction. Safe state and
  `server_opcode_13_message_received` events expose only type/body-length
  distributions and a redaction flag. The 20 stream-`92` and two stream-`114`
  packets move from unknown to partial, producing `13,412/21,782/13/0` and
  `52/22/2/0`. Opaque bodies are not replayed.
- Server opcode `394` and client opcode `279` now use exact redacted text
  envelopes instead of opaque width pins. The automatic dump confirms the
  server enum member but attributes no managed handler; the sole capture pair
  supplies the exact `u16-counted UTF-16 + zero` boundaries. Both texts contain
  57 code units, only indices `10..14` differ, and the client envelope follows
  by 57.92 ms. The fold reports this as neutral temporal correlation, not a
  proven request/response, and moves stream `92` to
  `13,414/21,782/11/0`. An exact loopback injection into the sole local-Wine
  world connection produced no opcode `279` within seven seconds, while the
  client remained responsive in map `101000000`; opcode `394` is not required
  by the current login/gameplay path.
- Client opcode `75` is now a full opcode-only field-bootstrap marker, observed
  once in both sustained captures and independently in the running local-Wine
  transcript at field epoch `1`. The two `111` world sessions also prove a
  repeated exit transaction: empty client opcode `241`, redacted-u32 client
  status opcode `46`/`45` after 64.396/66.699 ms, and final server opcode `9`
  after 165.073/167.004 ms. The gamestate now enters `exit_requested`, tracks
  the redacted status, and correlates the terminal transition. Coverage becomes
  `13,417/21,782/8/0`, `54/22/0/0`, and `26,661/44,381/58/0` for streams
  `92`, `114`, and `126`. The current game-menu attempt emitted no opcode `241`,
  so live terminal replay remains unclaimed.
- Client/server opcode `43` now uses two redacted client envelopes and one
  fixed server envelope instead of a sequence-keyed stream-specific switch.
  All 45 client and three server packets across streams `92` and `126`
  round-trip exactly as partial observations; sequence, variant, text length,
  message type, and opaque-byte counts are safe, while identifiers, text, and
  bodies remain omitted. An exact server packet live replay left core state
  unchanged, advanced matched heartbeats `173 -> 176`, retained one active
  connection with zero failures, and produced no client opcode-`43` response.
- Client opcode `114` now consumes and round-trips all 44 long-corpus packets
  as a redacted `u8 + counted UTF-16 + zero + u32` envelope. Text lengths
  `8/9/11` explain the exact `26/28/32` packet widths. Safe state/events expose
  only control and text-length distributions plus an omitted-value count;
  indirect tutorial/UI timing is documented as a hypothesis, not a semantic
  name. The active idle custom-server client emits none, so no reverse-direction
  replay is claimed.
- Server opcodes `189`/`190` now establish remote-player entry/removal state.
  All 114 entries and 39 leaves round-trip exactly, every leave matches the
  current field epoch, and all opcode-`202`/`217` movement broadcasts now
  reference a prior entry. A browser-free direct-Wayland A/B/A live test moved,
  removed, and restored the expected sprite while the folded active count
  followed `4 -> 3 -> 4` and the client remained active.
- Server opcode `224` is now an exact 22-byte remote-player/mob-template value
  record. All 20 stream-`126` and nine stream-`92` packets round-trip at full
  coverage; every primary id names an active remote player and every template
  names at least one active mob. Marker `0xff`, flag `0`/`1`, reserved u16 zero,
  and repeated-value equality are enforced. The player id is aliased/redacted,
  while the value remains neutrally named pending live-effect evidence.
- Server opcodes `285`/`286` now form a capture-bounded single-bit mob
  temporary-stat set/reset pair. All ten sets and five resets in stream `92`
  round-trip exactly and reference active template-`3210800` mobs. Every set
  matches the target and skill id of the preceding opcode-`219` relay within
  two server frames; the fold records three refreshes, three modeled resets,
  two capture-preexisting resets, and four leave-time clears. Source-level and
  duration units remain neutral, and no live visual/status effect is claimed.
- Server opcode `247` is fully decoded as a tutorial-UI instruction with
  redacted terminated UTF-16 text, two signed 16-bit values, a control byte,
  and an optional signed-32 pair confirmed by the pinned handler. All 33
  stream-`126` packets are full-coverage exact round trips. Two exact packets
  were accepted and folded by the active live client without blocking it; no
  overlay appeared in samples through one second, so visual rendering remains
  explicitly state-gated rather than inferred from packet acceptance.
- Server opcode `244` selector `8` is fully decoded as three signed int32
  values after the selector. All 54 stream-`126` packets are exact full-
  coverage round trips. A fresh browser-free injection of captured values
  `1036, 2003, 0` opened an instructional NPC dialogue whose text progressed
  from partial at 100 ms to complete at one second. The live transcript folds
  one exact `instructional_dialogue_requested` event, stays active on map
  `101000000`, and matches all 11 heartbeat pairs without assigning meanings
  to the three numeric values.
- Server opcodes `320`/`322`/`323` are exact positioned-effect records with an
  aliased primary key, typed i16 coordinates, and neutral controls. All 82
  stream-`126` packets round-trip at full coverage, producing 36 field-scoped
  aliases and 46 updates with no unknown opcode-`323` update. In the live A/B,
  an exact off-screen opcode-`322` had no visible effect; changing only its
  coordinates to the folded player position produced a transient blue `10`
  over the sprite at 100 ms, gone by one second. The pair folded as one alias
  and one update at `(633,-2677)`, HP stayed `50/222`, and 131/131 heartbeats
  matched.
- Server opcode `302` is now a typed NPC lifecycle control. All 36 stream-`126`
  packets are 23-byte control-`1` spawns whose body is exactly the final 16
  bytes of opcode `300`; they round-trip at full coverage and establish the
  NPCs referenced by later opcode-`303` updates. The pinned client handler
  confirms the common control/object-id prefix and a no-reader alternate
  branch. A canonical seven-byte control-`0` removal is modeled and unit-tested,
  while remaining explicitly absent from the reference PCAPs and not yet
  live-proven. One live composed control-`1` packet was accepted, folded the
  active NPC count from nine to ten, and left all 360 heartbeat pairs matched
  until the configured one-hour replay hold expired.
- Server opcode `239` now has full structural coverage for every observed
  selector branch. Stream `126` supplies 29 selector-`3` record lists with 38
  u32/i32 members, 27 empty selector-`9` packets, two empty selector-`13`
  packets, and one selector-`21` terminated counted UTF-16 packet; stream `92`
  adds one empty selector-`13` packet. All 60 reference packets round-trip and
  fold exactly. Record keys and text are retained only for re-emission and are
  redacted from safe state/events/reports/HTTP; the handler-backed selector
  dispatch does not justify a higher-level semantic or live-effect claim.
- Server opcode `348` now has full, redacted structural coverage for all 31
  stream-`126` packets. The pinned handler and capture agree on a common
  u8/i32/selector/i32 prefix plus terminated counted UTF-16 text; selector `0`
  has two trailing control bytes, while selectors `3`/`6`/`17` do not. Every
  packet round-trips exactly. State/events/reports/HTTP omit the primary values
  and text, and future selectors stay unknown.
- Client opcode `66` now gives those 31 envelopes a complete capture-local
  transaction model. Every server packet is followed by exactly one
  same-selector response; 25 packets are four-byte selector/status records and
  six selector-`6`/status-`1` packets add one redacted u32. Native shape
  validation and Python parsing consume all 31 exactly, while the gamestate
  fold reports 31 matched, zero unmatched, zero pending, and round trips from
  `728.174` to `10,436.006` ms. A cross-state live replay of one exact
  selector-`0` server packet into the active level-12 short-stream client
  produced no opcode `66` and the world connection closed after one further
  heartbeat. The browser-free launcher/direct Wayland seat restored the client
  to an active field with 719/719 matched heartbeats; opcode `348` therefore
  remains state-gated rather than generally replay-safe.
- Client opcode `122` now has full structural coverage for all 62 stream-`126`
  packets. The six observed selector/count shapes contain two to four u32
  values; selector `2` always ends in `0xffffffff`. Every packet round-trips
  byte-for-byte and folds into selector/shape counters plus one redacted event.
  The values remain available only to the lossless packet object, never safe
  state/events/reports/HTTP, and unobserved selector/count shapes stay unknown.
- The level-1-to-10 corpus expands opcode-`41` to all observed level, job,
  primary-stat, current/max HP/MP, AP/SP, EXP, and mesos masks. All 841 stat
  packets round-trip and the fold ends at level `10`, job `200`, HP `114/194`,
  MP `158/285`, EXP `980`, and mesos `1472`.
- The same corpus expands opcode-`39` to equipment adds, cash-tab stack adds,
  and operation-`2` equip moves. All 256 change sets and 232 modifications
  decode and fold with zero unknown-slot mutations. Its 78 opcode-`300` NPC
  spawns also validate after preserving the facing byte values `0/1/2/4/5`.
- The common fixed-width server family now has complete typed codecs for
  opcodes `11`, `24`, `45`, `56`, `58`, `59`, `60`, `71`, `72`, `74`, `76`,
  `89`, `96`, `105`, `112`, `121`, `131`, `178`, `301`, `386`, `388`, `389`,
  and `398`. Streams `114`, `92`, and `126` contain 21, 69, and 94 full records
  respectively. Opcode `60` adds six signed-`i32` long-corpus records; opcode
  `59` matches world-entry character state, and all other value roles remain
  neutral.
- `--generate-fixed-server-records` reconstructs every such occurrence,
  validates reparse/length/index/patch invariants, and exposes identifier-free
  plans under `protocol.fixed_server_record_emitter`. A browser-free live run
  composed its 11 stream-`114` frames with the initial snapshot and nine NPC
  emitters; the client rendered map `101000000`, and transcript
  `fixed_server_emitter_live_20260809/world/1786313433938476085_replay_12857.jsonl`
  folds validly to `active`, one matching character context, nine NPCs, and
  paired heartbeats.
- Opcodes `156` and `385` now have fully typed compact/expanded branches.
  Stream `126` has three-byte variants `156:0`/`385:1`; streams `92` and `114`
  have `156:1` as packet UTF-16 text, bool, and three int32 values, plus
  `385:0` as exactly 89 `uint8 selector, int32 value` entries. Short live GDB
  traces and exact capture round trips close both former opaque tails without
  assigning security semantics. A controlled A/B/A further proves opcode-`385`
  tuple indices are keyboard key codes, selector `1` is a skill binding, and
  index `29` is evdev Left Ctrl.
- `--generate-variable-server-records` regenerates those records with exact
  reparse/length/index/conflict checks. A browser-free live run patched stream
  `114` frames `9` and `11` together with the initial, fixed, and NPC emitters.
  The client rendered map `101000000`; transcript
  `variable_server_emitter_live_20260809/world/1786314493694015926_replay_12857.jsonl`
  folds validly to `active`, both expected variants, 89 entries, three typed
  values, zero opaque bytes, nine NPCs, and paired heartbeats.
- Replay mode has an opt-in loopback `POST /api/v1/server-packets` endpoint.
  It is disabled by default, requires `--enable-http-packet-injection`, exactly
  one active replay connection, bounded exact JSON, and serializes encryption
  and writes with heartbeats/reactive responses. Safe status exposes counters
  but never packet bytes. Exact live `385:0` and `156:1` injections left the
  client active on map `101000000` at HP `50/222`, MP `97/342`, with 110/110
  heartbeats; the transcript folds to four variable events, 178 entries, six
  typed values, zero opaque bytes, and two injection events.
- `inject-current-hp` now turns that raw endpoint into a typed, observed live
  experiment. It plans opcode `41` from the active transcript, restricts the
  target to the fixed loopback packet route, injects it, and polls until the
  decoded fold proves exactly one stat update with phase, field epoch, map,
  inventory, and progression unchanged. On transcript
  `neutral_records_live_20260810/world/1786346118785123354_replay_12857.jsonl`,
  the final command and fold matched `50 -> 49` at frame `775`; the same command
  then matched restoration `49 -> 50` at frame `777`, both on map `101000000`.
- `inject-mob-temporary-stat` now consumes the pinned IL2CPP-generated shape
  dump plus its private packet JSONL and performs a typed
  `279 -> 285 -> 286 -> 280` lifecycle. It verifies version/protocol/hash/shape
  evidence, prefers a captured 48-byte base spawn, rewrites only the redacted
  object id and current foothold placement, polls each folded state, and checks
  cleanup plus unchanged world/player/inventory/progression state. The live
  base-spawn run matched frames `1516/1518/1522/1523`, toggled active bit `103`
  `0 -> 1 -> 0`, rendered and removed template `3210800`, and retained
  1,424/1,424 heartbeat pairs. No unique visual marker distinguished the set
  interval, so the bit's specific client-visible meaning remains neutral.
- `?keyboard-skill=KEY_CODE:SKILL_ID` now performs a typed single-value change
  to an existing opcode-`385` selector-`1` binding. On a fresh client, Left Ctrl
  under `2001005` emitted opcode-`52` variant `18` with two hits `[27,32]`;
  rebinding only its value to learned skill `2001004` emitted variant `17` with
  one hit `[65]`; restoring `2001005` restored variant `18` with two hits
  `[29,25]`. The warning-free fold records keyboard snapshots
  `2001005 -> 2001004 -> 2001005`, remains active on map `101000000` at HP
  `50`, and matches 91/91 heartbeats.
- A second direct-evdev A/B/A validates key code `71` and client opcode `104`.
  Captured/restored `71 -> 2001002` emitted the exact fixed-width request
  `uint32 tick, uint32 skill id, uint8 level, uint16 trailing`; mutating only
  the binding value to `2001004` switched the same key to opcode-`52` variant
  `17`, and restoring it restored opcode `104`. The two requests carry learned
  level `1` and tick delta `230024` ms, within `15.792` ms of transcript elapsed
  time. The fold now gives opcode `104` full coverage, correlates it with
  learned skills and current bindings, and emits `client_skill_use_submitted`.
  The frozen run remains active and valid with 38 matched heartbeats; its only
  warning is the final shutdown-raced pending probe.
- Server opcode `42` now has partial structural coverage rather than a raw hex
  dump. Static client inspection and a live parser trace establish four
  `uint32` mask words; the all-zero branch then reads two `uint8` values and
  one signed `int16`. The fold reports mask/bit/value distributions, preserves
  nonzero bodies and trailing bytes as opaque, emits
  `local_temporary_stat_set_received`, and leaves modeled HP/MP unchanged for a
  zero mask. Neither `111.pcapng` gameplay stream nor `1-10FS.pcapng` stream
  `126` contains opcode `42`. A padded 160-byte zero probe reached the live
  socket but stopped subsequent heartbeat replies; the later exact 22-byte
  form was sent only after that stall. Both therefore remain unsafe response
  candidates with `network_progression_proven: false`, not proof of a skill
  effect. A fresh browser-free control then reached map `101000000`, emitted
  one exact opcode-`104` request through direct Wayland key `71`, and matched
  16/16 heartbeats with none pending.
- `--generate-field-npc-spawns` now reconstructs every fully typed opcode-`300`
  frame from the folded aliased entity model. It validates exact 22-byte
  re-encoding, reparsing, frame uniqueness, and patch conflicts; runtime status
  excludes object ids. Plans cover all nine stream-`114` frames `20..28` and
  all 53 stream-`92` frames across seven populated field epochs.
- A browser-free real-client run composed the initial snapshot generator with
  all nine generated stream-`114` NPC spawns. Runtime status reported nine
  patches and aliases `npc:1..npc:9`; the client entered the field and rendered
  the expected visible NPCs. Transcript
  `npc_spawn_emitter_live_20260809/world/1786311364616674969_replay_12857.jsonl`
  folds validly to `active`, nine active/spawned NPCs, and 10/10 matched
  heartbeats.
- Server opcode `293` is now an exact seven-byte mob-health-percentage update.
  Stream `92` has 208 and stream `126` has 399; every long-corpus update names
  an active mob, 189 reach zero, and none increase within a mob lifecycle.
  Zero-health state does not remove the mob before opcode `280` does so.
- Client opcode `47` and server opcode `217` are now structurally exact
  life-movement relay/broadcast packets. Stream `126` validates 2,585 client
  submissions with 8,189 commands and 347 server broadcasts with 1,399
  commands; 344 broadcasts name an already active player and three precede
  player discovery. Stream `92` independently validates all four observed
  client-tail variants and additional command tags. The fold emits redacted
  events and command/tail distributions; opaque command bodies and field roles
  keep the family at partial semantic coverage.
- Client opcode `13` is now decoded on world connections using the same neutral
  family as login. Stream `126` has 970 exact 11-byte type-`1` envelopes;
  stream `92` has 446 type-`1`, 104 length-prefixed type-`6`, and five
  length-prefixed type-`13` envelopes. Every packet round-trips, while the fold
  exposes only message-type/body-size counts and keeps all bodies opaque.
- Server opcode `77` now has a redacted structural envelope across all 515
  sustained-corpus samples. Variants `3`, `4`, and `5` fully bound their
  counted UTF-16 fields, optional terminator, fixed controls, and neutral
  terminal value; variant `8` preserves 278 final bytes across 13 packets as
  opaque. Streams `92`, `114`, and `126` contribute 180, 2, and 333 exact
  round-trips respectively, promoting 502 observations to full and 13 to
  partial coverage. State/events expose only variant, text-length,
  control/value, and opaque-byte distributions; captured text is omitted from
  safe reports and HTTP status.
- Client opcode `217`, separate from the same-numbered server life-movement
  broadcast, now has exact compact and counted record-set boundaries. Stream
  `126` contains 345 eight-byte compact packets and 592 record sets: format `0`
  contributes 1,539 fixed 14-byte records, and format `2` contributes 114 fixed
  11-byte records. All 937 packets round-trip. The fold exposes only redacted
  structural distributions; absent mob-id and timely opcode-`219` correlations,
  the family is neither attack-named nor replayed.
- Empty server opcode `426` and empty client opcode `309` are now a fully typed,
  temporally correlated notification/acknowledgement pair. Stream `126` has
  299 matches, stream `92` has 61, and stream `114` has one; all 361 server
  packets precede their client acknowledgement with zero unmatched or pending.
  Pinned handler code independently constructs opcode `309` in response to
  `426`. The higher-level purpose remains neutral and distinct from heartbeat
  opcodes `10`/`23`.
- Client opcode `101` now has an exact 11-byte, five-value numeric shape.
  Stream `126` contributes 146 packets and stream `92` another 73; all consume
  exactly and round-trip. Only two primary/secondary pairs occur in each
  corpus, while the outer byte fields remain zero. The primary value is not
  monotonic, so the fold exposes neutral distributions rather than retaining
  the shape manifest's tentative `client_tick` name.
- Client opcodes `50`/`52`/`54` now fold as one attack-action family. Stream
  `126` contributes 552/130/120 packets and stream `92` contributes 0/128/31.
  Extended `50`/`52` variants and every opcode-`54` action carry a mob object
  id at the capture-correlated offset; all such ids are known mob templates.
  Targeted `50`/`52` suffixes now expose 646 damage words after a fixed 14-byte
  prefix: stream `126` contributes 420 (`1..42`, total `6964`) and stream `92`
  contributes 226 (`0..49`, total `4864`). Each nonzero word is now an
  individual pending hit: the fold correlates all 399 and 208 opcode-`293`
  responses, clears 21 and 11 terminal hits at lifecycle boundaries, skips the
  seven zero-damage stream-`92` entries, and finishes with zero pending effects.
  Reports alias targets and redact client tokens while keeping control/value
  and target prefix/tail roles neutral.
- The official client's WZJS-v5 mob records provide `info/maxHP` for all 11
  templates attacked in the references. Opcode `293` is modeled as floor
  integer percentage, yielding an authoritative current-HP interval and a
  bounded next-percentage prediction per correlated hit. Stream `92` matches
  161/161 predictions exactly; stream `126` matches 203/209, with all six
  differences exactly one HP after `0.389..0.460`-second response delays.
  Consecutive HP bounds infer authoritative-minus-submitted damage `+1` for
  five and `-1` for one; none has an intervening modeled attack-relay hit.
- Server opcodes `218`/`219` now have capture-bounded attack-relay envelopes:
  opcode, aliased player object id, a packed target-count/hit-count nibble, and
  repeated mob-id/hit-action/damage arrays. Stream `126` adds 41/99 relays,
  123 target records (118 known mobs plus five zero placeholders), and 166 damage words;
  stream `92` adds 1/42 relays, 71 known-mob records, and 88 damage words. Safe
  events expose aliases and low-31-bit damage magnitudes, and active mob state
  accumulates relay hit/damage totals without overriding opcode-`293` health.
  All 42 opcode-`218` relays now type their common six-byte metadata prefix;
  37 full forms append captured-zero mastery/auxiliary values, and five short
  forms are accepted only with their exact all-zero target/damage placeholder.
  All 141 opcode-`219` prefixes now type the conditional skill id, display,
  facing flags, speed, mastery, and projectile id; their four-byte tails decode
  as signed attack positions and are compared with prior remote-player
  positions in fold telemetry. Relay-tag/unknown/auxiliary roles, the damage
  high-bit marker, client target prefix/tail fields, and the source of six
  delayed one-HP prediction differences remain neutral, so captured attack-
  relay generation and official authority-adjustment replay stay disabled.
- `--reactive-mob-health-responses` now provides a narrower exact transition
  for custom-server-owned state. It adopts typed opcode-`279` spawns for known
  max-HP templates, subtracts each nonzero opcode-`50`/`52` damage word, emits
  floor-percentage opcode `293`, and emits opcode `280` reason `1` on zero HP.
  A typed stream-`92` snail injected into the held-open stream-`114` field
  received real damage `[27,32]`; the server produced `[293,280]`, folded one
  matched zero-health effect and leave with no pending hits, and retained the
  active client/heartbeat exchange. The policy explicitly does not synthesize
  attack relays or claim to reproduce the six official ±1 HP adjustments. A
  fresh run records the targeted request at frame `85`, completed removal at
  `87`, and an untargeted rejection at `99` as bounded safe runtime events.
  Its combined fold is valid with no warnings, two attacks/59 damage, one
  matched health effect, no pending effects, and 17/17 heartbeats.
- The first large opcode-`157` world packet now has a capture-validated typed
  112-byte character/stat prefix. Both streams `92` and `114` round-trip
  byte-for-byte. Their inventory tails now decode into five equipment groups
  and use/setup/etc/cash records, including slot, template id, cash flag,
  expiration, and stack quantity. The two inventory regions also round-trip;
  the common 1,422-byte continuation now decodes skill levels, keyed strings,
  keyed timestamps, saved-map slots, extended properties, and the fixed
  trailer. String contents remain redacted, and neutral roles/equipment
  metadata keep the observation at partial semantic coverage. The gameplay
  fold seeds player, field, inventory, progression, and server-clock state,
  emits it on the field event, and validates the embedded character id against
  the world-entry request.
- The `1-10FS.pcapng` stream-`126` marker-`26` initial packet is no longer an
  opaque progression exception. Its 823 bytes split into the shared character
  state, a 537-byte nine-group/five-item inventory, and a typed 172-byte
  compact progression with one skill pair, 16 saved maps, a seven-byte neutral
  variant header, and compact trailer. `TypedInitialFieldSnapshot` now
  round-trips this packet and both `111.pcapng` marker-`23` variants exactly;
  the fold emits `progression_shape` and includes compact skills, maps, and
  clock state.
- The long capture's skill-record transaction is now fully typed. Eight client
  opcode-`103` level-change requests correlate by skill id with eight
  one-record server opcode-`46` updates; a ninth zero-record update exercises
  the empty branch, and all nine updates receive client opcode-`293`
  acknowledgements. The fold updates skill levels, emits all three lifecycle
  events, tracks request/ack timing, and finishes with no pending transaction.
  The automatic IL2CPP manifest carries these shapes and exactly consumes all
  26 family packets exported from stream `126`.
- `inject-skill-record` now plans either the captured zero-record opcode-`46`
  form or a one-record update for an existing folded skill, submits it only
  through the opt-in loopback packet API, and requires the real client's
  matched opcode-`293` acknowledgement before comparing all predicted state
  invariants. A browser-free live stream-`114` run delivered two of each form:
  all four acknowledgements matched with control `346`, no transaction remained
  pending, the client stayed responsive, and player/map/inventory/progression
  plus skill `2001005 = 6` remained unchanged with 61/61 heartbeats paired.
- `--generate-initial-field-snapshot` now reconstructs the complete nested
  opcode-`157` state before replay, verifies same-length byte equality for the
  unmodified baseline, reparses both envelope and nested forms, and exposes
  identifier-free inventory/progression telemetry through
  `protocol.initial_field_snapshot_emitter`. The HP rewrite is a compatibility
  mutation over this same emitter.
- A browser-free real-client stream-`114` run validated the unchanged emitter
  end to end. Runtime status reported frame `3`, one patch, nine groups/54
  items, six skills, keyed-property variant `2`, and HP `50/222 -> 50/222`.
  The client entered the field with the predicted level, HP, MP, and EXP; the
  live transcript
  `initial_field_emitter_live_20260809/world/1786310643434685295_replay_12857.jsonl`
  folds validly to `active` with identical state and 7/7 matched heartbeats.
- `--rewrite-initial-current-hp` now performs a validated, same-length typed
  mutation of only the large opcode-`157` player HP field. A real stream-`114`
  replay changed captured HP `50/222` to `1/222`; the client entered the field
  and showed `HP 1 / 222`. The replay-observed transcript independently folded
  to `active`, map `101000000`, HP `1/222`, unchanged inventory/progression,
  nine NPCs, and fully matched generated heartbeats. The loopback runtime API
  exposes the identifier-free plan and patch count.
- Player movement is now distinct from mob movement: client opcode `182` and
  server opcode `202` parse and re-encode all 644 stream-`92` packets and all
  4,281 commands. Fixed command tags `0/1/3/5` have payload lengths
  `13/7/5/13`; typed absolute/relative fields are emitted while type `3`
  remains a bounded five-byte semantic unknown. The game-state fold records
  local path endpoint `(633,-2677)` in both reference streams, maintains
  identifier-safe remote-player positions, and emits local submission and
  remote broadcast events. Both streams remain valid with no warnings.
- Server opcode `41` is now a typed masked stat delta. All 333 stream-`92`
  packets and 324 conditional values round-trip across observed INT, LUK, HP,
  MP, AP, EXP, and 64-bit mesos bits; combined masks preserve bit-order field
  layout. Request-flag and zero-mask tail roles remain neutral. The fold ends
  at HP `50`, MP `97`, EXP `1464`, mesos `4567`, and emits previous/current
  field changes. A generated stream-`114` HP packet changed the real HUD and
  independently observed active fold from `50/222` to `1/222`, kept MP/EXP and
  all other modeled state unchanged, and preserved matched heartbeats. Runtime
  status reported exactly one planned and one sent typed packet.
- Server opcode `39` now folds typed inventory change sets. All 69 stream-`92`
  packets round-trip: 40 quantity replacements, 16 complete-record adds, 15
  removes, and 13 empty packets, totaling 71 modifications with zero unknown
  slots. The final typed inventory matches stream `114`. A guarded generated
  packet changed existing Use slot `15`, item template `2000000`, from `27` to
  `1`; the real inventory UI and independently folded event showed `1`, all
  counts/player state remained unchanged, and all 18 heartbeat pairs matched.
  Runtime status reported one planned and one sent opcode-`39` packet.
- Client opcode `80` is now a typed 12-byte Use-item request and is correlated
  with server opcode-`39` quantity and opcode-`41` potion-stat effects. All 17
  stream-`92` requests match their modeled slot/template, quantity decrement,
  and effect: four red potions restore 50 HP and 13 blue potions restore 80 MP
  with max-MP capping. A reactive live request changed the visible red-potion
  stack `2 -> 1` and HUD HP `50/222 -> 100/222`; the recorded fold reported one
  inventory match, one effect match, zero mismatches/pending requests, and all
  20 heartbeat pairs matched. Runtime status reported one observed/served
  request, zero rejections, and two response packets.
  Reactive item use and pickup now emit bounded causal request, completion,
  and rejection events, and a modeled rejection no longer closes the
  connection. A fresh direct-Wayland PageUp run served red potion `2 -> 1`
  and HP `50 -> 100`, then safely rejected the second last-item request. Its
  frozen fold is valid and warning-free with two requests, one matched
  inventory/effect pair, one policy rejection, zero pending uses, and 90/90
  heartbeats.
- Client opcode `185`, server opcode `49`, and server opcode `312` now form a
  typed item-pickup chain. All 54 stream-`92` requests round-trip (48 base and
  six extended), match their folded field epoch, inventory/mesos/special
  result, and exact drop-id removal. All 100 field-drop removals round-trip;
  the 54 local chains have zero effect/removal mismatches and zero pending
  requests. Reactive pickup tests additionally prove ordered
  request/completion events and nonfatal rejection after the modeled drop has
  already been removed.
- Server opcode `311` is typed across animated item/mesos, field-load item,
  and field-load mesos variants. Stream `92` has 125 packets/66 drop
  lifecycles; the level-1-to-10 corpus adds four exact 30-byte mode-`2` mesos
  records. A guarded stream-`114` rewrite can change the final drop position
  and/or make both neutral owner words equal the initial player id without
  exposing identifiers through the runtime API.
- The corresponding real-client owner/proximity hypothesis was falsified:
  neither a mode-`2` owner rewrite nor a captured-shaped mode-`1`/mode-`0`
  pair at the player position caused opcode `185`, despite verified pickup-key
  binding and direct Wayland input. Runtime prediction now explicitly says
  that owner equality requires additional client conditions.
- Stream `83` validates five 60-channel world records, world `4`/channel `23`
  selection, character selection, and a matching `43.142.194.150:8587`
  handoff. Its private numeric identifiers are redacted in normal output.
- The live capture-backed server renders five world tabs and online channels.
- Capture-faithful opcode-`402` timing plus the live selected-world rewrite now
  makes the client emit channel-selection opcode `5` and enter the character
  controller. A fresh muted, browser-free run selected world `1`/channel `0`
  through the nested Sway seat, received the typed one-character list, emitted
  opcode `7`, accepted the `127.0.0.1:12857` handoff, and visibly entered map
  `101000000`. Login transcript
  `typed_character_list_live_20260809/login/1786343668425457994_replay_12082.jsonl`
  folds to `handoff_ready` with zero issues/warnings; its world transcript is
  the live typed-injection transcript above and folds to `active`.
- The enabled user service `maplestory-audio-mute.service` continuously mutes
  only PipeWire nodes named `Maplestory_Classic.exe` across relaunches.
- `tools/maplestory_classic_server/tools/launch_local_game.py` now provides the
  repeatable browser/CDP/NGM-free local launch. It discovers nested
  Sway/Xwayland or accepts explicit socket/display pins, verifies both namespace
  listeners and the audio service, optionally cold-restarts the Wine prefix,
  and focuses the new window through Sway.
- Nested pointer actions use the Sway seat rather than `xdotool`. The new
  `send_wayland_evdev_key.py` helper builds a small checked-in virtual-keyboard
  client and sends physical evdev codes directly to the nested Wayland seat;
  this preserves Unity raw scan codes without moving the host cursor.

## Proxy result

The original HK CONNECT proxy and the added HK SOCKS5 proxy were tested
explicitly. The SOCKS5 endpoint is the current route; unlike the IPRoyal
residential endpoint, it permits the nonstandard game port `10282`. The
earlier conclusion that all-HK exited before login was a topology error: the
redirect for destination port `10282` lives inside `mapleproxy`, while the
replay listener had been started on the host. Once the listener also ran inside
the namespace, an all-HK browser/game launch connected to the custom login
server immediately. Alternatively, an explicit namespace-to-host bridge would
be required.

`ss` on the host cannot see the relay or replay listeners. Inspect them with
`sudo ip netns exec mapleproxy ss -ltnp`. The tested IPRoyal CN residential
exit can reach ordinary web sites but the HK Beanfun authorization host closes
through that route. IPRoyal HK reaches the website but rejects port `10282` in
both HTTP CONNECT and SOCKS5 modes. The added HK SOCKS5 endpoint reaches both.

## Current custom-server result

The first encrypted login stages are decoded and controllable:

1. server opcode `0`: NGS challenge;
2. client opcode `13`: native NGS result (observed result selector `15`);
3. server opcode `13`: accepted acknowledgment (`0d0000` in the current probe);
4. server opcode `1`: account/login result and controller transition;
5. server opcode `2`: world records, terminated by world id `-1` (`ff`).

The successful reference extends that model with:

```text
client 4    world selection (`uint32 world_id`)
server 402 first 12-byte transition response
server 402 second 8-byte response after about 2.5 seconds
client 5    channel selection (world, channel, client IPv4)
server 4    typed character list (170-byte one-record and 18-byte empty variants)
client 7    character selection (`uint32 character_id`)
server 5    19-byte IPv4/port/character handoff
```

The replayed official frame at server index `3` carries the stale rejection.
Replacing all non-heartbeat frames removed it; restoring frames individually
then isolated index `3`. Replacing the whole frame with `0a00` is preferable to
changing its result byte to zero: result `0` displays “Logging in, please wait”
and is another status, not a demonstrated success response.

The original opcode-`1` handler needs more than the earlier two-byte probe.
Giving it a bounded 128-byte zero-filled payload initializes the controller and
world wrapper. Its modal can be dismissed to reveal the world-selection board.
The opcode-`2` handler is deferred until roughly 40–80 seconds into staged
runs. Focused Cpp2IL shows that controller field `+0xc8` is a wrapper and its
`List<World>` backing field is at wrapper `+0x50`; reading wrapper `+0x18` as a
list count caused the earlier false `worlds=0` result. The corrected live dump
shows `worlds=1` before and after the sentinel. Clicking an otherwise blank
tablet opens the channel scroll, but the tablet label and channel row remain
blank.

That synthetic flag-`0` limitation is resolved by the successful capture:
flags `1` and `2` render five named tabs and online channel rows live. In the
first channel test, selecting world `2` emitted opcode `4` twice and the server
returned both opcode-`402` frames immediately. The client then stalled and
never emitted opcode `5`. The reference has a 2.54-second gap between those
responses, so reactive response-sequence delays now reproduce that boundary.
The frame-aligned decoder exposed a second invariant: opcode-`402` stage 1
contains the selected world id. The stalled live run selected world `1` but
replayed reference world `4`; the fold now rejects that mismatch, and reactive
replay can rewrite the field from the triggering client opcode `4`.

The next gate is now bounded. After character list opcode `4` and server time
opcode `134`, an official-ticket A/B replay reached the same character scene
and “connecting to server” overlay both with and without the captured opcode
`13` type-`7` envelope. Neither run emitted a type-`6` envelope or character
opcode `7`, even after direct character/start clicks. Type `7` is therefore not
required to enter the character controller and is not sufficient to complete
it. Skipping directly to a valid transformed handoff also remains
insufficient: the scene goes black and no connection reaches local port
`12857`. At that stage, the bounded gate was a client-side
completion/selection state.

A subsequent patched live run sent the successful capture's server opcode `23`
after character-list/time/type-`7`. The client replied only with a decoded
opcode-`13` type-`15` empty status and stayed in `character_selection`; it sent
no opcode `7`. This established only that a late duplicate was insufficient.

The clean ordering experiment then omitted captured bootstrap server frame `4`
and sent the successful six-byte opcode `23` only after observing the live
client opcode `6`. Without any synthetic NGSX patch, the client returned a
non-empty type-`15` status, reached world/channel/character selection, emitted
opcode `7`, received the transformed handoff, and connected to the local
stream-`92` world replay on port `12857`. The login transcript folds validly to
`handoff_ready`; the resulting world transcript contains 1,589 client bytes
and 19,753 server bytes. The security exchange is required and its ordering,
not the mere presence of opcode `23`, was the missing completion condition.

The same browser-free login path now reaches a stateful held-open world with a
typed injected mob. Direct nested-Wayland Left Ctrl produced a real two-hit
opcode-`52`; exact custom-server HP predicted `8 -> 0`, sent zero-health and
leave packets, and the observed fold matched that action/effect/lifecycle while
remaining `active`. `GET /api/v1/status` exposes the policy under
`protocol.mob_health_responses`: its mutable state is nested under `state`, and
the parent carries observed/served/rejected counts, response-packet count, and
the last identifier-free response plan. The HTTP status route remains read-only
and loopback-only; packet injection is absent unless explicitly enabled under
the namespace/OS security boundary.

The same live path now validates the derived mob-movement policy. Stream `114`
provided the held-open field, stream `92` provided 11,949 deterministic
acknowledgement pairs, and typed opcodes `279`/`281` introduced and controlled
a template-`100100` snail at the player. The client submitted 205 opcode-`207`
movements; the server generated 205 opcode-`283` acknowledgements, and the
observed fold matched all 205 with exact flag/value/auxiliary rules and no
pending movement. Runtime status nests the safe policy under
`protocol.mob_movement_acknowledgements.state` and reports counters plus the
last response/rejection at the parent. Generated mob-death opcode `280` now
updates both health and movement active state.
Reactive acknowledgements now emit identifier-safe submission,
completion, and rejection runtime events. A fresh browser-free typed-snail run
recorded 58 alternating request/completion pairs; all 58 packet-level
acknowledgements matched, with no pending/unmatched movement, no analysis
issues or warnings, and 7/7 matched heartbeats. Unknown-object tests prove
the rejection event remains nonfatal and produces no guessed response.

One state-driven opcode-`282` primitive is now proven too. From 5,284 stream-
`92` broadcasts, the planner accepts only the dominant control prefix and exact
one-command stationary placement shape. A live stream-`114` run introduced a
template-`100100` snail at `(433,-2677)` and generated one placement at
`(833,-2677)`, foothold `635`, stance `4`. The real client rendered it at the
predicted target; the frozen transcript folds validly to that exact state with
one known broadcast/command and 11/11 matched heartbeats. HTTP status exposes
the identifier-free plan/evidence and planned/sent count under
`protocol.mob_movement_broadcast`.

The same planner now supports one explicitly selected captured multi-command
path. Stream-`92` server-direction frame `18818` supplies five absolute
commands moving 48 pixels over 1,080 ms. The server validates the source
template/control prefix, translates the reference and all positions, preserves
motion fields, requires the live origin/foothold to match, and reports mode
`translated_captured_path`. A browser-free real-client run moved the injected
template-`100100` snail from `(785,-2677)` to the predicted `(833,-2677)` on
foothold `635`. Its frozen transcript folds validly with one known broadcast,
five type-`0` commands, final stance `2`, and 9/9 matched heartbeats.

The caller no longer has to identify that frame. The new
`--emit-mob-movement-auto-path X:Y:FOOTHOLD` mode filters path evidence by the
active template and requested current-to-target displacement, then requires
one distinct relative position/velocity/stance/duration shape. Stream `92` has
exactly one candidate and one shape for template `100100` displacement
`(48,0)`, so the selector chose frame `18818` automatically. A second live run
rendered the predicted `(833,-2677)` endpoint; its independent fold has one
five-command broadcast, no unknown mob, and 13/13 matched heartbeats.

Bounded composition is now implemented as well. The server groups evidence by
template/displacement/relative motion shape, excludes ambiguous displacements,
and requires one shortest Manhattan-decreasing sequence within `2..8` steps.
For template `100100`, stream `92` yielded 167 usable displacements and 38
excluded ambiguous ones. Target displacement `(96,0)` has no direct primitive
and exactly one two-step route: frame `18818` twice. A live run advanced the
snail `(785,-2677) -> (833,-2677) -> (881,-2677)` and sent 2/2 planned packets.
Its independent fold is valid with two known broadcasts, ten type-`0` commands,
final foothold `635`/stance `2`, and 11/11 matched heartbeats.

Composed movement is now transmission-paced state rather than only a startup
prediction. Each replay connection owns a scheduler that rejects identity or
position/foothold/stance discontinuities and advances only after the exact
expected encrypted write drains. The read-only status route observed the live
sequence as `planned (785,-2677, 0/2)`, `in_progress (833,-2677, 1/2)`, then `complete
(881,-2677, 2/2)`; it also exposes last/next safe steps and confirmed/planning
frame counts. The frozen transcript folds validly with the two events
10.002838 seconds apart, ten type-`0` commands, final foothold `635`/stance
`2`, and 10/10 matched heartbeats. The scheduler retains only the confirmed
movement prefix for a later in-process planning fold.

That follow-up fold is now live. A per-connection decision queue accepts at
most eight startup-configured composed targets and never plans one until the
previous schedule's final packet drains. The real client first received one
automatic path `(785,-2677) -> (833,-2677)`; only afterward did the queue plan
the composed continuation `(833,-2677) -> (881,-2677) -> (929,-2677)` from
the baseline-plus-confirmed prefix. Because a fresh evidence fold takes about
32.5 seconds, it runs off the asyncio loop. The read-only status route
remained responsive throughout with `phase=planning`, one sent packet, zero currently
planned packets remaining, and `planning_decision_index=2`; it then exposed
three total packets and finished at `3/3`. The frozen transcript is valid with
three broadcasts, fifteen type-`0` commands, exact continuity, and 8/8 matched
heartbeats. The real client rendered the predicted final endpoint.

Repeated evidence folding is removed. A validated immutable movement-planning
context is built once at listener startup and shared by initial and queued
planners, while each connection still owns its mutable confirmed state. The
stream-`92` context contains 35,207 frames and 5,284 parsed paths; its measured
build time was 10.432799 seconds. Cached automatic planning took 0.000360
seconds and the composed follow-up took 0.005125 seconds. A second live run
retained the same `785 -> 833 -> 881 -> 929` result with 10.008720- and
10.002057-second movement gaps, rather than the former 42.500916-second first
gap. Its independent fold is valid with fifteen commands and 6/6 heartbeats.
Safe cache counts are available through the read-only status route.

A bounded relative-movement policy now derives targets from confirmed state
instead of requiring every endpoint at startup. With two `(+96,0)` decisions,
the client and API followed `833 -> 929 -> 1025`; each target was created only
after its predecessor completed. Runtime finished three decisions and five
packets at the predicted foothold/stance. The frozen transcript validates
`785 -> 833 -> 881 -> 929 -> 977 -> 1025`, twenty-five type-`0` commands, four
approximately three-second gaps, and 6/6 heartbeats. Policy count, displacement,
step bound, and foothold remain safe status-route state.

Those relative decisions can now be gated by the modeled server-opcode-`10` /
client-opcode-`23` heartbeat match instead of chaining immediately. One match
starts at most one pending decision; the initial movement remains
unconditional, and the configured packet pace still applies inside a composed
decision. A browser-free real-client run exposed decision 2 mid-flight at
`(881,-2677)` after the first match, then completed all five packets at
`(1025,-2677)` after the second. The independent transcript is valid with
21/21 heartbeats and exact movement gaps 5.326966, 1.000527, 3.999752, and
1.000549 seconds. Runtime trigger telemetry finished with three matched events,
two decisions started/completed, and one post-completion event ignored; the
HTTP status route remains read-only.

The policy can now use a client-originated gameplay event as well.
`served-mob-movement` waits for a known active mob's opcode-`207` submission,
drains the capture-derived opcode-`283` acknowledgement, and only then starts
one relative decision; rejected submissions have no scheduling effect.
`awaiting_event` distinguishes this idle gate from actual path planning. A
bounded live run observed one authentic sequence-`1` submission and the exact
frame order `207 -> 283 -> 282 -> 282`, reaching the predicted
`833 -> 881 -> 929` state. Its independent fold has three broadcasts, fifteen
type-`0` commands, one matched movement pair, zero pending/unmatched movement,
and 4/4 separately matched heartbeats. Runtime finished one event/decision and
`awaiting_event:false`; the HTTP status route remains read-only.

A bounded local-player proximity predicate is now the third policy trigger.
It compares each typed opcode-`182` path endpoint with the confirmed mob using
a required `1..4096` Manhattan radius and fires only on an outside-to-inside
edge. The live radius-`64` negative control observed endpoint `(548,-2652)` at
distance `310` without sending movement. A later frame-`107` endpoint
`(855,-2695)` was distance `40` from mob `(833,-2677)`, triggered frames
`108`/`109`, and completed the predicted `833 -> 881 -> 929` state. The
independent transcript is valid with six live predicate observations/one
entry, three broadcasts, fifteen type-`0` commands, and 11/11 separately
matched heartbeats. Safe API telemetry records no identifiers and the HTTP
status route remains read-only.

The three event-driven triggers now share a bounded post-decision cooldown.
`--mob-movement-policy-cooldown-seconds` accepts `0..3600`, starts only after
the authorized decision fully drains, rejects otherwise-qualifying events
inside the window without planning movement, and re-arms on the first later
qualifying event. A browser-free live run used two-second heartbeats and a
five-second cooldown: one response authorized frames `79`/`80`, the next three
responses emitted no movement, and the first response after expiry authorized
frames `89`/`90`. Runtime recorded two completed decisions and three cooldown
rejections. The frozen transcript is valid with no warnings, ends at the
predicted `(1025,-2677)`, and contains five broadcasts/twenty-five type-`0`
commands plus 16/16 matched heartbeats. The HTTP status route remains
read-only.

Replay transcripts now make policy decisions directly auditable. Bounded,
JSON-safe `runtime_event` records capture trigger observations, decision
starts/completions, cooldown rejections, and completed-queue ignores without
identifiers. The gameplay analyzer merges them into its ordered event stream
and aligns them with the preceding packet frame. The real-client proof records
the first decision on frames `78`/`80`, three cooldown rejections on
`82`/`84`/`86`, and re-arm/completion on `88`/`90`, including exact remaining
cooldown values. Its packet and annotation fold is valid with no warnings at
`(1025,-2677)`, five broadcasts/twenty-five commands, and 15/15 heartbeats.
Writers cap annotations at 16,384 and surface any drops as analysis warnings.

Login opcode `4` is no longer an opaque replay boundary. The one-character
170-byte response in `111.pcapng` stream `83` and the empty 18-byte response in
`1-10FS.pcapng` stream `116` both validate with full coverage and exact typed
round trips. The fold exposes identifier-safe character stats/appearance
counts, rejects a selection not present in the advertised list, and the replay
path can force the captured response through the typed emitter with the
`?character-list` frame transform. A browser-free real-client run used that
transform, rendered the decoded level-12 mage and `4/4/53/14` base stats on
character select, emitted opcode `7`, connected to the local world listener,
and entered gameplay. Its closed login transcript is
`typed_character_list_live_20260809/login/1786308465556022953_replay_12082.jsonl`;
the strict fold is `handoff_ready`, character count `1`, full opcode-`4`
coverage, and zero issues/warnings.

Two debugger hazards remain: attaching during Unity/NGS startup can invalidate
the run, and leaving GDB attached stalls Wine rendering even after startup.
Use only short validated patches or the transparent opcode-`2` trampoline.

## Immediate next steps

1. Use the owner/proximity negative controls to isolate the remaining
   client-side drop eligibility condition; serve a reactive pickup only after
   observing an authentic opcode-`185` request.
2. Determine whether client opcode `104` requires a modeled server response,
   then use one-field controls to test whether opcode-`385` selector `0` is an
   empty binding without assigning meanings to selectors `2/4/5/6`.
3. Capture a ranked or multi-character login to exercise the typed
   character-list count loop and optional four-ranking-value branch.
4. Add a bounded per-trigger event budget so repeated valid gameplay events
   can be rate-limited independently of the shared cooldown while keeping
   packet injection an explicit, loopback-only opt-in.

## Useful proof artifacts

```text
/home/sdancer/ms/downloads/maple_custom_server_replay.png
/home/sdancer/ms/downloads/maple_direct_current_screen.png
/home/sdancer/ms/downloads/maple_tw_postgate_screen.png
/home/sdancer/ms/downloads/maple_protocol_captures/
/home/sdancer/ms/downloads/maple_protocol_captures/hk_official_reference_20260808/
/home/sdancer/ms/downloads/maple_custom_server_observed/
```
