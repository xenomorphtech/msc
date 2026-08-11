# Custom server laboratory

## Location

```text
/home/sdancer/ms/tools/maplestory_classic_server/
```

This is a standalone Python tool (with PyCryptodome for Maple AES and optional
`tshark` for PCAP input). It is intentionally not part of the Albion Phoenix
application.

## Tests

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server
python -m unittest discover -s tests -v
```

The last run passed all 245 tests.

## Inspect and compare captures

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server

python -m maple_server inspect \
  /home/sdancer/ms/downloads/maple_protocol_captures/1786118307321677094_13.115.120.13_10282.jsonl

python -m maple_server compare \
  /home/sdancer/ms/downloads/maple_protocol_captures/1786118307321677094_13.115.120.13_10282.jsonl \
  /home/sdancer/ms/downloads/maple_protocol_captures/1786118506764535468_52.193.141.80_10282.jsonl
```

`inspect` prints structural information without dumping payloads. `compare`
reports event sizes, common prefixes/suffixes, and equal-position counts while
keeping sensitive bytes out of terminal output.

For PCAP or JSONL login logs, use the typed state fold instead:

```sh
python -m maple_server analyze-login \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 83 \
  --packets \
  --fail-on-invalid
```

It reassembles TCP, validates cipher headers and IV progression, parses known
packet shapes, and applies them to account/world/channel/character/handoff
state. `--packets` prints frame-aligned decoded fields and timing; `--json`
emits the same records for tooling. Account and character IDs are redacted
unless explicitly requested.

World logs use the corresponding gameplay fold:

```sh
python -m maple_server analyze-gameplay \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --packets \
  --events \
  --fail-on-invalid
```

It validates frame shapes and state invariants, emits typed field events, and
folds the initial player/map/inventory/progression snapshot plus subsequent
NPC, mob, movement, transition, termination, and heartbeat traffic.

The repository-root level-1-to-10 corpus is stream `126`:

```sh
python -m maple_server analyze-gameplay \
  --pcap /home/sdancer/ms/1-10FS.pcapng \
  --tcp-stream 126
```

Normalization removes its measured 14-byte server and 28-byte client
transport preludes before the Maple greeting. It then decrypts 71,100 frames,
folds one marker-`26` initial snapshot plus 35 later field epochs, and validates
all 203 pickup requests against known drops and matching epochs. It now passes
`--fail-on-invalid`: 26,661 observations are full, 44,439 partial, none are
unknown or invalid. One state-correlation warning remains,
not a shape failure: the aggregate warning for six delayed combat predictions
that differ by one HP.
The opcode-`158` stage-`0` variant keeps its
neutral word `1` and nine-byte tail as partial semantic coverage.

Player movement appears as decoded opcode-`182` submissions and opcode-`202`
broadcasts. The short stream prints one local path ending at `(633,-2677)` and
two remote-player broadcasts under session-local aliases. The long stream
validates and round-trips 531 submissions, 113 broadcasts, and all 4,281
commands, with fixed tags `0/1/3/5` and payload sizes `13/7/5/13` bytes.

Remote-player presence now begins with server opcode `189`, whose IL2CPP-backed
prefix carries object id, level, and a counted UTF-16 name before a retained
version-specific body. Opcode `190` is its exact u32-id removal, not a neutral
fixed record. Across streams `92/114/126`, all 114 entries and 39 leaves
round-trip exactly, all leaves match current-epoch entries, and every one of
563 opcode-`202` and 652 server opcode-`217` broadcasts now references a known
player. Safe events/state expose aliases, level, name length, and optional
position, but never the captured id or name.

Server opcode `247` is now a fully bounded tutorial-UI instruction: terminated
counted UTF-16 text, two i16 values, one control byte, and a handler-confirmed
optional pair of i32 values. Stream `126` contributes 33 exact full-coverage
packets with 17 redacted localization keys; safe output exposes only code-unit
and numeric distributions. Two exact packets were accepted by the live client
and folded without changing its active map/player state. No overlay appeared
at 100 ms, 400 ms, or one second on the level-12 character, so the client-side
render remains state-gated and is not claimed.

Server opcode `244` selector `8` is a separate instructional-dialogue request.
The pinned handler and all 54 stream-`126` packets agree on an exact 15-byte
shape: selector byte `8` followed by three signed int32 values. The fold emits
`instructional_dialogue_requested` and retains numeric distributions without
guessing the three value roles. Injecting exact captured values
`1036, 2003, 0` into a fresh browser-free level-12 session immediately opened
an NPC instruction dialogue; its text was partially rendered at 100 ms and
complete at one second. The packet folded back exactly at full coverage, the
client stayed active on map `101000000`, and all 11 transcript heartbeats were
matched.

Server opcodes `320`, `322`, and `323` form a handler-backed positioned-effect
family. Their exact 15/16/11-byte records retain an aliased primary identifier,
typed i16 coordinates, and neutral numeric/control values. All 82 stream-`126`
packets round-trip at full coverage; every opcode-`323` update resolves to a
current-field entity. A live exact opcode-`322` packet at its captured
off-screen position made no visible change. Replaying the same typed packet
with only its position changed to the folded player coordinate `(633,-2677)`
produced a transient blue `10` over the sprite, gone by one second, while HP
remained `50/222`. The transcript folded both packets as one aliased entity
plus one update and matched all 131 heartbeat pairs.

Client opcode `225` is the corresponding capture-bounded action family. All 15
stream-`126` packets are exactly 16 bytes: one signed primary key, two neutral
u32 values, and one neutral u16 trailer. Every key resolves to an active
positioned-effect alias in its field epoch, and every packet immediately
follows the targetless opcode-`50` attack form in client direction order. The
fold emits `positioned_effect_action_submitted`, exposes only aliases plus
aggregate `2/3`, `305/393`, and zero-trailer distributions, and never copies
the primary key into safe output. Native validation exact-consumes all 15
records. This moves the long corpus to `26,661/44,417/22/0` without assigning
higher-level meanings to the remaining values.

Client opcode `298` now forms a typed item-acquisition transaction with server
opcode `39`. All 12 stream-`126` requests are exact 76-byte records carrying a
selection index, request kind, item template, quantity, neutral duration value,
the permanent-expiration sentinel, a redacted serial, fixed sentinels, and
fixed flags. Request kinds `1` and `2` correlate respectively with Use and Cash
inventory additions. Every request matches the next same-epoch addition by
inventory and item template in `388.332..711.700` ms, including the final
quantity-`2` request split across two quantity-`1` slots. Nine Use responses
match aggregate quantity exactly; two Cash stack responses add quantity `3`
for request value `1`, and one Cash equipment-style response has no quantity,
so those distinctions remain telemetry rather than validation failures. Safe
events and analysis state redact the three nonzero serials and expose request,
inventory/kind/duration, match, quantity-correlation, pending, and latency
counters. Python and native codecs consume all 12 records exactly, moving the
long corpus to `26,661/44,429/10/0` without claiming the higher-level source of
the acquisition.

Client opcode `276` now has two capture-bounded selector branches. The sole
stream-`126` packet is selector `24`, two redacted header values, five counted
groups, and 19 redacted u32 pairs; it round-trips exactly as 210 bytes. The
held-open local-Wine client independently emitted a nine-byte selector-`17`
form containing three reserved zero bytes. Its warning-free transcript folds
with zero unknown packets and closed cleanly after the configured two-hour hold
with all `1,440/1,440` heartbeats matched; its final gameplay phase remains map
`101000000` at HP `50/222`. Safe state/events expose only selector,
compact/grouped shape, group count, pair count, and field epoch. Python and
isolated native validation exact-consume both branches. Header, group-selector,
pair, and higher-level opcode roles remain neutral. The long corpus advances to
`26,661/44,430/9/0`.

Client opcode `222` is now the compact branch of the existing item-pickup
request. Its six exact 19-byte stream-`126` records omit the opcode-`185`
control word and proof branch while retaining field epoch, client tick, signed
position, runtime drop id, and neutral validation token. All six epochs match
folded state, all drop ids resolve to active drops, and every request completes
the authoritative opcode-`39` inventory or opcode-`41` mesos effect,
opcode-`49` result, and exact-id opcode-`312` removal. Compact removals use
captured reason `2`; full opcode-`185` local removals use reason `5`, but the
behavioral source of that distinction remains neutral. Safe state exposes only
the `compact` counter/shape and a field-local drop alias. Python and native
codecs exact-consume all six records. The long fold now validates 203/203
pickup chains with no epoch, drop, effect, result, removal, or pending mismatch,
reduces its warning set from seven to the single unrelated one-HP combat
aggregate, and advances to `26,661/44,436/3/0`.

Client opcode `64` is now a capture-bounded position action. Its two exact
10-byte stream-`126` records contain a neutral u32 followed by signed i16
coordinates. Both coordinates equal the endpoint of the last same-epoch
client opcode-`47` life-movement path: `(198,275)` and `(3331,-219)`. The next
same-epoch server opcode `348` arrives after `439.289` and `396.405` ms,
respectively. The fold reports endpoint matches, FIFO opcode-`348` correlation,
pending counts, neutral-value distributions, and latency without claiming the
u32 role or a causal request/response relationship. Python and native codecs
consume both records exactly, advancing the corpus to `26,661/44,438/1/0`.

Client opcode `111` is now a capture-bounded Cash-slot action. Its sole exact
eight-byte stream-`126` record contains a neutral u32 and signed slot `3`. The
next same-epoch server opcode-`39` change set removes and re-adds Cash slot `3`
after `486.349` ms. The fold correlates only an exact Cash-slot modification,
keeps the u32 and higher-level action purpose neutral, and exposes bounded
match/pending/latency telemetry. Python and native codecs consume the record
exactly. Stream `126` therefore reaches `26,661/44,439/0/0` with only the
unrelated one-HP combat aggregate warning.

The analyzer also bounds client opcode `47` and server opcode `217` as a
separate life-movement relay family. Stream `126` contributes 2,585 client
submissions and 347 server broadcasts, all consuming exactly; stream `92`
exercises all fixed client-tail variants. Command bytes and neutral control/
tail roles remain opaque, so these packets are partial rather than full.

Client opcode `13` is shared with the login protocol but persists in gameplay.
The analyzer now accepts the exact 11-byte type-`1` shape and the existing
length-prefixed type-`6`/`13` variants, exposing only type and opaque-byte
counts. Stream `126` contains 970 type-`1` packets; stream `92` contains 555
packets across all three observed variants, all with exact round trips.
Server opcode `49` is explicitly split by its byte discriminator: variant `0`
is the existing pickup-gain notice, while variants `1/3/4/6/10/12` use a
separate neutral envelope and cannot enter pickup correlation. Across streams
`92` and `126`, all 503 non-pickup packets now round-trip exactly. Keyed/text,
keyed-u64, u64, and text branches provide 243 full observations; the 258
variant-`3` numeric records and two variant-`4` records retain 7,607 total
opaque bytes and provide 260 partial observations. Decoded text is kept only
for re-emission: events, reports, safe JSON, and HTTP-derived analysis expose
its code-unit count but never its contents.
Server opcode `77` is a separate redacted envelope family. Across streams
`92`, `114`, and `126`, variants `3/4/5/8` contribute 515 exact round trips.
Variants `3`, `4`, and `5` fully bound their counted UTF-16 fields and neutral
control/value suffixes; variant `8` preserves only its 4- or 117-byte tail as
opaque. The fold emits `server_opcode_77_received` and exposes only variant,
text-code-unit, control/value, and opaque-byte distributions. Neither packet
records, events, text reports, JSON, nor HTTP status return captured text.

The neutral server-record fold now separates opcodes `69`, `93`, `94`, `137`,
`148`, `201`, `205`, `276`, and `379`. Streams `92/114/126` contribute
`52/6/123` records, for 181/181 exact packet round trips. Combined opcode
counts are `69:50`, `93:7`, `94:3`, `137:3`, `148:23`, `201:46`, `205:42`,
`276:2`, and `379:5`. The generated IL2CPP dump supplies exact direct reads for
opcodes `94`, `137`, `276`, and `379` plus the delegated opcode-`148` variant
switch. That switch bounds
empty variant `10`,
count-zero variant `9`, and two-i32 variants `12`/`13`; the one legacy nonempty
variant-`9` body remains explicit opaque data because it does not consume under
the current build's record mask `0x9`. The family therefore provides 81 full
and 100 partial observations, 516 typed values, and 16,010 opaque bytes.
Potentially identifying values are retained for exact re-emission but omitted
from safe state, events, and reports.

The current tree was also exercised through a fresh browser-free launch on the
nested Wayland space, using direct seat input without moving the desktop
cursor. The muted client passed world and character selection and rendered map
`101000000`. At that point `GET /api/v1/status` reported one active connection,
zero failures, all 21 fixed-record frames patched, and 13/13 paired heartbeat
probes.

A later browser-free launch used the same direct nested-Wayland seat and muted
application stream to reach the field, then injected generated opcode-`148`
variant `10`. The three-byte packet folded as one full neutral event, changed
no core gamestate, advanced matched heartbeat probes from 11 to 18, and left
one active world connection with zero injection failures.

The next finite field-bootstrap pair now comes from the automatic
`tools/il2cpp_packet_dump` evidence instead of capture-width guesses. Opcode
`147` reads two four-`i32` rectangles and a counted `i32` vector. The generated
opcode-`272` handler delegates its body, so a focused live primitive-reader
trace supplies the complete neutral grammar: an `i32`, two `i64` values, five
more `i32` values, a counted entry list, two booleans and two counted groups of
`i32` triples per entry, and one terminal `i32`. The packet classes parse and
re-emit both shapes exactly; safe folds report only rectangle/count/group/flag
distributions and redact entry selectors and vector/triple values.

The three packets for each opcode are byte-identical across streams `92`,
`114`, and `126`; all six validate through both the Python fold and the native
generated-shape engine. The long corpus gains two full observations, reaching
`26,655/44,373/72/0`; stream `92` reaches `13,406/21,755/46/0`, and stream
`114` reaches `46/20/10/0`. The opt-in loopback packet route accepted the exact
1,056-byte opcode-`272` packet twice while the browser-free client was active.
Its independent transcript folds the captured bootstrap packet plus both live
injections as three `field_configuration_ledger_received` events, stays active
on map `101000000`, and leaves player, inventory, progression, skills, NPCs,
and phase unchanged. Runtime status retains one active connection, zero
injection failures, and advancing heartbeat responses; the GDB attach pause,
not the packet, explains the recorded 36.6-second maximum heartbeat latency.

The next automatic-dump batch closes server opcodes `27`, `28`, `142`, and
`425` without publishing captured text or identifiers. Generated handlers show
that `27` and `28` begin with an `i32` record count and that `142` begins with a
boolean gate before delegating. Exact parses across both reference captures add
integer/control/text records for `27`, paired-text records for `28`, and a
gated header plus keyed text/control records for `142`. Opcode `425` is a
`u16` count, repeated `i32` values, and a fixed four-`i32` trailer; its live
handler trace entered at reader cursor 6, consumed the count internally, and
made exactly 12 repeated `i32` calls at cursors 8 through 52.

Seven fixed-width semantic declarations cover both observed widths for
`27`/`28`/`142` and the single 68-byte `425` width. Native validation consumes
all 13 selected private-regression packets (`9` from `111`, including login
duplicates, and `4` from `1-10FS`) with no unsupported or failed shapes. The
Python codecs also consume and re-emit every packet exactly. At that checkpoint,
strict state-fold coverage was `26,659/44,373/68/0` for stream `126`,
`13,410/21,755/42/0` for stream `92`, and `49/20/7/0` for stream `114`.

One exact 68-byte opcode-`425` packet was sent through the same loopback-only
`POST /api/v1/server-packets` API. Its independent transcript contains the
captured packet and injected copy as two full
`server_opcode_425_ledger_received` events, remains semantically `active` on
map `101000000`, and leaves phase, player, inventory, and progression state
unchanged. The traced process exited later after the debugger session; a fresh
browser-free launch, operated through the nested Wayland seat, is back in the
field with the audio-mute service active and one ready replay connection.

Six related generated handlers provide the next bounded partial family. Server
opcodes `228`, `230`, `231`, `232`, `234`, and `235` all live on the same
handler class and directly read one `u32`; their generated bodies make no other
`PacketReader` calls. The 12 cross-corpus packets retain capture-specific tails
of `1`, `3`, `4`, `6`, `7`, `16`, or `20` bytes. One typed envelope validates
the opcode/length combinations, preserves every byte for re-emission, redacts
the leading value and tail, and folds them as partial neutral records. Seven
manifest shapes consume all 12 selected packets without native failures.

This family moves seven long-corpus observations and five stream-`92`
observations from unknown to partial. Current totals are
`26,659/44,380/61/0`, `13,410/21,760/37/0`, and `49/20/7/0` for streams
`126`, `92`, and `114`, respectively. No live packet was sent: without a typed
role for the leading `u32` or ignored tails, replaying a cross-session value
would be a state-safety guess rather than a model validation.

The automatic dump closes server opcode `276` as a single IL2CPP boolean, but
its captured wire byte is `0x05` in both stream `92` and stream `114`. The
pinned reader's ISIL calls `BitConverter.ToBoolean`, confirming that zero is
false and every nonzero byte is true. The native shape validator now normalizes
that truth value instead of rejecting bytes above one; typed Python boolean
records preserve their original raw byte for exact round trips. Both captured
packets validate natively and fold as full neutral events, moving strict totals
to `13,411/21,760/36/0` and `50/20/6/0`; stream `126` is unchanged at
`26,659/44,380/61/0`.

An exact identifier-free `140105` replay through the loopback packet API added
the predicted second opcode-`276` event. The phase stayed `active`, map and
field epoch stayed `101000000`/`1`, and the player/inventory/progression digest
was unchanged. Three later heartbeat probes all matched with none pending;
runtime status retained one active connection, zero injection failures, and a
ready packet route. The browser-free client remained focused on the nested
Sway space and the audio-mute service stayed active.

Opcode `137` supplies the next generated prefix without overstating its body.
Its handler directly reads `i16/i32/i32`; all three packets are 84 bytes and
retain a 72-byte capture-bounded tail. A redacted typed envelope consumes and
re-emits the two stream-`92` packets and one stream-`126` packet exactly, folds
them as partial neutral events, and publishes only typed-value/tail-length
counts. Coverage moves to `13,411/21,762/34/0` and
`26,659/44,381/60/0`, while stream `114` remains `50/20/6/0`. No live packet
was sent because the three values and delegated tail may depend on session or
field state.

Opcode `169` closes one branch completely by combining the automatic dump with
the native selector jump table. The handler first reads a `u8`; selector `3`
lands at `0x180BC3281`, reads one trailing-zero UTF-16 value, and returns
without executing the other selector branches listed by the flattened dump.
The sole stream-`126` packet is 54 bytes and contains 24 code units. Its codec
round-trips exactly, redacts the text, and emits one full
`server_opcode_169_text_instruction_received` event at field epoch `31`.
Strict stream-`126` coverage is now `26,660/44,381/59/0`; streams `92` and
`114` remain `13,411/21,762/34/0` and `50/20/6/0`. Live replay is deferred
because the redacted value is a client resource instruction and its field
effect has not yet been isolated.

Opcode `29` closes the next bootstrap boundary by following the automatic
handler into its delegated constructors. Handler `b7bc850c...` has no direct
reads; constructor `0x180CB4390` reads a `u8` record count and loops through
constructor `0x180CB3F20`, which reads
`i32/i32/trailing-zero UTF-16/i32/i16`. The 327-byte packets in streams `92`
and `114` are byte-identical four-record ledgers with 128 total text code
units. Both pass the native manifest validator and exact Python re-emission.
The gamestate fold now emits full `server_opcode_29_text_ledger` observations
and `server_opcode_29_ledger_received` events while safe reports expose only
counts and text lengths. At that decoder checkpoint, strict totals were
`13,412/21,762/33/0` for
stream `92`, `51/20/5/0` for stream `114`, and the unchanged
`26,660/44,381/59/0` for stream `126`. The HTTP gameplay state/events derived
from the fold inherit the same redaction; no packet-injection endpoint action
is claimed because the captured values remain neutral and cross-session safety
is unproven.

Opcode `135` closes the next large bootstrap boundary. The automatic dump maps
handler `aecdc2fe...` to `u8/bool/i16/i32` readers; a detachable hook on the
local Wine process recorded 1,305 executed non-`i16` reads without holding the
Unity process under a debugger. Every one of the remaining 45 cursor gaps is
exactly two bytes and matches the generated `i16` primitive. The resulting
four-section grammar performs 1,350 reads, reaches framed cursor `3729`, and
round-trips the sole 3,725-byte stream-`114` packet exactly. Safe gamestate and
events expose section totals `2/166`, `2/21`, `10`, and `21/260/260`, never the
stored numeric values. The fold emits a full
`server_opcode_135_bootstrap_ledger` observation and
`server_opcode_135_ledger_received`, moving stream `114` to `52/20/4/0`.

For the live proof, the remote `192.168.2.6` world socket was explicitly
closed and the browser-free local Wine client became the only replay peer at
`127.0.0.1`. Loopback-only `POST /api/v1/server-packets` accepted the exact
captured plaintext, the traced reader sequence consumed it, and the client
remained rendered in map `101000000` with the world socket and generated
heartbeat exchange active. The programmatic audio-mute service remained
active. Because the visible field state did not identify a bounded effect,
replay safety is limited to this exact packet-shape/non-stall result.

Server opcode `13` closes the remaining attributed automatic-dump family.
Handler `ad8499ed...` reads the discriminator directly; every observed server
type (`7`, `12`, and `14`) then uses a `uint32` byte count whose body consumes
the packet exactly. This holds for all 23 server packets in `111.pcapng`; the
level-1-to-10 capture has no server packet in this family. The gameplay fold
now emits partial `server_opcode_13_envelope` observations and
`server_opcode_13_message_received` events, exposing only direction-specific
type/body-length distributions and redaction flags. Stream `92` moves to
`13,412/21,782/13/0` and stream `114` to `52/22/2/0`; stream `126` is unchanged.
No replay is enabled because the bodies remain opaque and may contain
session-local transport state.

The remaining stream-`92` opcode-`394`/client-opcode-`279` pair is now bounded
without assigning it a security role. The automatic
`tools/il2cpp_packet_dump` output confirms enum opcode `394` but has no
attributed managed handler. Capture comparison closes the sole 119-byte server
packet as one 57-code-unit trailing-zero UTF-16 envelope. The next 120-byte
client opcode `279`, 57.92 ms later, is one neutral byte plus a same-length
UTF-16 envelope: only code-unit indices `10..14` differ. Both payloads now
round-trip exactly, fold as full redacted observations, and expose only text
length, control, changed-span, temporal-correlation, and gap distributions.
This moves stream `92` to `13,414/21,782/11/0`; streams `114` and `126` remain
`52/22/2/0` and `26,660/44,381/59/0`.

The causal interpretation was tested, not assumed. With the browser-free local
Wine client as the sole world peer, loopback-only
`POST /api/v1/server-packets` accepted the exact opcode-`394` plaintext. The
client stayed rendered in map `101000000`, retained the world connection, and
emitted no opcode `279` over the following seven seconds. Accordingly the
gamestate model calls these correlated envelopes rather than a proven
request/response, and opcode `394` remains unnecessary for the working login
and gameplay path.

Two client-side boundaries now close the short stream's remaining unknowns.
Opcode `75` is an exact empty marker observed once during initial field loading
in both sustained captures; the current local-Wine transcript independently
emitted it at field epoch `1` while phase was `field_loading`. Opcode `241`
begins the captured world-exit transaction in both `111` gameplay streams. It
is followed 64.396/66.699 ms later by a redacted `u32` status on client opcode
`46`/`45`, then by final server opcode `9` at 165.073/167.004 ms. The fold adds
an `exit_requested` phase, correlates the terminal packet FIFO, and publishes
only opcodes, counts, phases, and timing. Stream `92` reaches
`13,417/21,782/8/0`, stream `114` reaches `54/22/0/0`, and stream `126` reaches
`26,661/44,381/58/0`.

A direct-Wayland game-menu attempt did not emit opcode `241` from the current
client, so no terminal packet was injected and no live exit-effect claim is
made. Three controlled confirmations instead emitted three exact 41-byte
client opcode-`310` packets. No confirmation changed phase or led to opcode
`241`; the client remained active in map `101000000`. The two independent
captured terminal sequences remain the evidence for the exit transaction.

Client opcodes `100`, `307`, `308`, and `311` now consume as fixed-width,
redacted records. Their body widths are `24`, `12`, `72`, and `20` bytes.
Streams `92`/`126` contain `1/1`, `1/1`, `2/11`, and `2/6` records,
respectively. Opcode `308` repeats at approximately 300 seconds and opcode
`311` at approximately 600 seconds after the bootstrap-skewed first interval.
The current local-Wine transcript independently contains opcode `307`, ten
opcode-`308`, six opcode-`311`, and the three controlled opcode-`310` records.
Its first nine opcode-`308` gaps are within `299.992..300.017` seconds; a later
592.004-second gap prevents treating the cadence as a guaranteed periodic send.
The fold publishes only opcode/body-byte counts, field epoch, phase, and the
periodic intervals; all bodies stay private and every record remains partial.
The analyzer's safe JSON state exposes these aggregates under
`client_fixed_opaque_records` and emits `client_fixed_record_submitted` or
`client_periodic_report_submitted` events without packet bytes.

That older local world socket later timed out without opcode `241`, leaving its
recorded packet fold in `active` rather than falsely inferring a modeled exit.
The browser-free launcher then restarted only the local Wine client, and direct
nested-Wayland input traversed world, channel, and character selection without
moving the host cursor. The fresh client re-entered map `101000000`. At the
post-entry sample, transcript
`positioned_effect_actions_live_20260811/world/1786445521564813241_replay_12857.jsonl`
validates warning-free at `62/41/0/0`, stays `active` at HP `50/222`, and
matches all 10 heartbeat probes with none pending. Runtime HTTP status reports
one active world connection, packet injection ready, and zero injection
failures. The replay generated the typed initial-field snapshot, fixed and
variable server records, and NPC spawns; the programmatic Maple-only audio mute
remained active throughout.

Client opcode `79` now closes the strongest remaining transaction-shaped
unknown. Its two 13-byte stream-`126` packets parse as client tick, inventory
type, signed source slot, signed destination slot, and a trailing signed count.
Both are equip requests ending at slot `-11`; server opcode `39` applies the
same `2 -> -11` and `3 -> -11` moves after 13 frames/1,040.241 ms and one
frame/402.275 ms. The fold
matches them FIFO, moves the modeled items only when the server update arrives,
and emits `inventory_move_requested` plus `inventory_move_confirmed`. Safe JSON
adds `inventory_move_requests`, per-inventory counts, matches, unmatched server
updates, pending requests, and last/maximum response milliseconds without
including packet bytes. The Rust manifest independently exact-consumes both
records, and stream `126` advances to `26,661/44,402/37/0`.
Inventory-move and item-acquisition request/match/pending/latency counters plus
redacted opcode-`276` selector/shape/group/pair aggregates are part of finalized
`analyze-gameplay --json` output.
`GET /api/v1/status` remains the loopback runtime endpoint for connection,
injection, heartbeat, and configured-protocol telemetry; it does not
continuously refold or expose the current plaintext transcript.

Opcode `302` now separates the NPC manager's lifecycle control from ordinary
opcode-`300` spawns. All 36 long-corpus records use control `1`, carry an
object id followed by the exact 16-byte opcode-`300` spawn body, and fold as
full-coverage `npc_lifecycle_spawn` observations. The pinned handler reads the
control and object id first, consumes that body only for its matching branch,
and otherwise calls a compact no-reader helper. The typed control-`0` encoding
is therefore modeled as a seven-byte removal and is covered by fold tests, but
remains explicitly unobserved in the reference PCAPs and not yet live-proven.

A composed live control-`1` packet kept the captured object/template shape and
changed only its typed field placement to the current stream-`114` map. The
HTTP injector accepted all 23 bytes; the transcript folded it as one additional
NPC spawn, stayed `active` with ten NPCs, and matched all 360 heartbeat pairs.
The connection closed at the configured one-hour hold-open boundary rather
than after the injection. Because the hold expired before the control-`0`
follow-up could be sent, this run proves client acceptance and predicted fold
state for the spawn branch but makes no removal or visible-sprite claim.

Server opcode `239` now has capture-bounded selector envelopes. The pinned
handler confirms selector dispatch, while the two PCAPs establish only four
branches: selector `3` has a u8 count followed by u32/i32 records, selectors
`9` and `13` have no body, and selector `21` has terminated counted UTF-16 text
plus one trailing u32. Stream `126` contributes 59 packets across all four
branches and 38 records; stream `92` contributes one additional empty
selector-`13` packet. All 60 consume and round-trip exactly at full coverage.
The fold emits `server_opcode_239_received`; reports, events, safe JSON, and
HTTP-derived state expose numeric distributions and text length but never the
record keys or text. Unobserved selectors remain unknown, and no higher-level
gameplay/UI role or live-rendering effect is claimed.

Server opcode `348` is a separate redacted text envelope. The pinned handler
confirms a common u8/i32/u8-selector/i32 prefix before dispatch. All 31
stream-`126` packets use category `4`, value `0`, and selectors `0`, `3`, `6`,
or `17`, followed by one terminated counted UTF-16 string. Selector `0` adds
two control bytes; the other three captured selectors end at the terminator.
All 31 consume and re-encode exactly at full coverage. Safe reports/events/
JSON/HTTP expose only structural distributions and omit the six distinct
primary values plus all string contents. No `111.pcapng` gameplay stream
contains this opcode, and unobserved handler selectors remain unknown.

Client opcode `66` completes the capture-local transaction model. Each of the
31 server opcode-`348` envelopes is followed by exactly one same-selector
opcode-`66` response: 25 are four-byte selector/status records and six
selector-`6`, status-`1` records add a redacted u32. The fold matches them FIFO
per selector with zero unmatched or pending transactions, emits
`server_opcode_348_acknowledged`, and reports round trips from `728.174` to
`10,436.006` ms. The generated packet-shape manifest consumes all 31 exactly.

The opt-in injection endpoint also supplied useful negative evidence. It
accepted an exact 63-byte selector-`0` packet from the level-1-to-10 capture,
but the active level-12 short-stream client emitted no opcode `66`, advanced
only one more heartbeat, then closed its world connection and showed a black
framebuffer. This was a cross-state replay, so the server does not advertise
opcode `348` as generally safe to inject. The browser-free launcher and direct
nested-Wayland seat recovered the client to an active field; status then showed
one active world connection, zero failures, and 719/719 matched heartbeats.

Client opcode `122` is now a capture-bounded redacted selector envelope.
Stream `126` contains 62 packets across six selector/count shapes: selector
`1` carries two or three u32 values, selector `2` carries three or four and
always ends in `0xffffffff`, and selectors `4`/`5` carry three. All 62 consume
and re-encode exactly at full coverage. The fold exposes only selector/count/
sentinel distributions and emits redacted structural events; it does not
assign meanings to the u32 values or accept unobserved shapes.

Server opcode `224` is an exact 22-byte remote-player/mob-template value record:
u32 player id, fixed marker `0xff`, u32 neutral value, u32 mob template, flag
`0`/`1`, reserved u16 zero, and the same u32 value again. All 20 stream-`126`
and nine stream-`92` packets round-trip exactly; every player is active and
every template has an active mob at packet time. The fold aliases the player,
reports template/value/flag distributions and active-template counts, and
does not claim that the still-neutral value is damage.

Server opcodes `285`/`286` now fold the captured single-bit mob temporary-stat
set/reset pair. Stream `92` contains ten 33-byte sets and five 23-byte resets;
all reference active template-`3210800` mobs and round-trip exactly. Every set
matches the target and skill id in the preceding opcode-`219` relay within two
server frames. The fold records three refreshes, three modeled resets, two
capture-preexisting resets, four leave-time clears, and zero active statuses at
the end. The source-level and duration fields remain neutral, other masks stay
unknown, and no live effect is claimed yet.

Client opcode `115` now models both same-field inner-portal requests in stream
`92`. Each exact 22-byte record carries active field epoch `7`, a redacted
four-code-unit portal name, and signed source/destination positions. The paths
chain within one pixel—`(1050,234) -> (1099,410)` followed by
`(1099,411) -> (1040,1007)`—and are followed by same-epoch visibility
removals/entries without a field transition. Python and native codecs consume
both records exactly; safe state exposes no portal text. Stream `92` reaches
`13,419/21,788/0/0` with no warnings.

Together, the currently modeled families leave the long-corpus totals at
26,661 full, 44,439 partial, zero unknown, and zero invalid. Stream
`92` now reaches 13,419 full, 21,788 partial, zero unknown, and zero invalid;
stream `114` reaches 54/22/0/0.

Client/server opcode `43` is now folded as a neutral redacted family. The
client has a sequence byte followed by either an opaque identifier, counted
UTF-16 value, zero terminator, and six-byte tail, or a compact nine-byte body.
The server has a message byte plus a fixed 16-byte body. The automatic packet
manifest now represents the client forms as two length-disambiguated shapes;
this replaces the earlier stream-`92` switch that failed when the same sequence
values used the identified-text form in stream `126`. Across both sustained
captures, all 45 client and three server packets consume and re-emit exactly.
Safe analysis publishes only sequence/variant, text-length, message-type, and
opaque-byte distributions.

The already active browser-free stream-`114` client then received one exact
19-byte server envelope through loopback-only `POST /api/v1/server-packets`.
The independent transcript fold added one partial `server_opcode_43_received`
event, left phase, field epoch, map, player, inventory, and progression
unchanged, and advanced matched heartbeat probes from 173 to 176. Runtime
status retained one active connection with zero connection or injection
failures. No client opcode-`43` response appeared, so no security or
request/response behavior is assigned.

Client opcode `114` now folds all 44 level-1-to-10 packets as one redacted
`u8 + counted UTF-16 + zero + u32` envelope. Packet lengths `26/28/32` follow
directly from text lengths `8/9/11`; the fold exposes only control-value and
text-length distributions plus the count of omitted trailing values. Although
most packets occur within tens of seconds of tutorial/UI traffic, there is no
immediate one-for-one response and the higher-level purpose remains neutral.
The active idle level-12 custom-server client emits none, and this
client-to-server family is not synthesized or injected in the opposite
direction.

Client opcode `217` is modeled separately from server opcode `217`. Its 345
compact packets are exactly eight bytes. The other 592 packets contain a
ten-byte opaque prefix, count/format bytes, fixed records (14 bytes for format
`0`, 11 for format `2`), and an eight-byte opaque trailer. All 937 stream-`126`
instances round-trip and fold into safe count/format distributions. No active
mob-id or sub-second server opcode-`219` correlation was found, so the server
does not synthesize or replay this still-neutral client family.

The analyzer separately matches exact empty server opcode `426` notifications
to exact empty client opcode `309` acknowledgements. All 299 stream-`126`, 61
stream-`92`, and one stream-`114` pairs are ordered and matched, with no pending
or unsolicited member. Pinned client code confirms that handling `426`
constructs and sends opcode `309` without a body. State and events expose pair
counts and round-trip timing, while deliberately leaving the higher-level role
neutral and distinct from the opcode-`10`/`23` heartbeat.

Client opcode `101` is now structurally decoded as an exact 11-byte record
containing byte/u32/byte/u16/byte values. All 146 stream-`126` and 73
stream-`92` instances round-trip. Reports expose only numeric distributions;
the 32-bit field takes two discrete, non-monotonic values, so it remains
neutral rather than using the shape manifest's tentative `client_tick` label.

Client opcodes `50`/`52`/`54` now fold into one attack-action model. Stream
`126` has 802 actions and stream `92` has 159. Extended opcode-`50`/`52`
variants and every opcode-`54` action carry a capture-correlated mob target;
safe output aliases it and omits client tokens. Targeted `50`/`52` suffixes
also expose 646 damage words across both captures after a fixed opaque prefix.
The state fold treats every nonzero word as one hit, matches all 607 opcode-
`293` responses, clears 32 terminal hits at lifecycle boundaries, and skips
seven zero-damage words while leaving no pending effects. Server opcodes
`218`/`219`
likewise fold as 140 and 43 attack relays, with aliased actors and packed
target/hit counts. Their bodies expose 194 target records and 254 damage words,
with aliased mobs and a neutral high-bit marker; active mobs also accumulate
relay hit/damage telemetry. All 141 opcode-`219`
relays now expose conditional skill id, display/facing/speed/mastery fields,
projectile id, and a signed position; the fold compares that position with the
actor's prior movement state. All 42 opcode-`218` relays expose the common
metadata fields, with 37 full mastery/auxiliary forms and five strictly checked
short all-zero target placeholders. Official-client max HP for the 11 attacked
templates allows exact floor-percentage prediction for 364/370 testable hits;
the other six differ by exactly one HP after delayed responses. All six have no
intervening modeled relay hit and infer authoritative-minus-submitted damage
`+1` five times and `-1` once. Relay tag/unknown/auxiliary roles, damage high
bit, client target prefix/tail fields, and those delayed differences are still
not established well enough for the custom server to reproduce captured attack
relays or official authority adjustments. The narrower exact-HP responder
documented below is restricted to custom-server-owned mob state.

## Replay the login capture locally

The network namespace redirects the client's destination port `10282` to local
port `12082` **inside that namespace**. Start the listener inside
`mapleproxy`; a host-only listener will not receive the redirected socket:

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server

sudo ip netns exec mapleproxy sudo -u sdancer python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12082 \
  --transcript /home/sdancer/ms/downloads/maple_protocol_captures/1786118307321677094_13.115.120.13_10282.jsonl \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/login
```

Replay is strict by default. A fresh launch has ticket/session-dependent client
bytes, so use `--no-strict` for exploratory client behavior after confirming
where the strict mismatch occurs:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12082 \
  --no-strict \
  --transcript /home/sdancer/ms/downloads/maple_protocol_captures/1786118307321677094_13.115.120.13_10282.jsonl \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/login
```

## Current capture-backed login/world experiment

`111.pcapng` stream `83` is a successful login reference and stream `92` is
its successful world connection. PCAP plaintext is resolved inside the server
process, so private account/character records never appear as command-line hex
or committed fixtures. The working login composition is:

1. replay the proven local HK bootstrap/NGS transcript, but omit captured
   server frame `4` (opcode `23`);
2. on native client opcode `6`, send successful stream `83` server frame `13`
   (the six-byte opcode-`23` response);
3. on native client opcode `13`, send the local acknowledgment followed by
   successful account frame `3` (opcode rewritten `0` to local handler `1`),
   world frames `5` through `9`, and sentinel frame `10`;
4. on client opcode `4`, send frames `15` and `16` with delays `0,2.5`, and
   rewrite frame `16`'s stage-1 world id from the live selection;
5. on client opcode `5`, parse/re-emit typed character frame `17` with the
   `?character-list` transform, then send frames `18` and `19` with delays
   `0,0,1.0`;
6. on client opcode `7`, send handoff frame `20` after transforming only its
   endpoint to `127.0.0.1:12857`.

Repeated `--reply-on-client-opcode-from-pcap` options for one opcode form the
ordered response sequence. Configure the capture-faithful waits with:

```text
--drop-server-frame 4
--reply-on-client-opcode-from-pcap 6=/home/sdancer/ms/111.pcapng@83:13
--reply-on-client-opcode-from-pcap '5=/home/sdancer/ms/111.pcapng@83:17?character-list'
--client-opcode-reply-delays 4=0,2.5
--client-opcode-reply-delays 5=0,0,1.0
--rewrite-channel-transition-world
```

Dropping an encrypted server frame is not a ciphertext splice. The replay
decrypts the original stream with its captured IV progression and re-encrypts
all emitted later frames after removing one IV step. Reactive frames then use
the resulting post-transcript IV, so the client remains synchronized.

The live client now renders all five world tabs and their online channels.
The first untimed run sent both opcode-`402` frames back-to-back: selecting
world `2` made the client emit opcode `4` twice, receive both `402` frames, and
then stall without emitting channel opcode `5`. This is the evidence for the
2.5-second reactive delay, not a guessed UI delay.
The next timed run exposed a separate packet-shape mismatch: the client chose
world `1`, while captured frame `16` still named world `4`. The typed fold now
rejects this combination before replay, and the reactive rewrite binds the
stage-1 response to the triggering opcode-`4` world id.

The corrected timing and live-world rewrite now produce client opcode `5`
reliably and reach the character-selection controller. Frames `17` and `18`
are sufficient to reach that controller. A native authenticated A/B run then
replayed the same sequence without frame `19`: it reached the identical
“connecting to server” overlay, and character/start clicks still emitted no
opcode `7`. The earlier run that did send frame `19` also emitted no later
packet. Therefore type `7` is neither required to reach character selection nor
sufficient to complete it; the capture's following type-`6` packets do not by
themselves prove a request/response security relationship.

Sending the valid transformed handoff frame `20` proactively still only blanks
the scene: no TCP connection reaches `12857`, and the client exits after the
login connection closes. This bounded the then-missing requirement to a
client-side completion/selection transition rather than server validation of
frame `19`; the ordered opcode-`6` experiment below resolves that transition.

A follow-up live probe sent the successful capture's server opcode `23` again
after the character list, time, and type-`7` envelope. The client answered with
an opcode-`13` type-`15` status carrying an empty message, remained at character
selection, and emitted neither opcode `7` nor another type-`6` packet. That
proved a late duplicate is insufficient, but it did not test the capture's
request/response ordering.

The decisive clean run withheld bootstrap server frame `4` until the real
client opcode `6` appeared. The client then received the same six-byte opcode
`23`, returned a non-empty type-`15` status, entered world/channel/character
selection without any synthetic NGSX-success patch, and emitted character
opcode `7` after the Start click. The typed fold reached valid `handoff_ready`,
the transformed frame `20` was returned, and the client opened the local world
replay on port `12857`. Security completion is therefore required, and opcode
`23` must follow the actual opcode `6`; replaying it by captured event count can
send it too early when a fresh client emits extra frames.

For subsequent runs, start the listener composition, then launch the client
without the browser:

```sh
cd /home/sdancer/ms
python tools/maplestory_classic_server/tools/launch_local_game.py --restart
```

The launcher checks both namespace listeners, nested Sway/Xwayland, and the
persistent Maple-only audio mute service before using the local placeholder
arguments.

Start the local target for the transformed handoff separately:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 92 \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/world
```

PCAP replay normalizes TCP segments to handshake/frame-aligned transcript
events before serving them. The login handoff builder validates that the
selected and handed-off character IDs match before rewriting the endpoint.

## Typed initial-field generation and HP effect validation

The reusable generator uses the complete large opcode-`157` model instead of a
raw byte offset. Pass `--generate-initial-field-snapshot` to materialize and
re-emit the captured baseline through character, all nine inventory groups,
marker-specific progression, and trailer state. The marker-`23` packets from
`111.pcapng` and the compact marker-`26` packet from `1-10FS.pcapng` all
round-trip exactly. To apply the separately live-validated HP mutation, start
the stream-`114` world target inside `mapleproxy` with:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --world-heartbeat-interval-seconds 10 \
  --rewrite-initial-current-hp 1 \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/initial_hp_1 \
  --timing-scale 1 \
  --hold-open-seconds 300
```

The planner first requires a valid gameplay fold and exactly one typed initial
snapshot. It bounds HP by the decoded maximum, replaces only the nested
`current_hp`, requires the generated packet to retain its length, parses it
back through both the nested generator and envelope, and refuses a raw patch
targeting the same server frame. Baseline generation additionally requires
byte-for-byte equality with the source packet. The loopback status route is:

```sh
sudo ip netns exec mapleproxy curl \
  http://127.0.0.1:12858/api/v1/status
```

The 2026-08-08 real-client run planned captured HP `50/222 -> 1/222`, patched
one frame, entered map `101000000`, and displayed `HP 1 / 222`. Runtime status
reported one completed connection, all 29 generated probes answered, and none
pending. Its observed transcript folded validly to `active`, HP `1/222`, the
original inventory and progression, nine NPCs, and all 30 heartbeat pairs
matched including the captured pair. This matches the planner's
identifier-free prediction across packet, client, and folded-state evidence.
Baseline generation appears under
`protocol.initial_field_snapshot_emitter`; HP mutation appears under
`protocol.initial_player_hp_rewrite`. Both report the frame index, emitter,
inventory group/item counts, skill count, progression shape/variant,
original/emitted/max HP, prediction, and patch count.

The 2026-08-09 browser-free baseline run used
`--generate-initial-field-snapshot` with stream `114`. Runtime status reported
server frame `3`, one patch, nine inventory groups/54 items, six skills,
`keyed_properties` variant `2`, and HP `50/222 -> 50/222`. The client entered
map `101000000` and rendered level `12`, HP `50/222`, MP `97/342`, and EXP
`1464`. The open observed transcript at
`downloads/maple_custom_server_observed/initial_field_emitter_live_20260809/world/1786310643434685295_replay_12857.jsonl`
independently folded validly to `active` with identical player, inventory, and
progression state and 7/7 generated heartbeat pairs matched. This establishes
the unchanged emitter as a real client-accepted generator, separately from the
controlled HP mutation below.

## Typed fixed-width server-record generation

Add `--generate-fixed-server-records` to regenerate all fully modeled
fixed-width server records at their captured frame indices. The supported
opcodes are `11`, `24`, `45`, `56`, `58`, `59`, `60`, `71`, `72`, `74`, `76`,
`89`, `96`, `105`, `112`, `121`, `131`, `178`, `301`, `386`, `388`, `389`,
and `398`. The planner requires a valid gameplay fold, round-trips every typed
record, preserves its packet length, rejects duplicate indices and explicit
patch conflicts, and does not assume the records occur only during bootstrap.
Both sustained reference streams contain a second opcode-`96`, repeated empty
opcode `45`, and repeated opcode-`301` values during later gameplay. Opcode
`60` contributes six signed-`i32` records only in stream `126`; its width and
signedness come from the generated IL2CPP direct-read dump. Opcode `190` is
folded separately as a remote-player removal.

For stream `114`, the current flag replaces 21 typed server frames. It composes
with `--generate-initial-field-snapshot` and `--generate-field-npc-spawns`.
`protocol.fixed_server_record_emitter` exposes the frame/opcode sequence,
neutral typed values, field epochs, patch count, and the predicted unchanged
player/phase state. The opcode-`59` character id is excluded; status reports
only its flag, zero-reserved invariant, and match against world entry.

The 2026-08-09 browser-free live composition used all three emitters with the
then-modeled 11-record subset; the additional ten records were still sent as
their unchanged capture bytes in that same accepted session. The client
entered map `101000000` and rendered level `12`, HP `50/222`, MP
`97/342`, the expected NPCs, and the active field. The observed transcript at
`downloads/maple_custom_server_observed/fixed_server_emitter_live_20260809/world/1786313433938476085_replay_12857.jsonl`
folds validly to `active`, all 21 records at full coverage, one matching
character context, nine active/spawned NPCs, and continuously paired
heartbeats. This validates the original typed subset through the real client;
the expanded planner emits the identical bytes already accepted for the other
ten records and has exhaustive PCAP round-trip coverage.

## Typed variable server-record generation

Add `--generate-variable-server-records` for the opcode-`156` and `385`
records adjacent to field entry. Each packet has a typed opcode and one-byte
variant discriminator. In `1-10FS.pcapng`, opcode `156` variant `0` and opcode
`385` variant `1` are complete three-byte packets. In both `111.pcapng` world
streams, opcode `156` variant `1` carries a packet UTF-16 string, a boolean,
and three int32 values; opcode `385` variant `0` carries exactly 89 repeated
`uint8 selector, int32 value` entries. All four branches are fully consumed and
round-trip exactly. The field names remain neutral; no security or gameplay
role is assigned from shape alone. A later controlled A/B/A establishes that
opcode-`385` entry indices are keyboard key codes and selector `1` carries a
skill id. Index `29` is the evdev Left Ctrl key. A later selector-only A/B/A
establishes selector `0` as an empty binding; selectors `2/4/5/6` remain
neutral.

The option performs the same valid-fold, exact-length, reparse, unique-index,
and patch-conflict checks as the fixed emitter. Runtime status exposes only
opcode, variant, text length, flag, value/entry counts, field epoch, and frame
index under `protocol.variable_server_record_emitter`. Opcode-`156` text/raw
values and unproven opcode-`385` selector values are not included; the proven
skill-binding count and Left Ctrl skill id are included.

The 2026-08-09 browser-free live run regenerated expanded server frames `9`
and `11` together with one initial snapshot, 11 fixed records, and nine NPC
spawns. The client entered and rendered map `101000000`. Transcript
`downloads/maple_custom_server_observed/variable_server_emitter_live_20260809/world/1786314493694015926_replay_12857.jsonl`
folds validly to `active`, variants `385:0` and `156:1`, 89 typed entries,
three typed values, zero opaque bytes, nine NPCs, and paired heartbeat traffic.

The typed PCAP transform
`?keyboard-skill=KEY_CODE:SKILL_ID` changes only the value of an existing
selector-`1` binding. It requires expanded opcode `385`, key code `0..88`, a
captured skill-binding selector at that key, and a non-negative int32 skill id;
it preserves the selector and all other bindings. For example:

```text
111.pcapng@114:9?keyboard-skill=29:2001004
```

For the selector-only control, use
`?keyboard-selector-zero=KEY_CODE`. It accepts only an expanded opcode-`385`
record whose target is a captured selector-`1` skill binding, changes that one
selector byte to `0`, and preserves the int32 value plus all other entries.
The current key-`71` A/B/A kept value `2001002`: captured selector `1` emitted
opcode `104`; selector `0` emitted no skill request while an ordinary client
opcode-`13` packet followed the physical input; restoring the original
record restored opcode `104`. The warning-free active snapshot reports three
keyboard snapshots, selector counts `45 -> 46 -> 45`, skill-binding counts
`2 -> 1 -> 2`, final request count `4`, and 437/437 matched heartbeats. The
result names only selector `0` as empty and leaves `2/4/5/6` unresolved.

## Opt-in live server-packet injection

Replay mode can expose one deliberately narrow mutation endpoint for controlled
client experiments. It is disabled by default and requires both the loopback
HTTP listener and the explicit opt-in flag:

```text
--http-api-port 12858
--enable-http-packet-injection
```

The flag is rejected outside replay mode or without `--http-api-port`. The HTTP
listener still accepts only a numeric loopback address. There is no application-
level authentication: the trust boundary is the local namespace/OS account, so
enable the endpoint only while all local callers are trusted.

Send exactly one plaintext server packet as even-length hex. The packet must
contain at least its two-byte opcode, is capped at 64 KiB, and the JSON body is
capped at 128 KiB:

```sh
sudo ip netns exec mapleproxy curl -sS \
  -H 'Content-Type: application/json' \
  --data '{"plaintext_hex":"810100"}' \
  http://127.0.0.1:12858/api/v1/server-packets
```

The request shape is exact: no fields other than `plaintext_hex` are accepted.
Success returns `accepted`, opcode, plaintext length, and send time, but never
packet bytes. Disabled injection returns `403`; no active replay connection or
multiple ambiguous connections returns `409`; malformed and oversized inputs
return `400`/`413`. `GET /api/v1/status` exposes only readiness, active-
connection count, attempts, sends, failures, the last opcode/length/time, and
the last error.

Do not derive raw HP packet hex by hand. The companion command plans from the
current live transcript, injects through that endpoint, then polls the same
transcript until the predicted typed packet and state delta are observed:

```sh
sudo ip netns exec mapleproxy sudo -u "$USER" \
  python -m maple_server inject-current-hp \
  --transcript /path/to/live-world.jsonl \
  --current-hp 49 \
  --http-api-url http://127.0.0.1:12858/api/v1/server-packets \
  --json
```

`inject-current-hp` accepts only the exact packet route over loopback HTTP. It
round-trips the opcode-`41` shape before sending, requires one new modeled stat
update afterward, and compares current/max HP, phase, field epoch, map,
inventory, and progression. API acceptance alone remains insufficient; the
command succeeds only when the observed fold matches every check. The JSON
report is identifier-free and does not expose plaintext bytes.

Use the typed skill-record companion for the captured server opcode-`46` forms:

```sh
# Captured seven-byte zero-record control.
python -m maple_server inject-skill-record \
  --transcript /path/to/live-world.jsonl \
  --empty \
  --http-api-url http://127.0.0.1:12858/api/v1/server-packets \
  --json

# Reassert an existing live skill at its current level.
python -m maple_server inject-skill-record \
  --transcript /path/to/live-world.jsonl \
  --skill-id 2001005 \
  --http-api-url http://127.0.0.1:12858/api/v1/server-packets \
  --json
```

Exactly one of `--empty` and `--skill-id` is required. Existing-skill mode
defaults to the folded current level; `--level` can instead name an explicit
non-negative int32 level. The command refuses unknown skills or a baseline with
pending skill transactions, round-trips the typed packet before sending, and
then requires the exact opcode-`46` observation followed by its matched client
opcode-`293` acknowledgement. It verifies counter deltas, resulting skill
levels, player state, phase, field epoch, map, inventory, and all other
progression before reporting success.

For mob opcode-`285`/`286` experiments, use the generated-evidence validator
instead of copying packet hex. First run the pinned IL2CPP dumper's `verify`,
`dump`, `export-pcap`, and `validate --require-all-supported` commands from its
README. Keep the exported plaintext JSONL private. Then run:

```sh
sudo ip netns exec mapleproxy sudo -u "$USER" \
  python -m maple_server inject-mob-temporary-stat \
  --transcript /path/to/live-world.jsonl \
  --il2cpp-shape-dump /path/to/current-il2cpp-packets.json \
  --evidence-jsonl /path/to/private/111.streams-83-92-114.jsonl \
  --evidence-tcp-stream 92 \
  --spawn-hold-seconds 2 \
  --set-hold-seconds 2 \
  --reset-hold-seconds 2 \
  --http-api-url http://127.0.0.1:12858/api/v1/server-packets \
  --json
```

The command checks the dump/JSONL version and protocol, every selected payload
hash, and the generated shape entry for opcodes `279`, `285`, `286`, and `280`.
It selects a captured matched lifecycle (preferring the shorter base spawn),
allocates a collision-free redacted object id, and places the mob on the
player's last observed foothold. Each packet is posted only after the previous
one folds as predicted. On failure after spawn it attempts typed leave cleanup;
it still returns failure if the connection disappears or cleanup is impossible.
The safe report contains only aliases, template/shape/position fields, evidence
indices, API metadata, and invariant checks.

The endpoint does not decode or return opcode-`77` text. If a controlled test
injects one, `accepted` still proves only a serialized socket write; subsequent
offline gameplay analysis retains the text internally for exact round-trip
validation but publishes only redacted lengths and neutral numeric fields.

The selected connection registers only after its replay bootstrap frames and
unregisters on close. Injected plaintext shares one async lock with generated
heartbeats and reactive responses, so encryption and socket-write order cannot
advance the Maple cipher IV out of sequence. Successful sends are also written
to the replay transcript as packet and `http_server_packet_injected` runtime
records and pass through the existing modeled-response policies.

A browser-free stream-`114` live run validated both skill-record modes. Two
manual controls and the two typed command invocations produced four opcode-`46`
updates and four matched opcode-`293` acknowledgements, control value `346`,
zero unmatched or pending transactions, and acknowledgement times from
`11.297` through `864.607` ms. The final transcript
`downloads/maple_custom_server_observed/skill_records_live_20260810/world/1786360603786044891_replay_12857.jsonl`
folds validly and warning-free to active map `101000000`, HP `50`, unchanged
player/inventory/progression, skill `2001005` still at level `6`, and 61/61
matched generated heartbeats. The client remained responsive in the field.

The same still-active browser-free session then received a typed opcode-`94`
record created and round-tripped by `ServerOpcode94Record` before the loopback
`POST /api/v1/server-packets` call. The API accepted one 11-byte packet, the
live fold added exactly one `neutral_server_record_received` event with no
opaque bytes, and phase, field epoch, map, player, inventory, progression,
skills, and fixed-record state all remained unchanged. A later status sample
reported one active connection, zero failures, and 244/244 matched heartbeat
probes. This validates non-stalling client acceptance and the predicted neutral
fold, not the two integer fields' higher-level meaning.

The browser-free live proof injected exact captured opcode-`385` and `156`
expanded packets after the client was active. The client stayed on map
`101000000` at HP `50/222` and MP `97/342`; 110/110 generated heartbeat probes
were answered. Transcript
`downloads/maple_custom_server_observed/http_injection_live_20260809/world/1786315909674330462_replay_12857.jsonl`
folds validly to four variable records, 178 typed selector/value entries, six
typed int32 values, zero opaque bytes, and two injection events, matching the
predicted unchanged player/phase state.

The current remote-player A/B/A used the same endpoint without browser or host
cursor input. A typed opcode-`202`, composed from a captured remote-player
control/id and the local player's validated path, moved a white-haired remote
sprite to predicted position `(629,-2691)`. Injecting its six-byte opcode-`190`
made the sprite disappear and changed folded active-player state `4 -> 3`.
Replaying its exact opcode-`189` entry and the same movement made it visible
again and restored `3 -> 4`. The live transcript at
`downloads/maple_custom_server_observed/neutral_records_live_20260810/world/1786331780729639306_replay_12857.jsonl`
folds validly with zero unknown leaves. After restoration the client remained
active on map `101000000`, the server had no connection failures, and 209/209
heartbeat probes were paired.

The same live session then accepted two exact 60-byte opcode-`247` tutorial
instructions. The independent transcript fold reports both as exact full-
coverage `tutorial_ui_instruction_received` events, with phase/map/player state
unchanged and no connection failure. Framebuffer samples at 100 ms, 400 ms, and
one second showed no overlay, so the API result proves safe delivery and
non-blocking handling but not rendering for this already-progressed character.

The follow-up keyboard experiment used one typed mob and physical evdev input.
With the captured Left Ctrl binding `29 -> 2001005`, Ctrl emitted opcode-`52`
variant `18`, two hits, damage `[27,32]`. Injecting
`111.pcapng@114:9?keyboard-skill=29:2001004` changed only the binding value; Ctrl
then emitted variant `17`, one hit, damage `[65]`. Injecting the unmodified
frame restored variant `18`, two hits, damage `[29,25]`. The frozen transcript
`downloads/maple_custom_server_observed/key_binding_value_live_20260809/world/1786318178544471777_replay_12857.jsonl`
folds validly with no issues/warnings, three `keyboard_bindings_loaded` events,
two injection events, final Left Ctrl skill `2001005`, active map `101000000`,
HP `50`, and 91/91 matched heartbeats. This is a causal key-binding result;
the other selector families remain unnamed.

A second browser-free A/B/A exercised physical evdev key code `71`. Under the
captured `71 -> 2001002` binding, the client emitted the exact 13-byte skill-use
request `opcode 104, tick, skill 2001002, level 1, trailing 0`. Injecting only
`?keyboard-skill=71:2001004` changed the same key to the modeled opcode-`52`
variant-`17` attack; restoring the unmodified opcode-`385` frame restored the
opcode-`104` request. The two opcode-`104` ticks differ by `230024` ms while
their transcript timestamps differ by `230039.792` ms. The frozen transcript
is
`downloads/maple_custom_server_observed/key_binding_71_live_20260809/world/1786320080162364482_replay_12857.jsonl`.
It folds validly to active map `101000000`, HP `50`, final bindings
`29 -> 2001005` and `71 -> 2001002`, two full opcode-`104` observations, two
level/binding correlations, and no issues. It has 38 matched and zero unmatched
heartbeat responses; its sole warning is one final probe whose response fell
outside the capture during controlled shutdown. This validates the request
model and binding-dependent dispatch, not the server-side effect or response
semantics of skill `2001002`.

A fresh no-injection control sharpened the server-side boundary. Physical key
`71` emitted two more modeled opcode-`104` requests for skill `2001002`, level
`1`, and trailing zero, 10,684.712 ms apart. The only server packets between
them were two periodic opcode-`10` heartbeat probes; there was no non-heartbeat
server packet. The second request therefore proves that an immediate gameplay
response is unnecessary for repeat request dispatch. At the bounded snapshot,
the transcript remained `active`, valid, and warning-free with 275/275 matched
heartbeats and none pending. The source is
`downloads/maple_custom_server_observed/positioned_effect_actions_live_20260811/world/1786458087377858805_replay_12857.jsonl`.
The analyzer now records each request's prior-frame/elapsed interval and exact
intervening non-heartbeat opcode counts, plus aggregate same-skill and
response-free same-skill repeat counts. This is liveness/dispatch evidence,
not proof of the skill's visual or state effect.

### Opcode-42 response probe: decoded prefix, unsafe packet

The next response candidate was tested through the same opt-in injection API.
Static inspection and a live parser trace establish server opcode `42` as four
little-endian `uint32` mask words followed, on the all-zero branch, by two
bytes and one signed `int16`. `LocalTemporaryStatSetHeader` models exactly that
prefix. The analyzer reports mask patterns, enabled-bit counts, the neutral
zero-mask suffix value distributions, and opaque-byte totals; it emits a
partial `local_temporary_stat_set_header` observation plus a
`local_temporary_stat_set_received` event without changing HP/MP.

The API successfully wrote a 160-byte padded all-zero packet and a later exact
22-byte minimal packet. That success means only that encryption and socket
write completed. Heartbeat replies stopped after the padded packet, and the
minimal packet was sent only after the connection had already stalled, so
neither packet establishes acceptance or progression. The padded transcript
entry cleanly folds as the decoded 22-byte prefix plus 138 opaque bytes, and
both observations carry `network_progression_proven: false`. Opcode `42` is
absent from reference gameplay streams `92`, `114`, and `126`; no semantic
skill name or causal response role is assigned.

The fresh control reran the scripted browser-free login, entered map
`101000000`, sent physical key `71` directly through nested Wayland, observed
one exact opcode-`104` request for skill id `2001002`/level `1`, and matched
16/16 generated heartbeat responses with none pending. Treat that control as
the acceptance baseline. `POST /api/v1/server-packets` returning `accepted`
must always be followed by client output and heartbeat checks before a packet
shape is considered safe.

## Typed NPC-spawn generation

Add `--generate-field-npc-spawns` to the world replay command to regenerate
every fully typed opcode-`300` frame from folded NPC entity state. It composes
with `--generate-initial-field-snapshot`. For stream `114`, the planner emits
nine exact 22-byte packets at server frames `20..28`; the status route exposes
`protocol.npc_spawn_emitter` with nine patches, field epoch `1`, and the
alias/template/position/range state for `npc:1..npc:9`. Raw runtime object ids
remain excluded.

The 2026-08-09 browser-free live composition entered map `101000000` and
rendered the expected visible NPCs. Its observed transcript at
`downloads/maple_custom_server_observed/npc_spawn_emitter_live_20260809/world/1786311364616674969_replay_12857.jsonl`
folds validly to `active`, nine active/spawned NPCs, and 10/10 matched generated
heartbeats. This replaces nine more captured plaintext frames with model-
generated packets while preserving the client-visible field.

## Typed post-transcript HP update validation

Opcode `41` is the captured player-stat delta family. The model decodes the
observed INT, LUK, HP, MP, AP, EXP, and 64-bit mesos mask bits, folds each
field independently, and preserves the neutral request flag and final marker.
To emit a new current-HP delta after stream `114`:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --world-heartbeat-interval-seconds 10 \
  --emit-current-hp-update 1 \
  --post-transcript-start-delay-seconds 10 \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/current_hp_stat_1 \
  --timing-scale 1 \
  --hold-open-seconds 180
```

The planner validates current/max HP, bounds the requested value, generates
`29000000040000010000`, parses it back, and publishes
`protocol.player_stat_update` with its prediction and sent count. The real
client accepted the packet and displayed `HP 1/222`, while MP remained
`97/342` and EXP remained `1464`. The recorded exchange folded validly to
`active`, with one HP event carrying `previous:50` and `current:1`, and all
nine generated heartbeats matched in the completed transcript. This is a
post-entry state delta, separate from rewriting the initial snapshot.

## Typed inventory-quantity effect validation

Opcode `39` carries inventory change sets. The decoder handles the observed
empty, add, stack-quantity, and remove operations, reuses the initial-inventory
stack/cash record grammar, and applies modifications to known slots. To mutate
an existing stack after stream `114`:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --world-heartbeat-interval-seconds 10 \
  --emit-inventory-quantity-update use:15:1 \
  --post-transcript-start-delay-seconds 15 \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/inventory_use15_1 \
  --timing-scale 1 \
  --hold-open-seconds 180
```

The planner resolves Use slot `15` to item template `2000000`, validates its
captured quantity `27`, bounds the replacement, generates
`2700000101020f000100`, parses it back, and publishes
`protocol.inventory_quantity_update`. The real inventory window displayed
quantity `1` in that slot. The completed observed transcript folded validly to
`active`, recorded `previous_quantity:27` and `quantity:1`, retained the item
count and player state, resolved every slot, and matched all 18 generated
heartbeat pairs.

## Reactive consumable-use validation

Client opcode `80` is the capture-validated Use-item request. The typed policy
checks its signed slot and item template against current inventory state, then
emits the observed two-packet response: opcode `39` decrements the stack and
opcode `41` applies the captured HP/MP effect with maximum-stat capping. Only
red potion `2000000` (`+50 HP`) and blue potion `2000014` (`+80 MP`) are enabled;
unknown templates, mismatched/empty slots, capped stats, and the still-unknown
last-item removal shape are rejected.

The live red-potion experiment used:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --world-heartbeat-interval-seconds 10 \
  --emit-inventory-quantity-update use:15:2 \
  --post-transcript-start-delay-seconds 15 \
  --reactive-item-use-responses \
  --transcript-dir \
  /home/sdancer/ms/downloads/maple_custom_server_observed/reactive_item_use_red \
  --timing-scale 1 \
  --hold-open-seconds 300
```

Stream `92` supplies 17 independent request/effect examples: 13 blue potions
and four red potions. All 17 requests are exact 12-byte shapes, match the
modeled Use slot/template, decrement quantity by one, and match the following
stat effect. In the live run, the initial typed update visibly changed red
potions `27 -> 2`; using one produced client opcode `80`. Runtime telemetry
reported one observed/served request, zero rejections, and two response
packets. The client displayed quantity `1` and HP `100/222`, exactly matching
the `2 -> 1` and `50 -> 100` prediction. The completed transcript folded with
one inventory match, one stat-effect match, zero mismatches/pending requests,
and 20/20 matched heartbeat pairs.

Reactive item use and pickup now also write bounded runtime request,
completion, and rejection events. A rejection is folded against the matching
pending client request and does not close the world connection. A fresh
browser-free stream-`114` run used direct Wayland PageUp input twice. Frames
`232`/`234` recorded the first red-potion request and completed `[39,41]`
response (`2 -> 1`, HP `50 -> 100`); frame `250` recorded and rejected the
second request at the unvalidated last-item boundary without sending a packet.
The frozen transcript
`downloads/maple_custom_server_observed/reactive_item_policy_events_20260809/1786305404534384659_replay_12857.jsonl`
folds validly with no issues or warnings: two requests, one inventory/effect
match, one policy rejection, zero pending requests, and 90/90 heartbeat pairs.

## Pickup request/effect validation

The gameplay analyzer now decodes the complete capture-observed pickup chain:
server opcode `311`, client opcode `185`, the positive opcode-`39` inventory or
opcode-`41` mesos effect, server opcode `49`, and server opcode `312`. Stream
`92` contains 125 spawns for 66 unique drops, 54 requests (48 base plus six
with a 12-byte opaque proof), 54 short result records, and 100 removals. All
records round-trip. Fifty-nine drops have an exact mode-`1`/mode-`0` refresh
pair and seven are mode-`2` field-load items. Every pickup request names a
known active spawn; all 54 result values and all 54 local removals match that
spawn, with zero pending requests. Reports use field-local `drop:N` aliases and
do not print runtime drop, owner, source-mob, or actor ids.

Stream `114` ends with one active mode-`2` drop: item template `4000004` at
`(-863,-1742)`. The final folded player position is `(633,-2677)`, and Etc
slot `7` contains the same item at quantity `74`. Stream `92` independently
proves four pickups of template `4000004`, each as an Etc quantity delta of one,
an item gain notice quantity of one, and a reason-`5` removal whose actor equals
the spawn's two captured owner values.

The replay now has two typed controls for a real pickup A/B:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --rewrite-final-field-drop-position 633:-2677 \
  --rewrite-final-field-drop-owner-to-player \
  --reactive-item-pickup-responses \
  --item-pickup-evidence-tcp-stream 92 \
  --world-heartbeat-interval-seconds 10 \
  --transcript-dir \
  /home/sdancer/ms/downloads/maple_custom_server_observed/reactive_item_pickup \
  --timing-scale 1 \
  --hold-open-seconds 300
```

The rewrite changes only the typed coordinates in the 38-byte captured spawn;
the drop id, item template, ownership-neutral fields, expiration, and flags are
preserved and round-trip. The reactive policy accepts only the known active
drop, current field epoch, deterministic captured template effect, and exactly
one existing stack with capacity. It predicts and emits opcode `39` (`74 ->
75`), opcode `49` (item `4000004`, quantity `1`), and opcode `312` (reason `5`)
in that order, then removes the drop from mutable server state. Mesos, special,
new-slot, ambiguous-stack, and unknown-template cases remain rejected. The
client still supplies its own validation token; the server does not synthesize
or assign semantics to it. The same policy now accepts compact opcode `222`
and mirrors its captured 11-byte reason-`2` removal instead of the full
opcode-`185` 15-byte reason-`5` form.

Observed pickup requests now receive the same causal transcript treatment as
item use: request, completed `[39,49,312]` response, or safe rejection. Unit
coverage proves a second request for an already removed modeled drop is
rejected without closing the connection and leaves zero pending pickup work.

The owner rewrite is a separate same-length typed patch. It validates exactly
one initial player and one final field-load item, then changes only the two
neutral owner words. `protocol.final_field_drop_owner_rewrite` exposes the
aliased drop, item template, flag, frame/field epoch, patch count, and the
identifier-free prediction fields `drop_owner_fields: match_initial_player`
and `pickup_eligibility: requires_additional_client_conditions`.

That conservative prediction follows two generations of real-client controls.
Rewriting the mode-`2` owner words did not produce opcode `185`, and neither
did a captured-shaped mode-`1`/mode-`0` pair at the final player position. The
fresh transcript
`downloads/maple_custom_server_observed/positioned_effect_actions_live_20260811/world/1786458087377858805_replay_12857.jsonl`
then retained a known typed source-mob lifecycle and tried three animated pairs:
one after earlier source history, one less than a millisecond after mob entry
and leave, and one with an explicit controller-level-`0` release before leave.
All owner fields matched the player and every pair was at the player position;
none produced opcode `185` or compact opcode `222`, including after verified
physical pickup-key input. The fold remains `active`, valid, and warning-free
at the bounded control snapshot, with zero pickup requests and 141/141 matched
heartbeats. Owner equality, proximity, source-mob presence/history, immediate
lifecycle timing, and controller release are therefore not sufficient alone.

The first capture-timed combat/reward control used a stream-`92` family that
was authentic but whose exact drop was never requested in the reference. Its
typed mob received an authentic local opcode-`52` attack followed by the
capture-ordered MP, mob-health `20 -> 0`, leave, opcode-`49`, EXP `+10`, text,
and source-matched `4000004` pair. The 92.526 ms first-health timing was close
to that family's 102.326 ms reference timing, but pickup input remained
negative. The later drop-object audit corrects the earlier interpretation:
this bounded one unpicked family, not client admission in general.

The positive control instead copied the first stream-`92` `4000004` object
whose lifecycle is followed by an official request. The official sequence has
a 58.892 ms attack-to-health response, `12 -> 0` health, controller release at
450.451 ms, and pickup admission at 2,938.908 ms. The live sequence sampled the
current player position only after loading the reference packets, preserved
the source-position offset, and matched the live MP/EXP baselines. Its real
opcode-`52` attack targeted the active injected mob, the first health response
arrived in 53.681 ms, and control was released after approximately 450 ms.
Physical input produced base opcode `185` for the exact known drop 1,517.335 ms
after its live spawn. The client then retried every three seconds while the
response was deliberately withheld. Once one evidence-derived `[39,49,312]`
response was sent, Etc slot `7` changed `74 -> 75` and the drop disappeared.
The snapshot is active, valid, and warning-free with 62 raw requests folded as
one admitted chain plus 61 retries, one matching effect/result/removal, and
900/900 heartbeats.

The next cut uses the second independently admitted `4000004` object. Its
official pair has source offset `(+10,-3)`, controller release at 398.819 ms,
and request at 1,591.279 ms. The live control sent only that pair at the player
and its release at 394.459 ms. It deliberately omitted source-mob entry,
attack, HP, leave, and reward packets, and the fold marked the referenced mob
unknown. Even before any fresh key input, the client's pickup-action state
emitted opcode `185` in 1,584.485 ms and then every three seconds. A reason-`1`
cleanup closed the intentionally unanswered ten-attempt chain. The same pair
was then reinjected and requested in 1,595.243 ms, again before the delayed
fresh input; one guarded response changed `75 -> 76` and removed it. This
proves the admitted pair and an already-active pickup action do not need the
combat/reward prefix, but does not yet prove the pair initiates pickup from a
fresh neutral input state.

The next control started a new client and world connection, re-entered map
`101000000`, and established an active zero-request baseline. The exact second
admitted pair plus its controller release at 394.575 ms stayed negative after
capture-timed physical pickup input. The first admitted combat/death/reward
family also stayed negative. Its first scheduling pass delivered HP at 169.033
ms and was discarded as a timing control; the calibrated pass delivered the
first HP update 64.085 ms after the real opcode-`52` attack, released the source
controller 450.850 ms after the pair, and scheduled pickup input at the prior
positive live age of 1,517.335 ms. No opcode `185` or `222` followed. After
reason-`1` cleanup, the fresh transcript remains active, valid, and
warning-free with zero pickup requests/chains/pending work, one baseline
field-load drop, and 180/180 heartbeat pairs. Pair/release timing and
near-reference combat-response timing therefore do not initialize admission
from neutral state by themselves; the earlier drop-only success relied on
pickup-action state already active in that session.

Two reusable PCAP transforms encode those bounded rewrites.
`?character-stat=FIELD:VALUE` accepts only an opcode-`41` packet whose sole
captured stat is `FIELD`, preserving its mask, request flag, and tail.
`?field-drop-position=X:Y[:SOURCE_X:SOURCE_Y]` reparses opcode `311`, changes
only the signed destination and optional animated source positions, and
preserves the drop, owner, source-mob, item, timing, and flag fields. The
fold now coalesces same-epoch/same-drop retries without hiding packet counts.
Safe state exposes logical chain/retry totals and admitted drop kinds/templates,
and result/removal timing is correlated to the latest attempt while retaining
the first request frame and attempt count. A different-reason removal before
any effect/result records one interrupted chain rather than a false response
mismatch; an expected local-pickup removal with no result still fails. The
aggregate live fold is warning-free with 76 requests, three chains, 73 retries,
two completions, one interruption, no pending pickup, and 1,064/1,064
heartbeats.
Request events now also retain the aliased drop's first-spawn frame/age and the
source controller's last release frame/age. Release events list aliased active
drops from that source and their first-spawn-to-release delays, preserving the
mode-`1` clock across the matching mode-`0` refresh. In stream `92`, the four
official `4000004` admissions have drop ages `2,938.908`, `1,591.279`,
`4,124.092`, and `2,378.920` ms. Their source-controller release ages at request
are `2,488.457`, `1,192.460`, `4,124.092`, and `1,988.300` ms; the third release
precedes its drop spawn, so it is specifically the only one without a
post-spawn release. The three primed live admissions have drop ages
`1,517.335`, `1,584.485`, and `1,595.243` ms.

## Reactive mob-health validation

The custom server can now own a deliberately exact subset of combat state. The
following proven run kept stream `114` open, injected a typed snail spawn copied
from stream `92` at the folded player position, and enabled reactive health:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --reactive-mob-health-responses \
  --send-after-transcript-from-pcap \
  '/home/sdancer/ms/111.pcapng@92:563?mob-spawn=633:-2677:0:0' \
  --post-transcript-start-delay-seconds 2 \
  --world-heartbeat-interval-seconds 10 \
  --transcript-dir \
  /home/sdancer/ms/downloads/maple_custom_server_observed/reactive_mob_health_20260809 \
  --timing-scale 1 \
  --hold-open-seconds 3600
```

The `mob-spawn` transform first parses a validated opcode-`279` packet. It
changes only signed `x/y` and, when provided, the two uint16 foothold fields.
The proof preserved template `100100`, initialized it at its referenced `8/8`
HP, and exposed it as `mob:runtime:1` rather than leaking its wire object id.

Physical evdev key `29` sent directly through nested Wayland produced one real
opcode-`52` variant-`18` action with damage `[27,32]`. The first hit changed
`8 -> 0`; the second was already terminal. The server sent opcode `293` with
percentage `0`, then opcode `280` reason `1`, and removed the mob. Runtime
status recorded one observed/served request, zero rejections, two response
packets, and `terminal_hits_skipped: 1`. The client stayed connected and kept
answering generated heartbeats.

The live transcript
`reactive_mob_health_20260809/1786281154891058720_replay_12857.jsonl` folds
validly to `active`: one attack, one matched zero-health effect, one leave,
zero active mobs, and zero pending combat effects. Generated heartbeat replies
continued; because this transcript is still being appended, a fold sampled
between a probe and its response can transiently report one pending probe.
This is a request/effect/lifecycle validation. It is not another next-
percentage sample, because the injected spawn had no earlier opcode-`293`
health observation.

The replay now records the policy side of this chain as the same bounded,
identifier-free runtime events used by movement scheduling. In the fresh
browser-free proof, authentic targeted attack frame `85` emitted
`mob_health_request_observed` with `[27,32]`; after opcode-`293` and
opcode-`280`, frame `87` emitted `mob_health_response_completed` with
`8 -> 0`, percentage `[0]`, removal, and one skipped terminal hit. A second
physical Ctrl swing was untargeted: frame `99` records observation plus the
safe rejection reason and has no response packet. Transcript
`reactive_mob_health_policy_events_20260809/1786304902178638016_replay_12857.jsonl`
folds validly with no warnings: two attacks/59 submitted damage, one matched
health effect, one zero-health update and leave, no active mob or pending
effect, and 17/17 matched heartbeats.

Query the read-only status route from the listener's namespace:

```sh
sudo ip netns exec mapleproxy curl -s \
  http://127.0.0.1:12858/api/v1/status
```

`protocol.mob_health_responses.state` contains aliased active mobs with exact
current/max HP and percentage, source-evidence counts, and the deterministic
damage/percentage/terminal rules. The parent object contains request and sent-
packet counters plus `last_response` with damage, HP before/after, emitted
percentages/opcodes, zero entries, skipped terminal hits, and removal. The API
also reports the most recent safe `last_rejection`; rejected/untargeted attacks
receive no modeled response but do not close the held-open connection. The API
remains loopback-only; status is read-only, while server-packet injection is
absent unless explicitly enabled under the current local namespace/OS access
boundary.

Captured official combat still has six delayed ±1 HP authority adjustments.
The exact responder does not claim to reproduce those, does not synthesize
opcodes `218`/`219`, and rejects unknown/inactive targets, ambiguous HP,
missing damage, and high-bit damage rather than guessing.

## Reactive mob-movement acknowledgement validation

Stream `92` contains the large acknowledgement corpus but ends after a field
reset with no explicit mobs. Stream `114` provides a stable held-open gameplay
field but no mob evidence. The replay now separates those roles and adopts
typed post-transcript mob state:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --reactive-mob-movement-acknowledgements \
  --mob-movement-evidence-tcp-stream 92 \
  --reactive-mob-health-responses \
  --send-after-transcript-from-pcap \
  '/home/sdancer/ms/111.pcapng@92:563?mob-spawn=633:-2677:635:635' \
  --send-after-transcript-from-pcap \
  '/home/sdancer/ms/111.pcapng@92:604?mob-spawn=633:-2677:635:635' \
  --post-transcript-start-delay-seconds 2 \
  --post-transcript-frame-delay-seconds 0.1 \
  --world-heartbeat-interval-seconds 10 \
  --transcript-dir \
  /home/sdancer/ms/downloads/maple_custom_server_observed/reactive_mob_movement_20260809 \
  --timing-scale 1 \
  --hold-open-seconds 3600
```

The `mob-spawn` transform accepts either a typed opcode-`279` entry or an
opcode-`281` controller assignment with embedded spawn data. It changes only
position and optional footholds, preserving the object, template, controller,
and remaining spawn fields. The policy learns field-local object/template
state as those packets are sent.

The direct browser-free login reached the held-open map and stayed active. The
client submitted 205 opcode-`207` movements for the injected template-`100100`
snail; 205 generated opcode-`283` acknowledgements copied each object/sequence,
used status value `0`, derived the flag from control byte zero, and zeroed both
auxiliary fields. The observed transcript
`reactive_mob_movement_20260809/1786284358797500712_replay_12857.jsonl`
folds validly with `submitted:205`, `acknowledged:205`, `matched:205`,
`unmatched:0`, and `pending:0`. It also contains 69 matched generated
heartbeats and remained in the active phase until the test listener was
stopped cleanly.

Reactive acknowledgements now record bounded causal runtime events as well.
`mob_movement_submission_observed` contains the known-template flag, template,
sequence, command count, control-byte predicate, and reference/start/end
coordinates without the runtime object id. A successful drain adds
`mob_movement_acknowledgement_completed`; a policy refusal instead adds
`mob_movement_submission_rejected` and its safe reason. Fresh browser-free
transcript
`reactive_mob_ack_policy_events_clean_20260809/1786307034810350480_replay_12857.jsonl`
contains 58 alternating request/completion pairs. Its fold is valid and
warning-free with 58/58 packet-level movement matches, no pending/unmatched
movement, and 7/7 matched heartbeats.

`protocol.mob_movement_acknowledgements.state` exposes the evidence mapping,
field epoch, and identifier-free known/active mob counts. The parent reports
submission/response/rejection counters, `last_response`, and `last_rejection`.
Unknown live submissions are rejected without closing transport. A generated
health-policy opcode-`280` is also applied to movement state so a dead mob is
removed from both policies consistently.

### Generated opcode-282 placement

The custom server also owns one conservative server-to-client movement
primitive. `--emit-mob-movement-broadcast X:Y:FOOTHOLD[:STANCE]` selects the
only active modeled mob after explicit post-transcript frames, validates an
exact stationary shape in the movement evidence, predicts the state delta, and
appends one typed opcode `282`. The validated visual run used:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --mob-movement-evidence-tcp-stream 92 \
  --reactive-mob-health-responses \
  --send-after-transcript-from-pcap \
  '/home/sdancer/ms/111.pcapng@92:563?mob-spawn=433:-2677:635:635' \
  --emit-mob-movement-broadcast '833:-2677:635:4' \
  --post-transcript-start-delay-seconds 2 \
  --post-transcript-frame-delay-seconds 30 \
  --world-heartbeat-interval-seconds 10 \
  --transcript-dir \
  /home/sdancer/ms/downloads/maple_custom_server_observed/generated_mob_broadcast_visual_20260809 \
  --timing-scale 1 \
  --hold-open-seconds 3600
```

The evidence corpus has 5,284 broadcasts. Prefix `0000ff00000000` occurs in
5,230; 1,509 of those have one absolute command whose position equals the
reference, zero velocity, and duration 1,080 ms. The selected stance `4` has
1,055 exact examples. The plan refuses zero/multiple active mobs, absent
stance-specific evidence, invalid coordinates/footholds, or an invalid replay
instead of guessing.

The injected template-`100100` snail started at `(433,-2677)` on foothold
`635`. After the generated packet, the real client rendered it at the predicted
right-side target `(833,-2677)`. Runtime API
`protocol.mob_movement_broadcast` reported the aliased entity/template,
previous and predicted position/foothold/stance, exact command fields, evidence
counts, and `packets_planned:1`/`packets_sent:1`. The final transcript
`generated_mob_broadcast_visual_20260809/1786286736690024914_replay_12857.jsonl`
folds validly to mob position `(833,-2677)`, stance `4`, one known broadcast,
one command, and 11 matched heartbeats with none pending.

The mutually exclusive
`--emit-mob-movement-path EVIDENCE_SERVER_FRAME:X:Y:FOOTHOLD` mode reuses one
exact multi-command opcode-`282` shape from the movement evidence. It resolves
the source frame's field-local template, requires that template and the
dominant control prefix, accepts only two or more absolute commands, translates
the reference and every command to the requested endpoint, preserves each
velocity/stance/duration, and rewrites all command footholds only after
checking continuity with the active mob. The validated run used:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --mob-movement-evidence-tcp-stream 92 \
  --send-after-transcript-from-pcap \
  '/home/sdancer/ms/111.pcapng@92:563?mob-spawn=785:-2677:635:635' \
  --emit-mob-movement-path '18818:833:-2677:635' \
  --post-transcript-start-delay-seconds 2 \
  --post-transcript-frame-delay-seconds 30 \
  --world-heartbeat-interval-seconds 10 \
  --transcript-dir \
  /home/sdancer/ms/downloads/maple_custom_server_observed/generated_mob_path_visual_20260809 \
  --timing-scale 1 \
  --hold-open-seconds 180
```

Evidence server-direction frame `18818` has reference `(249,2024)`, endpoint
`(297,2024)`, five absolute commands, and total duration 1,080 ms. The
generated packet used reference `(785,-2677)` and command positions
`(813,-2677)`, `(814,-2677)`, `(821,-2679)`, `(825,-2679)`, and
`(833,-2677)`. Runtime status reported mode
`translated_captured_path`, exact relative-motion-shape evidence `1`, one
planned/sent packet, and the complete safe command list. The real client
rendered the blue snail at the predicted endpoint. Transcript
`generated_mob_path_visual_20260809/1786288852728632356_replay_12857.jsonl`
folds validly with final position `(833,-2677)`, foothold `635`, stance `2`,
one known broadcast, five type-`0` commands, and 9/9 matched heartbeats. This
proves one selected captured path and its endpoint effect, not autonomous path
selection.

For state-driven selection, use
`--emit-mob-movement-auto-path X:Y:FOOTHOLD`. The planner filters the evidence
by active template, dominant prefix, multiple absolute commands, and the exact
requested endpoint displacement. It groups candidates by relative
position/velocity/stance/duration shape and proceeds only when one distinct
shape remains. Thus repeated identical observations increase support, while
two different ways to produce the same displacement are rejected as
ambiguous. This option is mutually exclusive with both explicit movement
emission options.

The live automatic run used the same command above except for:

```text
--emit-mob-movement-auto-path '833:-2677:635'
--transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/generated_mob_auto_path_visual_20260809
```

Runtime API `protocol.mob_movement_broadcast` reported mode
`auto_selected_captured_path`, source server frame `18818`, one matching
displacement path, one matching relative motion shape, one exact selected
shape observation, and one planned/sent packet. The real client rendered the
same predicted endpoint without receiving a frame selection from the caller.
Transcript
`generated_mob_auto_path_visual_20260809/1786290456741921955_replay_12857.jsonl`
folds validly to `(833,-2677)`/foothold `635`/stance `2`, one known broadcast,
five type-`0` commands, and 13/13 matched heartbeats.

`--emit-mob-movement-composed-path MAX_STEPS:X:Y:FOOTHOLD` plans a bounded
sequence when no direct unique displacement reaches the target. It excludes
all ambiguous displacement shapes, searches only moves that strictly reduce
Manhattan distance, bounds intermediate coordinates to `int16`, and rejects
zero or multiple shortest sequences. The `MAX_STEPS` bound is `2..8`.

The validated composed run changed the automatic command to:

```text
--emit-mob-movement-composed-path '2:881:-2677:635'
--mob-movement-step-delay-seconds 10
--transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/generated_mob_composed_path_visual_20260809
```

For the injected template-`100100` snail at `(785,-2677)`, the evidence catalog
contained 167 usable displacements and excluded 38 ambiguous ones. There was
no direct `(96,0)` primitive and exactly one shortest composition:
frame `18818` for `(48,0)`, then the same shape translated from the intermediate
state for another `(48,0)`. Runtime status reported source frames
`[18818,18818]`, intermediate `(833,-2677)`, predicted final `(881,-2677)`,
and two planned/sent packets. The client rendered the snail at that final
position. Transcript
`generated_mob_composed_path_visual_20260809/1786292585566000786_replay_12857.jsonl`
folds validly with two known broadcasts, ten type-`0` commands, no unknown mob,
final foothold `635`/stance `2`, and 11/11 matched heartbeats.

Generated movement plans now become one mutable scheduler per replay
connection. Scheduler construction rejects a change of entity, template,
field epoch, object, or any discontinuity in position, foothold, or stance.
It begins at the first step's `previous` state and advances only after the
matching encrypted packet has been written and `drain()` has completed. An
unexpected or out-of-order plaintext cannot advance it. The confirmed
movement prefix is retained beside the original post-transcript planning
baseline, so another in-process planning decision can fold only packets that
were actually transmitted.

`--mob-movement-step-delay-seconds SECONDS` controls only gaps between
consecutive scheduled movement packets. A matching explicit
`--post-transcript-gap-delay-seconds` still wins for that particular gap;
unrelated post-transcript frames continue to use the ordinary frame delay.
The option is nonnegative and requires a movement-emission option.

The runtime object keeps the immutable plan/evidence fields and adds:

```text
protocol.mob_movement_broadcast.packets_planned
protocol.mob_movement_broadcast.packets_sent
protocol.mob_movement_broadcast.packets_remaining
protocol.mob_movement_broadcast.state.phase               # planned/planning/in_progress/complete
protocol.mob_movement_broadcast.state.current             # x/y/foothold/stance
protocol.mob_movement_broadcast.state.target
protocol.mob_movement_broadcast.state.last_sent_step
protocol.mob_movement_broadcast.state.next_step
protocol.mob_movement_broadcast.state.confirmed_server_frame_count
protocol.mob_movement_broadcast.state.planning_server_frame_count
```

A second real-client run used the dedicated 10-second step delay. Before any
connection, status was `planned` at `(785,-2677)` with `0/2` packets sent.
After the first packet, status was `in_progress` at `(833,-2677)`, with one
packet remaining and step 2 still predicted at `(881,-2677)`. It then became
`complete` at that final state with `2/2` sent. Transcript
`generated_mob_scheduler_visual_20260809/1786294591708398631_replay_12857.jsonl`
folds validly with the two movement events 10.002838 seconds apart, two known
broadcasts, ten type-`0` commands, final foothold `635`/stance `2`, and 10/10
matched heartbeats. This validates both client effect and transmission-paced
state advancement; `drain()` confirms the local write, not a client-level
movement acknowledgement.

A startup-bounded follow-up queue can now make a second movement decision from
the transmitted state without exposing a mutation API. Repeat
`--queue-mob-movement-composed-path MAX_STEPS:X:Y:FOOTHOLD` at most eight
times after any initial movement-emission option. Each target remains
unplanned until the preceding decision is complete. The connection then calls
the existing composed-path planner with exactly the original baseline plus all
confirmed opcode-`282` packets. Capture analysis runs in a worker thread, so
the listener, client connection, and read-only HTTP status endpoint remain
responsive while the next decision is being computed.

The live queue proof used a one-packet automatic decision followed by a
two-packet composed decision:

```text
--emit-mob-movement-auto-path '833:-2677:635'
--queue-mob-movement-composed-path '2:929:-2677:635'
--mob-movement-step-delay-seconds 10
--transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/generated_mob_decision_queue_async_visual_20260809
```

After the first drained write, the API remained available in `planning` at
`(833,-2677)`: one known packet was planned/sent, no known packet remained,
decision 1 was complete, and `planning_decision_index` was `2`. Once the
capture-backed worker returned, status changed to three total planned packets
with decision 2 active and two packets remaining. It then exposed
`in_progress (881,-2677, 2/3)` and `complete (929,-2677, 3/3)`. The queue state
adds its eight-decision bound, total/planned/completed/remaining decision
counts, active/planning decision indices, and the still-unplanned safe target
list under
`protocol.mob_movement_broadcast.state.decision_queue`.

Transcript
`generated_mob_decision_queue_async_visual_20260809/1786296459661295020_replay_12857.jsonl`
folds validly with exact continuity
`785 -> 833 -> 881 -> 929`, three known broadcasts, fifteen type-`0` commands,
final foothold `635`/stance `2`, and 8/8 matched heartbeats. The first-to-second
movement gap is 42.500916 seconds because it includes the capture fold and the
configured ten-second pace; the second-to-third gap is 10.001710 seconds. The
HTTP service answered throughout the planning portion. This is a fixed
startup queue, not autonomous AI and not an HTTP command surface.

The immutable evidence is now folded once when the listener starts and retained
in a typed `MobMovementPlanningContext`. It owns the validated replay/evidence
analyses, all parsed captured paths and broadcasts, and stationary-shape counts.
Both the initial planner and every connection-local follow-up reuse it; mutable
mob position still comes only from each scheduler's confirmed frame prefix.
`protocol.mob_movement_broadcast.planning_cache` reports identifier-free cache
counts. For the live corpus those are 76 replay frames, 35,207 evidence frames,
5,284 captured paths/broadcasts, and stationary stance counts `2:17`, `4:1055`,
`5:437`.

A direct benchmark built the validated context in 10.432799 seconds, then
planned the initial automatic packet in 0.000360 seconds and the two-packet
follow-up in 0.005125 seconds. The cached real-client transcript
`generated_mob_decision_queue_cached_visual_20260809/1786297725914120609_replay_12857.jsonl`
again folds validly to `785 -> 833 -> 881 -> 929`, with three broadcasts,
fifteen type-`0` commands, final foothold `635`/stance `2`, and 6/6 matched
heartbeats. Its movement gaps are 10.008720 and 10.002057 seconds, so the former
32.5-second replanning pause is gone and only the configured ten-second pace
remains. The live API moved directly from the first confirmed state to three
known planned packets between one-second polls.

For a state-derived bounded policy instead of enumerated endpoints, use:

```text
--emit-mob-movement-auto-path '833:-2677:635'
--mob-movement-relative-policy '2:2:96:0:635'
--mob-movement-step-delay-seconds 3
```

The policy format is `DECISIONS:MAX_STEPS:DX:DY:FOOTHOLD`. Decisions are bound
to `1..8`, composed steps to `2..8`, and zero displacement is rejected. The
next endpoint is calculated only when the previous decision is confirmed
complete; derived coordinates must fit `int16`. It conflicts with explicit
queued targets and still requires one initial movement emission.

In the real-client proof, the initial automatic packet ended at `833`. Policy
decision 1 derived target `929` from that confirmed state and composed two
`(48,0)` packets; only after reaching `929` did decision 2 derive target `1025`
and compose two more. The API finished with three decisions and five packets
planned/sent, final foothold `635`/stance `2`, and the safe relative-policy
parameters under `state.decision_queue`. The client rendered the snail at the
predicted far-right endpoint. Transcript
`generated_mob_relative_policy_visual_20260809/1786298675748836952_replay_12857.jsonl`
folds validly through `785 -> 833 -> 881 -> 929 -> 977 -> 1025`, five known
broadcasts, twenty-five type-`0` commands, and 6/6 matched heartbeats. The four
movement gaps are 3.011704, 3.000499, 3.008745, and 3.001274 seconds, matching
the dedicated three-second pace.

Relative decisions may instead wait for a modeled live event:

```text
--mob-movement-relative-policy '2:2:96:0:635'
--mob-movement-policy-trigger matched-heartbeat
--world-heartbeat-interval-seconds 5
--mob-movement-step-delay-seconds 1
```

`matched-heartbeat` requires both a relative policy and periodic world
heartbeats. One response is matched only when an outstanding server opcode
`10` probe exists, and each match can start at most one still-pending policy
decision. It does not gate the initial movement packet. The first packet of an
authorized decision is sent immediately; `--mob-movement-step-delay-seconds`
still paces later packets inside that decision. The read-only status route
exposes `mode`, `awaiting_event`, `matched_events_observed`,
`decisions_started`, `decisions_completed`, and
`events_ignored_after_completion` under
`protocol.mob_movement_broadcast.policy_trigger`.

The real-client heartbeat-gated run reached an observable intermediate state
after its first match: decision 2 was active at `(881,-2677)`, with `2/3`
known packets sent, while the trigger counters were one event, one decision
started, and zero decisions completed. It ultimately reached `(1025,-2677)`
with all three decisions and five packets complete. Transcript
`generated_mob_heartbeat_policy_visual_20260809/1786299984499719895_replay_12857.jsonl`
folds validly with no warnings through
`785 -> 833 -> 881 -> 929 -> 977 -> 1025`, twenty-five type-`0` commands, and
21/21 matched heartbeats. The four movement gaps are 5.326966, 1.000527,
3.999752, and 1.000549 seconds: frames `78 -> 79` and `83 -> 84` show each
heartbeat response immediately preceding a new decision, while the roughly
one-second gaps are the configured pace within each two-packet decision.

All three event-driven triggers can share a deterministic post-decision
cooldown:

```text
--mob-movement-policy-trigger matched-heartbeat
--mob-movement-policy-cooldown-seconds 5
```

The bound is `0..3600` seconds and is rejected with the `immediate` trigger.
It starts only after every packet in one authorized decision has drained.
Otherwise-qualifying events inside the window are still counted but cannot
plan or send another decision; the first qualifying event at or after expiry
re-arms the pending policy. Safe trigger telemetry adds `cooldown_seconds`,
`events_rejected_by_cooldown`, `last_event_outcome`, and
`last_cooldown_remaining_seconds`.

The browser-free live proof used two-second heartbeats, a five-second
cooldown, and one-second intra-decision pacing. Response frame `78` authorized
movement frames `79`/`80`; responses `82`, `84`, and `86` arrived about
0.99, 2.99, and 4.99 seconds after completion and emitted no movement.
Response `88` arrived after expiry and authorized frames `89`/`90`. At that
point the API reported two decisions started/completed, three cooldown
rejections, and one later event ignored after completion. Transcript
`generated_mob_policy_cooldown_visual_20260809/1786303210604795485_replay_12857.jsonl`
folds validly with no warnings through
`785 -> 833 -> 881 -> 929 -> 977 -> 1025`, five broadcasts, twenty-five
type-`0` commands, and 16/16 matched heartbeats. The live client remained
connected throughout and kept answering probes.

Accepted event-driven decisions can also be capped independently of that
timer:

```text
--mob-movement-policy-trigger matched-heartbeat
--mob-movement-policy-event-budget 1
```

The budget is optional, bounded to `1..8`, and invalid for the immediate
trigger. An accepted event consumes one unit before planning. After exhaustion,
qualifying events remain observable but produce no plan or packet regardless
of cooldown state. Safe `policy_trigger` telemetry exposes `event_budget`,
`event_budget_used`, `event_budget_remaining`, and
`events_rejected_by_budget`; the rejection annotation uses
`reason: event_budget`. An encrypted integration test drives two matched
heartbeat responses into a two-decision policy with budget one, proves only
the first decision is planned and sent, and leaves the second decision
explicitly budget-blocked.

Recorded replays now preserve the scheduler side of that proof as safe
`runtime_event` JSONL records. Each qualifying trigger records an observation,
then a start/completion, cooldown rejection, or completed-queue ignore outcome.
The records contain only trigger mode, decision index, reason, and bounded
timing values; they do not contain object or account identifiers. The gameplay
analyzer merges them into the normal timestamp-ordered event stream with
`direction: runtime` and the preceding packet's frame index. Writers cap them
at 16,384 per transcript, report written/dropped totals in the close record,
and make any dropped annotations an analysis warning.

The browser-free annotation proof is
`generated_mob_policy_events_visual_20260809/1786304141212541434_replay_12857.jsonl`.
Its emitted events align the first observation/start with heartbeat-response
frame `78`, decision-`2` completion with movement frame `80`, three rejections
with frames `82`/`84`/`86` and exact remaining durations
`4.006931`/`2.007733`/`0.006772`, the re-armed start with frame `88`, and
decision-`3` completion with frame `90`. The fold is valid with no warnings,
ends at `(1025,-2677)`, and contains five broadcasts/twenty-five commands plus
15/15 matched heartbeats.

For a client-originated gameplay event instead of liveness, use:

```text
--reactive-mob-movement-acknowledgements
--mob-movement-relative-policy '1:2:96:0:635'
--mob-movement-policy-trigger served-mob-movement
```

This mode requires the typed reactive acknowledgement policy. A client opcode
`207` authorizes one decision only after its object/template/field checks pass
and the generated opcode `283` acknowledgement drains. Unknown or rejected
submissions do not trigger movement. While a relative decision is pending but
no qualifying event has arrived, `policy_trigger.awaiting_event` is true even
though the underlying decision queue describes its next unplanned target as
`planning`.

The bounded real-client proof injected both the typed spawn and controller
assignment for a template-`100100` snail. One authentic sequence-`1`
submission was accepted and acknowledged, then one `(+96,0)` decision moved
the server model from `833` through `881` to `929`. The live API completed
`3/3` packets with one event/decision and `awaiting_event:false`; periodic
heartbeats advanced independently. Transcript
`generated_mob_served_movement_policy_complete_20260809/1786300928969365966_replay_12857.jsonl`
is valid with no warnings. Frames `78 -> 79 -> 80` are the submission,
matched acknowledgement, and first generated movement packet; frame `81`
finishes the decision 1.000714 seconds later. The fold reports three known
broadcasts, fifteen type-`0` commands, one matched movement pair, no pending or
unmatched movement, and 4/4 matched heartbeats.

For a geometric gameplay predicate, use:

```text
--mob-movement-relative-policy '1:2:96:0:635'
--mob-movement-policy-trigger player-proximity
--mob-movement-proximity-radius 64
```

The radius is a required Manhattan-distance bound in `1..4096`. Each typed
local-player opcode `182` compares its explicit path-end coordinates with the
movement scheduler's transmission-confirmed mob position. The trigger is
edge-based: the first in-radius observation, or a later outside-to-inside
transition, can authorize one decision; repeated observations while already
inside cannot. Safe `policy_trigger.proximity` telemetry reports the radius,
observation/entry counts, prior inside state, and the last player/mob
coordinates, distance, and predicate result.

The real-client negative control used direct nested-Wayland Left input and
observed player endpoint `(548,-2652)`, distance `310` from mob
`(833,-2677)`. Two typed observations remained outside, with no entry or
decision. Direct Right then produced four more observations; frame `107`
ended at `(855,-2695)`, distance `40`, and became the first entry. Generated
movement frames `108`/`109` followed 0.009526/1.001263 seconds later and
completed `833 -> 881 -> 929`. Transcript
`generated_mob_player_proximity_policy_visual_20260809/1786301943288947015_replay_12857.jsonl`
folds validly with no warnings: seven total player submissions (one replayed,
six predicate observations), three known mob broadcasts, fifteen type-`0`
commands, and 11/11 matched heartbeats.

## Historical synthetic staging experiment

The replay can patch captured server frames, react to a decrypted client
opcode, append plaintext frames, and control every gap independently. The
current experiment uses these post-transcript plaintext messages in order:

```text
queued opcode-13 acknowledgment
opcode-1 bounded account-success probe
opcode-2 world 0 / channel 0 record
opcode-2 signed-id -1 sentinel
```

Use repeated `--post-transcript-gap-delay-seconds` values for the gaps in that
combined sequence. The current diagnostic timing is `0,15,120`: no wait before
the account frame, 15 seconds before the world record, then two minutes before
the sentinel. The long final gap permits a pre-sentinel structural dump because
the sentinel consumes or clears the controller's staging list. If fewer gap
values are supplied, later gaps fall back to
`--post-transcript-frame-delay-seconds`.

`--send-after-transcript` and `--send-zero-filled-after-transcript` share one
argument destination, so their command-line order is preserved. This matters:
an earlier implementation grouped explicit frames ahead of zero-filled frames
and accidentally sent the world list before the account transition.

Captured server frame index `3` is a 12-byte opcode-`0` status whose result
byte is `2`; replaying it produces the policy-restriction dialog. Replace the
whole frame with heartbeat `0a00`. Rewriting only its result byte to zero is
not a success path—it displays “Logging in, please wait.”

The two-byte opcode-`1` transition probe bypasses required controller setup.
Use `--send-zero-filled-after-transcript 1:128:0` to let the original handler
initialize its state. The current canonical diagnostic command is:

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server

sudo ip netns exec mapleproxy sudo -u sdancer python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12082 \
  --no-strict \
  --transcript /home/sdancer/ms/downloads/maple_protocol_captures/1786118307321677094_13.115.120.13_10282.jsonl \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/login \
  --initial-delay-seconds 20 \
  --hold-open-seconds 300 \
  --server-frame-patch 0=000000010000000000000400740065007300740000000000000000000000000000000000 \
  --server-frame-patch 3=0a00 \
  --reply-on-client-opcode 13=0d0000 \
  --send-zero-filled-after-transcript 1:128:0 \
  --send-after-transcript 0200000400740065007300740000000000000000000001060074006500730074002d0031000000000000000000000000000000 \
  --send-after-transcript 0200ff \
  --post-transcript-gap-delay-seconds 0 \
  --post-transcript-gap-delay-seconds 15 \
  --post-transcript-gap-delay-seconds 120
```

For a structural run, arm
`tools/gdb_stage_opcode2_controller_capture.py` with action `arm` after the
module is loaded, poll with action `status`, restore after capture, and use
action `dump` before the sentinel. It validates the handler and executable
padding bytes and never remains attached. Do not use the persistent breakpoint
probe for timing-sensitive runs; it stalls Wine rendering.

## Replay the `58880` exchange

The namespace redirects destination port `58880` to local port `12080`:

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server

sudo ip netns exec mapleproxy sudo -u sdancer python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12080 \
  --no-strict \
  --transcript /home/sdancer/ms/downloads/maple_protocol_captures/1786118312530175497_54.238.121.146_58880.jsonl \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/world
```

Start both listeners in separate terminals, then use the direct client launch
from `CLIENT.md`.

## Stub and capture-proxy modes

Minimal stub:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer python -m maple_server stub \
  --listen-host 0.0.0.0 \
  --listen-port 12082 \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/stub
```

The package also provides a direct `capture-proxy` mode. Its proxy password is
read from `MAPLE_PROXY_PASSWORD`; never pass it as a CLI argument. See the
project's own `README.md` for all options.

## Proven behavior

- The custom login replay served 22,074 bytes identical to the recorded
  official server stream.
- A fresh client sent 1,335 bytes; the first 159 bytes matched the recorded
  client session before per-session material diverged.
- Both login and `58880` connections were served locally; the upstream relay
  saw neither port during the proof run.
- The finite transcript closes after its recorded events. The client then
  reconnects approximately every 2.2 seconds, so stop it promptly or add a
  hold-open/stateful server behavior before long tests.
- The screenshot of the local replay result is at
  `/home/sdancer/ms/downloads/maple_custom_server_replay.png`.
- Native client opcode `13` is decryptable and can be acknowledged reactively.
- Direct transition probes reached the real world and character scenes.
- Replaying captured frame `3` causes the policy dialog; replacing it with a
  heartbeat removes the dialog while preserving the remaining setup stream.
- The original account handler accepts the bounded zero-filled probe, creates
  an empty world staging list, and reaches the world-selection UI after its
  informational modal is dismissed.
- A corrected 51-byte opcode-`2` record is structurally intended to describe
  one world and one channel; its strings require a trailing byte after their
  UTF-16LE contents. The handler is confirmed to run, but the live count must
  still be sampled before the sentinel clears the staging list.
- Uniform post-frame timing delivered world packets during the opcode-`1`
  scene change, before the opcode-`2` handler was active. Per-gap scheduling
  was added specifically to remove that race.
- The successful PCAP account packet, five full 60-channel worlds, sentinel,
  selections, and handoff all pass the typed packet/state validator.
- A live capture-backed replay renders the five world tabs and their online
  channels. Client opcode `4` identifies the selected world.
- The two opcode-`402` packets require their observed 2.5-second gap; sending
  them together stalls before the client emits channel opcode `5`.
- With the gap and live-world rewrite, the client emits opcode `5` and accepts
  the character list and server time. Withholding the captured opcode-`23`
  response until native client opcode `6` completes the security exchange; the
  client then emits character opcode `7`, accepts the rewritten handoff, and
  connects to the local world replay.
- Proactively sending a valid handoff without that gate produces a black scene,
  no world-port connection, and client exit after the login socket closes.
- The MapleStory PipeWire stream is kept muted by the enabled
  `maplestory-audio-mute.service`, using application identity rather than a
  changing node number.
- A typed initial opcode-`157` HP rewrite changed `50/222 -> 1/222`; the real
  HUD and independently folded active game state both reported `1/222` while
  map, inventory, progression, and client liveness matched the prediction.
- The gameplay analyzer now emits typed local/remote player movement records
  and folds their endpoints instead of reporting opcodes `182` and `202` as
  unknown packets. Those movement families add no validation warnings in
  either PCAP world stream.
- The analyzer now structurally decodes life movement opcodes `47`/`217`,
  folds command and client-tail distributions, redacts the client token, and
  validates all 2,932 packets from stream `126` without a shape failure.
- World-session opcode `13` now uses the neutral fixed/length-prefixed envelope
  decoder, accounting for all 970 long-corpus packets without exposing bodies.
- Client opcode `217` now has bounded compact and counted-record envelopes,
  accounting for all 937 long-corpus packets while deliberately remaining out
  of replay until its effect semantics are established.
- Empty server opcode `426` and client opcode `309` now fold as a one-for-one
  notification/acknowledgement pair across all three gameplay streams, with
  full shape coverage and explicit unmatched/pending telemetry.
- Client opcode `101` now folds all 219 sustained-capture packets into neutral
  five-field distributions with exact byte consumption and round trips.
- Client opcodes `50`/`52`/`54` now fold 961 sustained-capture attack actions
  with aliased mob targets where present; server opcodes `218`/`219` fold 183
  attack relays with packed target/hit counts, 194 typed target records, and
  254 damage words. The 141 ranged relays additionally type skill/projectile/
  animation metadata and signed positions; all 42 close-range relays type their
  common/full metadata and short placeholder distinction. The extended client
  suffixes add 646 typed damage words and 607 per-hit health matches with no
  pending effects after lifecycle cleanup. Official-client max HP predicts
  364/370 testable health transitions exactly and bounds the other six to a
  one-HP difference; none of those six has an intervening modeled relay, and
  their inferred damage deltas are `{-1: 1, +1: 5}`. Unresolved semantic roles
  and the delayed differences remain out of generation and replay.
- All 333 long-stream opcode-`41` stat packets now round-trip and fold into
  player state. A generated HP-mask packet produced the predicted live
  `50/222 -> 1/222` HUD and event-state change without disturbing liveness.
- All 69 stream-`92` opcode-`39` packets now round-trip and fold 71 inventory
  modifications. A generated Use-slot quantity update produced the predicted
  live `27 -> 1` inventory UI and event-state effect without losing liveness.
- All 17 stream-`92` opcode-`80` requests now round-trip and correlate with
  exact stack decrements plus potion stat effects. A reactive live request
  produced the predicted red-potion `2 -> 1` and HP `50 -> 100` effects, with
  zero mismatches and continued heartbeats.
- All 125 stream-`92` opcode-`311` packets round-trip and fold into 66 drop
  lifecycles. All 54 pickup requests, gain values, effects, and local removals
  correlate with an active spawn; stream `114` ends with one modeled active
  item drop rather than none.
- The typed stream-`114` pickup plan resolves `drop:1`, item `4000004`, Etc
  slot `7`, quantity `74`, and the four matching stream-`92` effects. Its
  position rewrite round-trips at the same 38-byte width, and encrypted replay
  tests produce the predicted opcodes `39,49,312` and mutable `74 -> 75` state.
- Live owner-only and captured-shaped animated-drop probes produced zero
  opcode-`185`/`222` requests. A fresh typed source-mob control also remained
  negative across delayed leave, immediate enter/leave, and explicit
  controller-release variants, so owner/proximity/source history and lifecycle
  timing remain modeled relations rather than proof of pickup eligibility.
- The exact first reference-admitted `4000004` combat/reward/drop family did
  produce a real live opcode-`185` request. One guarded `[39,49,312]` response
  changed Etc quantity `74 -> 75` and removed the drop. Sixty-one later
  same-drop attempts coalesce as retries of that one completed chain, leaving
  the active fold warning-free with 900/900 heartbeat pairs.
- A second officially admitted pair was requested twice without replaying its
  source mob, combat, or reward prefix and before any fresh pickup input. One
  unanswered ten-attempt chain was explicitly interrupted; the reinjected
  four-attempt chain completed `75 -> 76`. The fold distinguishes both cases,
  has no pending pickup or warnings, and retains 1,064/1,064 heartbeat pairs.
- A cold client/world control replayed that exact pair with a 394.575-ms
  release and then the full first admitted family with a calibrated 64.085-ms
  attack-to-HP response and 450.850-ms release. Capture-timed physical pickup
  input still produced zero requests. After cleanup the active warning-free
  fold has no pickup chains or pending work and 180/180 heartbeat pairs. The
  fold now emits drop/release age telemetry for every admitted request and
  release event so future controls compare the causal timing directly.
- An opt-in reactive mob-health policy now adopts exact typed mob state and
  emits per-hit opcode-`293` updates plus opcode-`280` reason `1` on death. A
  real typed-snail injection received opcode-`52` damage `[27,32]`, produced
  the predicted `[293,280]` response and `8 -> 0` lifecycle, folded validly,
  and kept the client/heartbeat exchange active. Official ±1 HP authority
  adjustments and attack-relay synthesis remain outside that exact policy.
- Login opcode `4` now parses and re-emits typed character stats, appearance
  slot maps, optional rankings, and the fixed trailer. The one-record
  `111.pcapng` and empty `1-10FS.pcapng` variants both round-trip exactly. A
  browser-free live replay using `?character-list` rendered the predicted
  level/job/stats, reached character selection without a stall, handed off on
  opcode `7`, and entered the local gameplay replay; its strict login fold has
  full character-list coverage and no issues or warnings.
- Login heartbeat traffic now shares the exact world codecs and is folded as
  empty server opcode-`10` probes plus ten-byte client opcode-`23` responses.
  Stream `83` has one match, stream `116` has four probes/three matches/one
  pending probe, and the current local login has eight matches with no
  unmatched or pending response. Safe reports retain only token width and
  round-trip counters/timing.
- Login client opcode `31` now has one shared variable codec and manifest shape
  across the `183`-, `275`-, and `201`-byte stream-`83`/stream-`116`/live
  records. The exact boundary is a zero prefix, variant `2`, three terminated
  counted UTF-16 fields, a fixed 48-byte length-prefixed opaque blob, and a
  zero suffix. Safe reports expose only text-length patterns and blob byte
  totals, leaving all retained contents and their higher-level purpose neutral;
  at that checkpoint, only opcode `6` remained unknown in the live login.
- Login client opcode `6` now closes that live unknown inventory with a shared
  `42 + 6*count` record-set shape. Stream `83` carries 299 entries; stream `116`
  and live each carry 152. Each entry is a unique `uint16` index covering the
  complete `0..count-1` set plus a redacted `uint32` value, following nine
  redacted header words and the count. Safe state publishes only counts and
  boundary checks; all values and the higher-level record-set role stay neutral.
- Nested UI pointer input now stays on the Sway seat, and the checked-in
  `send_wayland_evdev_key.py` helper sends physical evdev codes directly over
  Wayland for Unity raw input without `xdotool` or the host cursor.

## Next server milestone

Replace the remaining opaque replay portions with stateful handling:

1. Isolate the client-side state transition that initializes pickup admission;
   the fresh exact-pair and calibrated full-family controls now exclude
   pair/release timing and near-reference attack-response timing alone. Continue
   to gate `[39,49,312]` on an authentic opcode `185` or compact opcode `222`
   request.
2. Deepen the remaining capture-bounded gameplay bodies only where generated
   handlers, independent captures, or controlled effects support exact fields;
   retain neutral roles for the opcode-`394`/`279` correlation.
3. Reuse the proven typed final-field mob injection to validate the existing
   movement-acknowledgement policy through the real client.
4. Capture a ranked or multi-character account to validate the conditional
   four-`int32` character ranking branch and record-count loop independently.
5. Name the remaining neutral account, character-list style/trailer,
   equipment, progression, and field-trailer fields only when independent
   captures or controlled effects support them.
