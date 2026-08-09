# Status as of 2026-08-09

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
- The custom-server suite currently passes all 149 tests.
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
  25,597 full, 43,954 partial, 1,549 unknown-but-lossless, and zero invalid
  packet observations. Stream `92` now reports 12,976 full, 21,604 partial,
  627 unknown, and zero invalid; stream `114` reports 16/14/46/0. Thirteen
  long-corpus state-correlation warnings remain: the prior 12 plus one
  aggregate warning for six one-HP combat prediction differences.
- The level-1-to-10 corpus expands opcode-`41` to all observed level, job,
  primary-stat, current/max HP/MP, AP/SP, EXP, and mesos masks. All 841 stat
  packets round-trip and the fold ends at level `10`, job `200`, HP `114/194`,
  MP `158/285`, EXP `980`, and mesos `1472`.
- The same corpus expands opcode-`39` to equipment adds, cash-tab stack adds,
  and operation-`2` equip moves. All 256 change sets and 232 modifications
  decode and fold with zero unknown-slot mutations. Its 78 opcode-`300` NPC
  spawns also validate after preserving the facing byte values `0/1/2/4/5`.
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
  attack relays or claim to reproduce the six official ±1 HP adjustments.
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
- Client opcode `185`, server opcode `49`, and server opcode `312` now form a
  typed item-pickup chain. All 54 stream-`92` requests round-trip (48 base and
  six extended), match their folded field epoch, inventory/mesos/special
  result, and exact drop-id removal. All 100 field-drop removals round-trip;
  the 54 local chains have zero effect/removal mismatches and zero pending
  requests.
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
  controller.
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
server 4    170-byte character list (inner records still partial)
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
the last identifier-free response plan. The HTTP listener remains read-only
and loopback-only, using namespace/OS access as its current security boundary.

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
expected encrypted write drains. The read-only API observed the live sequence
as `planned (785,-2677, 0/2)`, `in_progress (833,-2677, 1/2)`, then `complete
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
32.5 seconds, it runs off the asyncio loop. The read-only API remained
responsive throughout with `phase=planning`, one sent packet, zero currently
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
Safe cache counts are available through the read-only API.

A bounded relative-movement policy now derives targets from confirmed state
instead of requiring every endpoint at startup. With two `(+96,0)` decisions,
the client and API followed `833 -> 929 -> 1025`; each target was created only
after its predecessor completed. Runtime finished three decisions and five
packets at the predicted foothold/stance. The frozen transcript validates
`785 -> 833 -> 881 -> 929 -> 977 -> 1025`, twenty-five type-`0` commands, four
approximately three-second gaps, and 6/6 heartbeats. Policy count, displacement,
step bound, and foothold remain safe/read-only API state.

Those relative decisions can now be gated by the modeled server-opcode-`10` /
client-opcode-`23` heartbeat match instead of chaining immediately. One match
starts at most one pending decision; the initial movement remains
unconditional, and the configured packet pace still applies inside a composed
decision. A browser-free real-client run exposed decision 2 mid-flight at
`(881,-2677)` after the first match, then completed all five packets at
`(1025,-2677)` after the second. The independent transcript is valid with
21/21 heartbeats and exact movement gaps 5.326966, 1.000527, 3.999752, and
1.000549 seconds. Runtime trigger telemetry finished with three matched events,
two decisions started/completed, and one post-completion event ignored; HTTP
remains read-only.

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
`awaiting_event:false`; HTTP remains read-only.

Two debugger hazards remain: attaching during Unity/NGS startup can invalidate
the run, and leaving GDB attached stalls Wine rendering even after startup.
Use only short validated patches or the transparent opcode-`2` trampoline.

## Immediate next steps

1. Decode the captured opcode-`4` character-list inner records and generate the
   list from typed player state rather than replay bytes.
2. Use the owner/proximity negative controls to isolate the remaining
   client-side drop eligibility condition; serve a reactive pickup only after
   observing an authentic opcode-`185` request.
3. Promote the complete initial opcode-`157` model from a safe one-field
   mutation to a generated field snapshot, then replace more finite replay
   frames with state-driven emitters.
4. Add a bounded local-player/mob proximity predicate as the next modeled
   movement-policy trigger, retaining deterministic cooldowns and the read-only
   HTTP boundary.

## Useful proof artifacts

```text
/home/sdancer/ms/downloads/maple_custom_server_replay.png
/home/sdancer/ms/downloads/maple_direct_current_screen.png
/home/sdancer/ms/downloads/maple_tw_postgate_screen.png
/home/sdancer/ms/downloads/maple_protocol_captures/
/home/sdancer/ms/downloads/maple_protocol_captures/hk_official_reference_20260808/
/home/sdancer/ms/downloads/maple_custom_server_observed/
```
