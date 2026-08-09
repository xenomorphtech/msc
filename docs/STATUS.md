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
- The custom-server suite currently passes all 126 tests.
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
  25,597 full, 43,132 partial, 2,371 unknown-but-lossless, and zero invalid
  packet observations. Twelve state-correlation warnings remain.
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
- Client opcode `54` now has an exact 24-byte record with one u32 control value,
  two flag bytes, and four more u32 values. All 120 stream-`126` and 31
  stream-`92` packets round-trip. The fold records flag/value distributions and
  bounded ranges but does not apply an effect because the numeric roles remain
  unproven.
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
  Sway/Xwayland, verifies both namespace listeners and the audio service, optionally
  cold-restarts the Wine prefix, and focuses the new window through Sway.

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

## Useful proof artifacts

```text
/home/sdancer/ms/downloads/maple_custom_server_replay.png
/home/sdancer/ms/downloads/maple_direct_current_screen.png
/home/sdancer/ms/downloads/maple_tw_postgate_screen.png
/home/sdancer/ms/downloads/maple_protocol_captures/
/home/sdancer/ms/downloads/maple_protocol_captures/hk_official_reference_20260808/
/home/sdancer/ms/downloads/maple_custom_server_observed/
```
