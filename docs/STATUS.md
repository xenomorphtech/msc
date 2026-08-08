# Status as of 2026-08-08

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
- Lossless JSONL capture, strict/non-strict replay, frame patching, reactive
  opcode replies, hold-open, and independently timed post-transcript frames
  are implemented.
- PCAP TCP reassembly, Maple endpoint identification, frame normalization,
  private PCAP-frame sourcing/transforms, and per-opcode reactive response
  timing are implemented.
- Protocol-300 greeting parsing, encrypted-frame framing, Maple AES payload
  encryption/decryption, and IV shuffling are implemented and tested.
- Login logs now fold into typed game state with full/partial/unknown/invalid
  shape confidence. The successful reference ends at validated
  `handoff_ready` state.
- The custom-server suite currently passes all 56 tests.
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
- `/home/sdancer/Downloads/111.pcapng` supplies a separate successful
  protocol-compatible reference: login stream `83` and world stream `92`.
- Stream `83` validates five 60-channel world records, world `4`/channel `23`
  selection, character selection, and a matching `43.142.194.150:8587`
  handoff. Its private numeric identifiers are redacted in normal output.
- The live capture-backed server renders five world tabs and online channels.
- Capture-faithful opcode-`402` timing plus the live selected-world rewrite now
  makes the client emit channel-selection opcode `5` and enter the character
  controller.
- The enabled user service `maplestory-audio-mute.service` continuously mutes
  only PipeWire nodes named `Maplestory_Classic.exe` across relaunches.

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
opcode `134`, the reference sends opcode `13` message type `7` with a
length-prefixed 27-byte opaque body. The official client answers with three
type-`6` messages and then character-selection opcode `7`. A direct launch has
not reproduced those type-`6` bodies yet. Skipping the exchange and sending a
valid transformed handoff immediately is not sufficient: the scene goes
black, no connection reaches local port `12857`, and the client exits after
the login socket is closed. This proves the client-side completion/selection
state is required, without implying that a custom server must validate the
opaque proof contents.

Two debugger hazards remain: attaching during Unity/NGS startup can invalidate
the run, and leaving GDB attached stalls Wine rendering even after startup.
Use only short validated patches or the transparent opcode-`2` trampoline.

## Immediate next steps

1. Complete or safely bypass the type-`7`/type-`6` client security transition
   and obtain live character opcode `7`.
2. Validate the captured opcode-`4` character-list envelope in the local
   controller and decode its 167-byte inner records.
3. Select the character, verify opcode `7`, and follow the endpoint-rewritten
   handoff into the local stream-`92` listener.
4. Replace initial world/map replay with typed stateful packets.

## Useful proof artifacts

```text
/home/sdancer/ms/downloads/maple_custom_server_replay.png
/home/sdancer/ms/downloads/maple_direct_current_screen.png
/home/sdancer/ms/downloads/maple_tw_postgate_screen.png
/home/sdancer/ms/downloads/maple_protocol_captures/
/home/sdancer/ms/downloads/maple_protocol_captures/hk_official_reference_20260808/
/home/sdancer/ms/downloads/maple_custom_server_observed/
```
