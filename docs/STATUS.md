# Status as of 2026-08-08

## Working

- The complete client and NGM are installed in the dedicated Wine prefix and
  render inside nested Sway/Xwayland on display `:1`.
- The persistent browser session and CDP helper have issued fresh authenticated
  HK launch tickets without printing credentials or ticket contents. After the
  cookies were deliberately cleared during the latest run, Beanfun began
  returning temporary login-flow timeout `01004`; no fresh ticket has been
  issued since that cooldown began.
- The `mapleproxy` namespace transparently relays ordinary TCP and redirects
  login port `10282` to local port `12082` and handoff port `58880` to `12080`.
- Lossless JSONL capture, strict/non-strict replay, frame patching, reactive
  opcode replies, hold-open, and independently timed post-transcript frames
  are implemented.
- Protocol-300 greeting parsing, encrypted-frame framing, Maple AES payload
  encryption/decryption, and IV shuffling are implemented and tested.
- The custom-server suite currently passes all 31 tests.
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
  packet. A transparent process-local trampoline confirms that the handler is
  entered without leaving GDB attached.

## Proxy result

The official HK proxy was tested explicitly and is the current route. The
earlier conclusion that all-HK exited before login was a topology error: the
redirect for destination port `10282` lives inside `mapleproxy`, while the
replay listener had been started on the host. Once the listener also ran inside
the namespace, an all-HK browser/game launch connected to the custom login
server immediately. Alternatively, an explicit namespace-to-host bridge would
be required.

`ss` on the host cannot see the relay or replay listeners. Inspect them with
`sudo ip netns exec mapleproxy ss -ltnp`. Both HK and Taiwan exits were also
tested during the current browser-login timeout and returned the same Beanfun
`01004`, ruling out proxy geography as its immediate cause.

## Current custom-server result

The first encrypted login stages are decoded and controllable:

1. server opcode `0`: NGS challenge;
2. client opcode `13`: native NGS result (observed result selector `15`);
3. server opcode `13`: accepted acknowledgment (`0d0000` in the current probe);
4. server opcode `1`: account/login result and controller transition;
5. server opcode `2`: world records, terminated by world id `-1` (`ff`).

The replayed official frame at server index `3` carries the stale rejection.
Replacing all non-heartbeat frames removed it; restoring frames individually
then isolated index `3`. Replacing the whole frame with `0a00` is preferable to
changing its result byte to zero: result `0` displays “Logging in, please wait”
and is another status, not a demonstrated success response.

The original opcode-`1` handler needs more than the earlier two-byte probe.
Giving it a bounded 128-byte zero-filled payload initializes the controller and
world list. Its modal can be dismissed to reveal the world-selection board.
The opcode-`2` handler is deferred until roughly 60–80 seconds into current
runs; the `-1` sentinel consumes/clears the staging list, so structural dumps
must occur before the sentinel. The latest pre-sentinel validation was ready
but could not be launched after the website ticket cooldown began.

Two debugger hazards remain: attaching during Unity/NGS startup can invalidate
the run, and leaving GDB attached stalls Wine rendering even after startup.
Use only short validated patches or the transparent opcode-`2` trampoline.

## Immediate next steps

1. Re-establish a fresh website ticket after Beanfun timeout `01004` clears.
2. Run the replay listener inside `mapleproxy`, patch captured frame `3` to a
   heartbeat, and let the original opcode-`1` handler consume the 128-byte
   bounded payload.
3. Arm the transparent opcode-`2` controller capture and delay the sentinel
   long enough to dump world/channel counts before the staging list is cleared.
4. Verify and select the real one-world/one-channel entry.
5. Decode the resulting character-list request/response and bring the first
   disposable character into a map.

## Useful proof artifacts

```text
/home/sdancer/ms/downloads/maple_custom_server_replay.png
/home/sdancer/ms/downloads/maple_direct_current_screen.png
/home/sdancer/ms/downloads/maple_tw_postgate_screen.png
/home/sdancer/ms/downloads/maple_protocol_captures/
/home/sdancer/ms/downloads/maple_custom_server_observed/
```
