# Confirmed protocol facts

## Login greeting

Login begins with a 33-byte cleartext greeting. One captured greeting was:

```text
1f00 2c01 0300 330030003000 6e3c795a 885db958 04
2c010000 2c010000 00000000
```

Parsed fields:

```text
packet payload length: 31
protocol version:      300
subversion:            UTF-16LE "300"
IV 1:                  6e 3c 79 5a
IV 2:                  88 5d b9 58
locale:                4
trailing build words:  300, 300, 0
```

The IV values are session material; do not assume this example applies to a
new connection.

## Encrypted-frame header

Each encrypted login frame starts with four bytes. Its payload length is:

```text
uint16_le(header[0:2]) XOR uint16_le(header[2:4])
```

This framing is implemented in:

```text
/home/sdancer/ms/tools/maplestory_classic_server/maple_server/protocol.py
```

Known packet payload lengths from the first complete official session:

```text
client -> server: 275, 954, then seven packets of 10 bytes
server -> client: 27, 164, 21770, 12, 6, then seven packets of 2 bytes
```

The second session had the same core sequence and continued producing
heartbeat-sized packets until capture stopped.

## Payload cipher

The protocol-300 payload cipher is implemented in
`tools/maplestory_classic_server/maple_server/protocol.py`. Each direction has
its own four-byte IV. A frame is decrypted with the current IV, then that IV is
advanced with the recovered Maple shuffle routine. Appended synthetic server
frames must continue from the IV after the last replayed server frame; reactive
client reads must advance the client IV in the same way.

This implementation is validated by observed ciphertext/header vectors and by
round-trip tests. The former assumption that the cipher constants were still
the main blocker is obsolete.

## Login opcodes recovered so far

```text
server 0   NGS challenge
client 13  native NGS result/proof (observed result selector 15)
server 13  NGS result acknowledgment
server 1   account/login result
server 2   one world record, or a signed world-id -1 sentinel
```

The custom replay currently ignores the opaque native proof and acknowledges
opcode `13` with plaintext `0d0000`. That is enough for the client to continue
into the login controller. It is a local-server behavior, not a claim that the
official NGS proof has been reproduced.

The captured server frame at index `3` is a second opcode-`0` message with
plaintext result byte `2`. It is the direct source of the replayed
account-policy dialog: replacing only this frame with heartbeat `0a00` removes
the dialog. Changing result `2` to `0` instead displays “Logging in, please
wait,” so zero is not yet proven to mean unconditional success for this
message.

The earlier two-byte opcode-`1` probe could trigger a controller transition but
bypassed required account state. A bounded 128-byte zero-filled opcode-`1`
payload lets the original handler run, creates its empty world staging list,
and reaches world selection after an informational modal is dismissed. This is
still a structural probe, not a decoded production account response. Direct
transition probes separately established state `1` as world selection and
state `2` as character selection.

## World-list packet (`server opcode 2`)

The current parser model is:

```text
uint16 opcode = 2
int8   world_id
string world_name
uint8  world_flag
string event_description
uint16 event_exp_rate
uint16 event_drop_rate
uint8  channel_count
repeat channel_count:
  string channel_name
  int32  population
  uint8  world_id
  uint8  channel_id
  uint8  adult_channel
  int32  unknown
uint16 balloon_count
repeat balloon_count:
  uint16 x
  uint16 y
  string message
```

Every `string` above is encoded as a little-endian `uint16` UTF-16 character
count, followed by that many UTF-16LE code units, followed by one additional
byte consumed by the client string reader. Omitting that byte shifts every
subsequent field. A separate three-byte packet `02 00 ff` ends the world list.

The current 51-byte test packet describes world `0` named `test`, with one
channel named `test-1`, zero population, and no balloons. Do not place the raw
hex in general logs; the replay command in `CUSTOM_SERVER.md` is the canonical
lab recipe.

A transparent process-local trampoline confirms that opcode `2` reaches the
build-specific handler without leaving GDB attached. The signed-id `-1`
sentinel consumes or clears the controller's staging list, so world/channel
counts must be inspected before the sentinel rather than after it.

## `58880` exchange

The client sent a stable HTTP/1.1 request:

```http
GET / HTTP/1.1
Host: 54.238.121.146:58880
Cache-Control: no-cache
```

The response was 218 bytes and had the fixed body:

```text
aewwawuiaryatp
```

Date and cache/entity metadata varied. The role appears to be a probe or
handoff rather than the encrypted login channel.

## Bootstrap connection

An additional TLS connection was captured at `54.65.46.47:5050`, with roughly
842 client bytes and 4,544 server bytes in the first observed exchange. It has
not yet been decoded.

## Capture inventory

Primary captures live in:

```text
/home/sdancer/ms/downloads/maple_protocol_captures/
```

Important files:

```text
1786118307321677094_13.115.120.13_10282.jsonl
1786118506764535468_52.193.141.80_10282.jsonl
1786118312530175497_54.238.121.146_58880.jsonl
1786118511968891795_54.238.121.146_58880.jsonl
1786118473811233268_54.65.46.47_5050.jsonl
```

## Current unknowns

- The complete successful opcode-`1` account payload is not decoded; the
  bounded zero-filled probe only supplies enough data for structural progress.
- The character-list opcode and minimum character/map handoff payload are not
  yet decoded.
- The purpose and required state for the TLS `5050` connection remain unknown.
- The exact semantics of captured opcode-`0` result values other than the
  observed policy result `2` remain unknown.
