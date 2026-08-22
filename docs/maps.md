# Map capture and replay coverage

The `1-10FS` level-1-through-10 capture spans many maps. The project is not
limited to the single Ellinia snapshot used by the current physics-lab
launcher.

## Captured coverage

| Measurement | Value |
| --- | --- |
| World TCP stream | `126` |
| Field epochs | 36 |
| Server opcode-`157` snapshots/transitions | 36 |
| Distinct map IDs | 21 |
| Captured progression | Level 1 through level 10 |

The distinct captured map IDs are:

`0`, `10000`, `20000`, `20001`, `30000`, `40000`, `40001`, `40002`,
`50000`, `50001`, `60000`, `1000000`, `1000004`, `1010000`, `1010002`,
`1020000`, `100050000`, `101000000`, `101000003`, `101000004`, and
`104000000`.

This route includes Lith Harbor (`104000000`) and Ellinia (`101000000`), along
with the tutorial and beginner-island fields traversed during leveling.

## Current live-lab status

The Wine + Frida RL run completed so far used the stream-`114` replay and map
`101000000` (Ellinia). Consequently, the saved policy weights have only been
trained and validated live on Ellinia. This is a launcher/configuration
limitation, not a capture-data limitation.

The next multi-map step is to segment the `1-10FS` stream by field epoch,
replay its opcode-`157` transitions, select the corresponding prefab for each
map ID, and train or evaluate the policy within each captured field.

## Local evidence

- Decoded packets:
  `tools/il2cpp_packet_dump/target/private/1-10FS.stream-126.jsonl`
- Field boundaries and map IDs:
  `/home/sdancer/ms2/captures/1-10FS.stream-126.c2s-gamestate.jsonl`
- Leveling route:
  `/home/sdancer/ms2/captures/levels-1-10.stream-126.json`
