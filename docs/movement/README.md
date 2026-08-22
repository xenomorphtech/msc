# Client-side movement

MapleStory Classic computes walk, jump, climb, drop-through, and knockback
inside the Unity `VecCtrl` on the official client. The custom server does not
simulate those ticks. It only accepts the serialized path the client already
ran (`client opcode 182` for the local player, `client opcode 47` for other
life) and, later, will need the same ballistic bounds to decide whether a
submitted path was possible.

This directory is the working note for that contract and for proving that the
reconstructed bounds can still reach every spawn, portal, and ladder a
beginner can physically use.

- [PHYSICS.md](PHYSICS.md) — VecCtrl types, constants, packet commands
- [REACHABILITY.md](REACHABILITY.md) — foothold graph, auditor, map results

## What is client-side

The client owns:

- left/right walk along footholds
- jump (Alt / action 53)
- jump-down / drop through a platform (down + jump)
- climb up/down ladders and ropes
- knockback from contact (disabled for these audits)

The server owns:

- which map the character is on
- whether a portal/field-transfer request is accepted (`client opcode 43` →
  `server opcode 157`)
- whether a mob exists to collide with

For movement-reachability work, mobs are omitted. Stream `114` already has no
mob lifecycle packets; `--omit-mob-spawns` drops opcodes `218/219/279/280/281/282/285/286/293`
from any later capture.

## Laboratory

```sh
python tools/maplestory_classic_server/tools/run_physics_lab.py \
  --detach --hook none --display :10 --omit-mob-spawns
```

The isolated `maplephysics` namespace, Xvfb, NGSX stub, and capture-backed
login/world replay are described in [../CUSTOM_SERVER.md](../CUSTOM_SERVER.md).
The live world snapshot is map `101000000` (Ellinia). Xvfb software rendering
is slow; wait for the login dialog, dismiss **确定**, then world/channel/Start.

## Reachability auditor

```sh
python tools/maplestory_classic_server/tools/audit_map_reachability.py
python tools/maplestory_classic_server/tools/audit_map_reachability.py --map-id 101000000
```

It loads `ms4/knowledge/world-v300.json` plus
`downloads/maplestory_classic_navigation/*.json`, builds the walk/jump/climb/drop
graph from each map's footholds, and reports any travel portal or ladder that
is not spawn-reachable under beginner physics.
