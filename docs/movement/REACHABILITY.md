# Map reachability

The auditor in `maple_server/navigation.py` treats each walkable foothold as a
node. Edges are:

- **walk** — shared endpoints or WZ `prev`/`next` links
- **climb** — ladder/rope top and bottom within 50×55 px of a surface
- **drop** — nearly vertical, downward, not `forbidFallDown`, ≤ 460 px
- **jump** — gap ≤ 180 px and vertical delta inside ballistic rise / max drop

Spawn portals (`pt=0` or `pn=sp`) land on the first foothold at or below their
`(x, y)`. From that surface the graph must reach:

- every other walkable foothold that a beginner can actually use
- every **travel** portal (`tm` not `999999999`)
- both ends of every ladder/rope

Travel portals more than 80 px from any foothold, or on a disconnected
surface, are reported as gaps. Script-only / spawn portals are not required.

## Command

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server
python tools/audit_map_reachability.py
python tools/audit_map_reachability.py --map-id 101000000 --json
```

Default maps: Maple Island `0/10000/20000/30000/40000/50000/50001/60000` and
Victoria `1000000`, `100000000`, `101000000`, `102000000`, `103000000`,
`104000000`, `104000100`, `104000400`. Geometry comes from
`/home/sdancer/ms4/knowledge/world-v300.json` (705 maps) with the three
checked-in files under `downloads/maplestory_classic_navigation/` as a
fallback.

## Mobs off

Movement audits and the physics lab omit mobs so contact knockback cannot
change a path:

```text
--omit-mob-spawns
```

That drops server opcodes `218`, `219`, `279`, `280`, `281`, `282`, `285`,
`286`, and `293` with corrected IV progression. The current stream-`114`
Ellinia snapshot contains none of those opcodes.

## Live map walk

The custom world listener serves one field at a time. Stream `114` is Ellinia
(`101000000`). Changing maps still requires a typed `opcode 157` snapshot for
the destination; that emitter is not yet a general portal server. Until then,
intra-map reachability is the proof that left/right, jump, climb, and
drop-through connect every usable surface on each extracted map.

## Auditor run (2026-08-18)

`python tools/audit_map_reachability.py` against `world-v300.json`. Beginner
physics: walk 125, jump 555, gravity 2000, gap 180, drop 460. Mobs ignored.

| Map | Name | Footholds | Travel portals | Ladders | Result |
| --- | --- | --- | --- | --- | --- |
| 0 | Maple Island spawn | 57/58 | 1/1 | 1/1 | ok |
| 10000 | Maple Island | 16/20 | 1/1 | 0/0 | ok |
| 20000 | Maple Island | 28/28 | 2/2 | 1/1 | ok |
| 30000 | Maple Island | 64/64 | 1/1 | 4/4 | ok |
| 40000 | Maple Island | 73/73 | 1/1 | 10/10 | ok |
| 50000 | Maple Island | 86/86 | 3/3 | 12/12 | ok |
| 50001 | Snail Hunting Ground I | 88/88 | 4/4 | 7/7 | ok |
| 60000 | Southperry | 139/143 | 2/2 | 7/7 | ok |
| 1000000 | Mushroom Town | 115/115 | 4/4 | 11/11 | ok |
| 100000000 | Henesys | 227/233 | 7/7 | 2/2 | ok |
| 101000000 | Ellinia | 1236/1236 | 6/6 | 37/37 | ok |
| 102000000 | Perion | 481/481 | 6/6 | 15/15 | ok |
| 103000000 | Kerning City | 435/450 | 15/15 | 27/27 | ok |
| 104000000 | Lith Harbor | 374/382 | 4/4 | 17/17 | ok |
| 104000100 | Lith Harbor side | 89/89 | 2/2 | 1/1 | ok |
| 104000400 | Lith Harbor side | 63/63 | 2/2 | 4/4 | ok |

Unused footholds are vertical collision walls or leftover chain segments, not
walk surfaces. Event (`pt=3`) and script portals are excluded. Same-map warp
destinations such as Henesys `in03` are entered by a hidden `up00` warp, not
by walking from spawn.

Every ordinary travel portal and every ladder/rope on these maps is
spawn-reachable by walk, jump, climb, or drop. The live custom-server field
is Ellinia (`101000000`); that map is complete (1236/1236 walkable footholds,
6/6 portals, 37/37 ladders). Changing maps in the live replay still needs a
typed destination `opcode 157` snapshot.
