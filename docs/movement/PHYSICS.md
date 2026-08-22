# VecCtrl physics and packet contract

## IL2CPP types

Original names are still in `global-metadata.dat`:

```text
Msc.Game.Object.Control.VecCtrl
Msc.Game.Object.Control.VecCtrlUser
Msc.Game.Object.Control.VecCtrlMob
Msc.Game.Object.Control.VecCtrl.AbsPos
Msc.Game.Object.Control.VecCtrl.RelPos
Msc.Game.Object.Control.VecCtrl.FallDownData
Msc.Game.Object.Control.VecCtrl.ImpactNext
Msc.Game.PhysicalSpace2D
Msc.Game.Foothold
Msc.Data.StaticFoothold
Msc.Data.LadderOrRope
Msc.Game.Object.UserLocal
```

Source paths include `Assets/Scripts/Game/Object/Control/VecCtrl.cs` and
`Assets/Scripts/Game/PhysicalSpace2D.cs`. This is the Unity remake of the old
C++ `CVecCtrl` / `CWvsPhysicalSpace2D`.

Live field offsets are dumped after the client is in a field:

```sh
python tools/maplestory_classic_server/tools/run_physics_lab.py \
  --attach-only --hook gdb --display :10
```

Do not attach Frida or leave GDB on the process during splash/NGS; that
stalls or kills Wine.

## Deterministic beginner rules

The executable rules are in
`tools/maplestory_classic_server/maple_server/physics_rules.py`. Their original
force-envelope source is `/home/sdancer/ms2/docs/movement.hmtl` (the source
file really has the transposed `.hmtl` suffix). Geometry comes from WZ map
foothold and `ladderRope` records in `world-v300.json`; these records are often
called map prefabs in the tooling, but they are not Unity collider prefabs.

Coordinates are +x right and +y down. The default integration timestep is
30 ms.

| Quantity | Value | Role |
| --- | --- | --- |
| run acceleration | 1400 | map units / second² while a direction is held |
| release deceleration | 800 | map units / second² on grounded key release |
| walk speed | 125 | map units / second at 100% shoe speed |
| jump impulse | -555 | vertical takeoff speed (+y is down) |
| gravity | 2000 | map units / second² |
| terminal fall speed | 670 | map units / second |
| climb speed | 60 | map units / second on a ladder or rope |
| ballistic rise | `v² / 2g` ≈ 77 px | capped by `max_jump_rise` 120 |
| max jump gap | 180 px | horizontal reach for a jump edge |
| max drop | 460 px | downward jump or drop-through |

Jump-down is allowed only when the current foothold does not set
`forbidFallDown`. Climb uses `ladderRope` records (`l=1` ladder, `l=0` rope).

## Packet commands

Local player movement is `client opcode 182`. Life/mob movement is
`client opcode 47`. Broadcasts are `server opcode 202` and `217`. Command
tags and widths are exact on streams `92` and `126`:

| Type | Payload | Fields | Physics role |
| --- | --- | --- | --- |
| 0 / 5 | 13 bytes | x, y, vx, vy, foothold, stance, duration | walk / stand / land |
| 1 | 7 bytes | vx, vy, stance, duration | jump, fall, knockback in air |
| 3 | 9 bytes | x, y, neutral, stance, duration | jump-down / drop-through start |
| 4 | 9 bytes | x, y, neutral, stance, duration | climb attach/detach or teleport-like settle |

A path starts at a reference `(x, y)` then applies one or more commands. The
custom server currently records these; it does not yet reject an impossible
path. The reachability graph is the first backend check that a submitted
endpoint is on a spawn-connected surface.

## Inputs

Physical keys in the live client (evdev / Unity raw input):

| Key | Action |
| --- | --- |
| Left / Right | walk |
| Alt | jump (action 53) |
| Down + Alt | jump-down through a foothold |
| Up / Down on a rope or ladder | climb |

There is no dedicated jump packet. Opcode `182` is the serialized result after
`VecCtrl` has already moved.

## RL capture verification

The successful Ellinia RL ascent on map `101000000` can be checked without
opening a window or touching the host X11 session:

```sh
PYTHONPATH=tools/maplestory_classic_server \
python tools/maplestory_classic_server/tools/verify_rl_physics.py \
  --output .codex_tmp/physics-lab/rl-physics-verification.json
```

The 140-second success window currently proves:

- 154 of 154 opcode-47 plaintext submissions re-emit byte-for-byte through
  the typed packet constructors (595 typed commands, no opaque commands).
- 98 of 99 measurable gravity transitions are exactly 2000; the remaining
  integer-quantized transition is 1996.667, within 3.334 units/s².
- all 28 measurable takeoffs recover an initial velocity of exactly -555.
- all four terminal samples are exactly 670.
- all 331 ordinary foothold contacts resolve to the map prefab within two map
  units (maximum y error 1.15); four sit one integer unit beyond a segment
  endpoint and are accepted as endpoint quantization.
- 418 packet samples correlate to a Frida frame within 60 ms. Median absolute
  position errors are 0.29 x and 1.59 y map units.

This ascent does not independently excite every rule. Run acceleration,
ground-release deceleration, the 125 walk cap, climb speed, and the 30 ms
timestep retain source-model provenance and unit tests; gravity, jump impulse,
terminal fall speed, and foothold contacts have live packet evidence in this
window.

The completed RL run retained its final weights and final status, but not each
historical action decision. The verifier therefore shadows the final 10,816-
update policy over the observed trajectory and verifies that it reaches the
same goal, while labeling action-for-action comparison unavailable. Future
runs should add `--trace PATH` to `run_rl_navigation.py`; it appends every
observation/action decision as owner-only JSONL.

"Same packet" means the complete plaintext opcode payload. Encrypted wire
frames are intentionally different on a new connection because their bytes
depend on the per-session IV and cipher progression.
