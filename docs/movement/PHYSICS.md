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

## Beginner constants

These are the values used by the reachability graph. They are labeled
hypotheses until a live `VecCtrlUser` dump confirms stored units, but they
already match capture-backed jump height (~77 px apex) and observed drops.

| Quantity | Value | Role |
| --- | --- | --- |
| walk speed | 125 | pixels / second at 100% shoe speed |
| jump impulse | 555 | vertical takeoff speed |
| gravity | 2000 | pixels / second² |
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
