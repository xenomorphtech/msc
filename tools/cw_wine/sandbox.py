"""State and input journal for a stable local field bootstrap.

Movement is still simulated by the native client. Origins are observations,
not authoritative end positions, and are not restored into opaque field blobs.
"""
from collections import Counter
import asyncio
import json
from pathlib import Path
import struct
import time


class WorldSandbox:
    def __init__(self, directory, stamp):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        self.stamp = stamp
        self.ready = False
        self.character_id = None
        self.movement_count = 0
        self.origin = None
        self.counts = Counter()
        self.journal = (self.directory / f"{stamp}-commands.jsonl").open("w")
        self.last_saved = 0
        self.quests = {}
        self.kills = 0
        self.mobs = {}
        self.last_attack = 0
        self.exp = 3  # Initial fixture EXP; its first captured kill raises this to 4.
        self.tasks = set()

    def observe_server(self, opcode, body):
        # Native spawn handler 0x1d89e50 reads spawn kind, OID, effect byte,
        # then the model ID. Only initial tutorial model 1 is supported here.
        if opcode == 966 and len(body) == 312:
            identifier = struct.unpack_from("<I", body, 3)[0]
            model = struct.unpack_from("<I", body, 8)[0]
            if identifier and model == 1:
                self.mobs.setdefault(identifier, {"spawn": body, "hp": 30})

    async def receive(self, opcode, body, send):
        self.counts[opcode] += 1
        if opcode == 125 and len(body) >= 14:
            self.character_id = struct.unpack_from("<I", body, 10)[0]
        elif opcode == 0x8111 and len(body) >= 20 and body[2] in (1, 2):
            self.movement_count += 1
            self.origin = list(struct.unpack_from("<hh", body, 16))
        # Retain raw commands so new handlers can be recovered against actual
        # user input rather than guessed from the previous client version.
        if opcode not in (112, 0x43dd, 0xb226):
            self.journal.write(json.dumps({"timestamp_ns": time.time_ns(), "opcode": opcode,
                                          "body_hex": body.hex(), "field_ready": self.ready}) + "\n")
            self.journal.flush()
        if self.ready and opcode == 0x809f and len(body) >= 11:
            action, quest, npc = struct.unpack_from("<BII", body, 2)
            # Verified against capture C247 and S672..674 and native quest-result
            # dispatch at 0x28fa630. Completion needs real kill/item validation.
            if action == 1 and quest == 1005 and npc == 7 and len(body) == 19:
                if self.quests.get(str(quest)) != 1:
                    self.quests[str(quest)] = 1
                    self.save_character()
                    for response in self.quest_start_packets():
                        await send(int.from_bytes(response[:2], "little"), response)
                else:
                    await send(139, self.quest_state_packet(self.kills))
        if self.ready and opcode == 0xb226 and len(body) >= 8:
            identifier, sequence = struct.unpack_from("<IH", body, 2)
            if identifier in self.mobs and self.mobs[identifier]["hp"]:
                # Native control ACK: OID, sequence, action, MP, skill fields.
                ack = struct.pack("<HIHBIIHIIB", 996, identifier, sequence, 0, 30, 0, 0, 0, 0, 0)
                await send(996, ack)
        if self.ready and opcode == 0x5c9a:
            await self.melee(body, send)
        if time.monotonic() - self.last_saved >= 1:
            self.save()

    @staticmethod
    def quest_state_packet(kills=0):
        progress = f"{min(kills, 3):03d}".encode() if kills else b""
        return struct.pack("<HBIBH", 139, 1, 1005, 1, len(progress)) + progress

    @classmethod
    def quest_start_packets(cls):
        return [cls.quest_state_packet(), bytes.fromhex("8b000d4b04000008007169643d31303035"),
                struct.pack("<HBIIIB", 733, 12, 1005, 7, 0, 1)]

    async def start(self, send):
        if self.character_id is not None:
            path = self.directory / f"character-{self.character_id}.json"
            if path.exists():
                saved = json.loads(path.read_text())
                if saved.get("reference") != "native-cw-0.9.0" or saved.get("character_id") != self.character_id:
                    raise ValueError("saved character belongs to another reference")
                self.quests = saved.get("quests", {})
                self.kills = min(3, max(0, int(saved.get("tutorial_kills", 0))))
                self.exp = max(3, int(saved.get("exp", 3 + self.kills)))
            if self.quests.get("1005") == 1:
                await send(139, self.quest_state_packet(self.kills))
            if self.exp != 3:
                await send(126, self.exp_packet())
        # Give this local client ownership of the initial tutorial mobs. The
        # native client supplies their movement simulation; ACKs stay live.
        for identifier, mob in self.mobs.items():
            await send(1086, struct.pack("<HII", 1086, identifier, self.character_id or 0))
            await send(978, struct.pack("<H", 978) + b"\x01" + mob["spawn"][3:])
        self.ready = True
        self.save()

    async def melee(self, body, send):
        # Capture's 173 User Melee packets share this layout: a single target
        # record starts at +125, hit count at +129 and uint64 damage at +136.
        # Restrict to the observed basic single-hit/single-target form.
        if len(body) not in (224, 232) or body[3] != 1 or body[84:96] != b"\x0a\x00User Melee":
            return
        identifier, hits = struct.unpack_from("<II", body, 125)
        damage = struct.unpack_from("<Q", body, 136)[0]
        mob = self.mobs.get(identifier)
        if not mob or not mob["hp"] or hits != 1 or not 1 <= damage <= 1000:
            return
        if time.monotonic() - self.last_attack < .15:
            return
        self.last_attack = time.monotonic()
        # Model 1 HP=30 is independently implied by capture hit 18 -> 40%,
        # hit 20 -> 33%, followed by lethal hits and native removal packets.
        # This fixture accepts client-reported basic damage; other combat forms
        # need their own decoder and server damage calculation.
        mob["hp"] = max(0, mob["hp"] - damage)
        await send(1008, struct.pack("<HIIB", 1008, identifier, mob["hp"] * 100 // 30, 0))
        if mob["hp"] == 0:
            await send(1098, struct.pack("<HIII", 1098, identifier, self.character_id or 0, 0))
            await send(978, struct.pack("<HBI", 978, 0, identifier))
            await send(977, struct.pack("<HIBBII", 977, identifier, 1, 0, 0, 0))
            self.exp += 1
            await send(126, self.exp_packet())
            if self.quests.get("1005") == 1:
                self.kills = min(3, self.kills + 1)
                await send(139, self.quest_state_packet(self.kills))
            self.save_character()
            task = asyncio.create_task(self.respawn(identifier, send))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        self.save()

    def exp_packet(self):
        # Native stat decoder 0x311150: flag 0x10000 carries uint64 EXP.
        # The surrounding three flags and two suffix flags match captured S126.
        return struct.pack("<HBBBIQBB", 126, 0, 0, 1, 0x10000, self.exp, 0, 0)

    async def respawn(self, identifier, send):
        await asyncio.sleep(6)
        mob = self.mobs[identifier]
        mob["hp"] = 30
        try:
            await send(966, mob["spawn"])
            await send(1086, struct.pack("<HII", 1086, identifier, self.character_id or 0))
            await send(978, struct.pack("<H", 978) + b"\x01" + mob["spawn"][3:])
            self.save()
        except ConnectionError:
            return

    def save_character(self):
        if self.character_id is None:
            return
        path = self.directory / f"character-{self.character_id}.json"
        temporary = path.with_suffix(".partial")
        temporary.write_text(json.dumps({"reference": "native-cw-0.9.0", "character_id": self.character_id,
                                         "quests": self.quests, "tutorial_kills": self.kills, "exp": self.exp}, indent=2) + "\n")
        temporary.replace(path)

    def save(self):
        state = {"session": self.stamp, "field_ready": self.ready, "character_id": self.character_id,
                 "movement_packets": self.movement_count, "reported_movement_origin": self.origin,
                 "received_opcodes": dict(self.counts), "updated_at_ns": time.time_ns(),
                 "quests": self.quests,
                 "tutorial_kills": self.kills,
                 "exp": self.exp,
                 "mobs": {str(key): {"hp": value["hp"]} for key, value in self.mobs.items()},
                 "scope": "tutorial field, basic reported melee damage, respawns, EXP and quest-1005 acceptance/kills; loot, level-up, quest completion and inventory persistence are not implemented"}
        path = self.directory / f"{self.stamp}-state.json"
        temporary = path.with_suffix(".partial")
        temporary.write_text(json.dumps(state, indent=2) + "\n")
        temporary.replace(path)
        self.last_saved = time.monotonic()

    def close(self):
        for task in self.tasks:
            task.cancel()
        self.save()
        self.journal.close()
