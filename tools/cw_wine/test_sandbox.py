import struct
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from sandbox import WorldSandbox


class SandboxTests(unittest.IsolatedAsyncioTestCase):
    async def test_tutorial_melee_ack_death_and_progress(self):
        with tempfile.TemporaryDirectory() as temporary:
            sandbox = WorldSandbox(Path(temporary), 1)
            sandbox.character_id = 188753
            sandbox.quests = {"1005": 1}
            spawn = bytearray(312)
            struct.pack_into("<HBI", spawn, 0, 966, 0, 0x2bf09f6)
            struct.pack_into("<I", spawn, 8, 1)
            sandbox.observe_server(966, bytes(spawn))
            sent = []
            async def send(opcode, body): sent.append((opcode, body))
            await sandbox.start(send)
            self.assertEqual([opcode for opcode, _ in sent], [139, 1086, 978])
            sent.clear()
            await sandbox.receive(0xb226, bytes.fromhex("26b2f609bf020100"), send)
            self.assertEqual(sent, [(996, bytes.fromhex("e403f609bf020100001e000000000000000000000000000000000000"))])
            attack = bytearray(224)
            attack[:4] = bytes.fromhex("9a5c0101")
            attack[84:96] = b"\x0a\x00User Melee"
            struct.pack_into("<II", attack, 125, 0x2bf09f6, 1)
            struct.pack_into("<Q", attack, 136, 18)
            sent.clear()
            with patch("sandbox.time.monotonic", return_value=100):
                await sandbox.receive(0x5c9a, bytes(attack), send)
            self.assertEqual(sent, [(1008, bytes.fromhex("f003f609bf022800000000"))])
            self.assertEqual(sandbox.mobs[0x2bf09f6]["hp"], 12)
            struct.pack_into("<Q", attack, 136, 21)
            sent.clear()
            with patch("sandbox.time.monotonic", return_value=101):
                await sandbox.receive(0x5c9a, bytes(attack), send)
            self.assertEqual([opcode for opcode, _ in sent], [1008, 1098, 978, 977, 126, 139])
            self.assertEqual(sent[3][1].hex(), "d103f609bf0201000000000000000000")
            self.assertEqual(sent[-1][1].hex(), "8b0001ed030000010300303031")
            self.assertEqual(sent[-2][1].hex(), "7e000000010000010004000000000000000000")
            self.assertEqual(sandbox.kills, 1)
            sent.clear()
            with patch("sandbox.time.monotonic", return_value=102):
                await sandbox.receive(0x5c9a, bytes(attack), send)
            self.assertEqual(sent, [])
            self.assertEqual(sandbox.kills, 1)
            sandbox.close()
            restored = WorldSandbox(Path(temporary), 2)
            restored.character_id = 188753
            await restored.start(send)
            self.assertEqual(restored.kills, 1)
            self.assertEqual([body.hex() for opcode, body in sent if opcode == 139][-1], "8b0001ed030000010300303031")
            self.assertEqual(restored.exp, 4)
            restored.close()

    async def test_quest_start_is_request_driven_idempotent_and_restored(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            sent = []
            async def send(opcode, body):
                sent.append((opcode, body))
            sandbox = WorldSandbox(directory, 1)
            login = bytearray(14)
            struct.pack_into("<I", login, 10, 188753)
            await sandbox.receive(125, bytes(login), send)
            await sandbox.start(send)
            self.assertEqual(sent, [])
            # Captured request C247, followed by exact observed response bodies.
            request = bytes.fromhex("9f8001ed03000007000000e6ffd70000000000")
            await sandbox.receive(32927, request, send)
            self.assertEqual([body.hex() for _, body in sent], [
                "8b0001ed030000010000", "8b000d4b04000008007169643d31303035",
                "dd020ced030000070000000000000001"])
            sent.clear()
            await sandbox.receive(32927, request, send)
            self.assertEqual(len(sent), 1)
            sent.clear()
            # Unknown IDs, truncated requests and completion never grant rewards.
            await sandbox.receive(32927, request[:7], send)
            await sandbox.receive(32927, request[:2] + b"\x02" + request[3:], send)
            await sandbox.receive(32927, request[:3] + struct.pack("<I", 9999) + request[7:], send)
            self.assertEqual(sent, [])
            sandbox.close()
            restored = WorldSandbox(directory, 2)
            await restored.receive(125, bytes(login), send)
            await restored.start(send)
            self.assertEqual(restored.quests, {"1005": 1})
            self.assertEqual([body.hex() for _, body in sent], ["8b0001ed030000010000"])
            restored.close()


if __name__ == "__main__":
    unittest.main()
