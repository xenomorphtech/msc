from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.gameplay import (  # noqa: E402
    InventoryItemEntity,
    MobEntity,
    NpcEntity,
)
from maple_server.live_proxy import (  # noqa: E402
    AtomicStatePublisher,
    LiveGameStateSession,
    LiveProxyConfig,
    live_proxy_connection,
)
from maple_server.packets import (  # noqa: E402
    MobSpawnData,
    MobSpawnTemporaryStatus,
    NpcSpawn,
)
from maple_server.protocol import crypt_payload, encode_frame_header  # noqa: E402
from maple_server.server import CaptureProxyConfig  # noqa: E402


HANDSHAKE = bytes.fromhex(
    "1f00 2c01 0300 330030003000 6e3c795a 885db958 04 "
    "2c010000 2c010000 00000000"
)
CLIENT_IV = bytes.fromhex("6e3c795a")
SERVER_IV = bytes.fromhex("885db958")


def encrypted_frame(plaintext: bytes, iv: bytes, version_mask: int) -> bytes:
    return encode_frame_header(len(plaintext), iv, version_mask) + crypt_payload(
        plaintext, iv
    )


class LiveGameStateSessionTest(unittest.TestCase):
    def test_decrypts_both_directions_into_the_existing_fold(self) -> None:
        session = LiveGameStateSession(
            upstream_host="maple.invalid", upstream_port=8587, peer="test"
        )
        session.accept_handshake(HANDSHAKE)
        server_plaintext = bytes.fromhex("ff7f01")
        client_plaintext = bytes.fromhex("fe7f02")
        server_wire = encrypted_frame(server_plaintext, SERVER_IV, ~300)
        client_wire = encrypted_frame(client_plaintext, CLIENT_IV, 3)

        server_observation = session.accept_frame(
            "server_to_client", server_wire[:4], server_wire[4:], timestamp_ns=10
        )
        client_observation = session.accept_frame(
            "client_to_server", client_wire[:4], client_wire[4:], timestamp_ns=20
        )

        self.assertIsNotNone(server_observation)
        self.assertIsNotNone(client_observation)
        self.assertEqual(server_observation.opcode, 0x7FFF)
        self.assertEqual(client_observation.opcode, 0x7FFE)
        self.assertEqual(
            session.fold.state.packets_by_direction,
            {"server_to_client": 1, "client_to_server": 1},
        )
        self.assertEqual(session.version_masks["server_to_client"], ~300 & 0xFFFF)
        self.assertEqual(session.version_masks["client_to_server"], 3)

    def test_snapshot_exposes_inferred_platforms_combat_and_inventory(self) -> None:
        session = LiveGameStateSession(
            upstream_host="maple.invalid", upstream_port=8587, peer="test"
        )
        state = session.fold.state
        state.player_x = 120
        state.player_y = 205
        state.current_hp = 41
        state.max_hp = 80
        state.current_mp = 12
        state.max_mp = 30
        state.inventory_items = {
            "use": (
                InventoryItemEntity(
                    slot=1,
                    record_type=2,
                    item_id=2_000_000,
                    cash_item=False,
                    expires_at_ticks=0,
                    quantity=7,
                ),
            )
        }
        npc_spawn = NpcSpawn(
            object_id=1,
            template_id=101,
            x=100,
            cy=210,
            facing_value=0,
            foothold_id=17,
            range_left=-50,
            range_right=300,
            hidden=False,
        )
        state.npcs[1] = NpcEntity(alias="npc:1", spawn=npc_spawn)
        mob_spawn = MobSpawnData(
            spawn_marker=1,
            template_id=210_100,
            temporary_status=MobSpawnTemporaryStatus(),
            x=180,
            y=210,
            stance=0,
            foothold_id=17,
            origin_foothold_id=17,
            appear_type=0,
            team=0,
            effect_item_id=0,
        )
        state.mobs[2] = MobEntity(
            alias="mob:1",
            spawn=mob_spawn,
            x=180,
            y=210,
            foothold_id=17,
            health_percentage=75,
            max_hp=50,
            health_hp_min=38,
            health_hp_max=38,
        )

        snapshot = session.snapshot(status="connected")
        game_state = snapshot["state"]

        self.assertEqual(game_state["player"]["platform"], "foothold:17")
        self.assertEqual(game_state["platforms"][0]["confidence"], "npc_range")
        self.assertEqual(game_state["enemies"][0]["health_percentage"], 75)
        self.assertEqual(game_state["inventory"][0]["items"][0]["quantity"], 7)

    def test_atomic_publisher_replaces_complete_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "state.json"
            publisher = AtomicStatePublisher(path)
            publisher.publish({"sequence": 1})
            publisher.publish({"sequence": 2, "complete": True})

            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"sequence": 2, "complete": True},
            )
            self.assertEqual(list(path.parent.glob("*.tmp")), [])


class LiveProxyIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def test_forwards_identical_wire_bytes_and_publishes_state(self) -> None:
        server_plaintext = bytes.fromhex("ff7f01")
        client_plaintext = bytes.fromhex("fe7f02")
        server_wire = encrypted_frame(server_plaintext, SERVER_IV, ~300)
        client_wire = encrypted_frame(client_plaintext, CLIENT_IV, 3)
        received_client_wire: asyncio.Future[bytes] = (
            asyncio.get_running_loop().create_future()
        )

        async def upstream_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            writer.write(HANDSHAKE + server_wire)
            await writer.drain()
            received_client_wire.set_result(
                await reader.readexactly(len(client_wire))
            )
            writer.close()
            await writer.wait_closed()

        upstream_server = await asyncio.start_server(
            upstream_handler, "127.0.0.1", 0
        )
        upstream_port = upstream_server.sockets[0].getsockname()[1]

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config = LiveProxyConfig(
                transport=CaptureProxyConfig(
                    upstream_host="127.0.0.1",
                    upstream_port=upstream_port,
                    transcript_directory=root / "captures",
                ),
                state_file=root / "state.json",
            )
            proxy_tasks: set[asyncio.Task[None]] = set()

            def proxy_handler(
                reader: asyncio.StreamReader, writer: asyncio.StreamWriter
            ) -> None:
                task = asyncio.create_task(
                    live_proxy_connection(reader, writer, config)
                )
                proxy_tasks.add(task)
                task.add_done_callback(proxy_tasks.discard)

            proxy_server = await asyncio.start_server(
                proxy_handler, "127.0.0.1", 0
            )
            proxy_port = proxy_server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)

            self.assertEqual(
                await reader.readexactly(len(HANDSHAKE + server_wire)),
                HANDSHAKE + server_wire,
            )
            writer.write(client_wire)
            await writer.drain()
            writer.write_eof()
            await asyncio.wait_for(reader.read(), timeout=2)
            self.assertEqual(
                await asyncio.wait_for(received_client_wire, timeout=2), client_wire
            )
            writer.close()
            await writer.wait_closed()

            deadline = asyncio.get_running_loop().time() + 2
            while proxy_tasks and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.01)
            self.assertFalse(proxy_tasks)
            snapshot = json.loads(config.state_file.read_text(encoding="utf-8"))
            self.assertEqual(snapshot["connection"]["status"], "disconnected")
            self.assertEqual(
                snapshot["state"]["packets"],
                {"client_to_server": 1, "server_to_client": 1},
            )

            proxy_server.close()
            await proxy_server.wait_closed()

        upstream_server.close()
        await upstream_server.wait_closed()


if __name__ == "__main__":
    unittest.main()
