"""Relay of a fork run: TCP on the internal chainsim network to the run's chain endpoint socket.

Runs inside the relay container (python3 -I, standard library only, mounted read-only): the forge
container (gVisor, netstack) can reach this container and nothing else, and this container can
reach only the Unix socket of the run's proxy endpoint (`chain/fork_rpc.py`), which holds the policy.
It forwards bytes and adds nothing; it caps connections and bytes per connection so a test cannot
use it to exhaust the host.

    python3 -I rpc_relay.py <listen_port> <unix_socket_path>
"""

import asyncio
import sys

MAX_CONNECTIONS = 32
MAX_BYTES_PER_CONNECTION = 64 * 1024 * 1024
IDLE_S = 60


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, budget: list[int]) -> None:
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=IDLE_S)
            if not chunk:
                break
            budget[0] -= len(chunk)
            if budget[0] < 0:
                break
            writer.write(chunk)
            await writer.drain()
    except (TimeoutError, OSError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


def main(argv: list[str]) -> int:
    port, sock = int(argv[1]), argv[2]
    active = [0]

    async def handle(c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter) -> None:
        if active[0] >= MAX_CONNECTIONS:
            c_writer.close()
            return
        active[0] += 1
        try:
            u_reader, u_writer = await asyncio.open_unix_connection(sock)
        except OSError:
            active[0] -= 1
            c_writer.close()
            return
        budget = [MAX_BYTES_PER_CONNECTION]
        try:
            await asyncio.gather(_pipe(c_reader, u_writer, budget), _pipe(u_reader, c_writer, budget))
        finally:
            active[0] -= 1

    async def run() -> None:
        server = await asyncio.start_server(handle, "0.0.0.0", port)
        print("relay ready", flush=True)
        async with server:
            await server.serve_forever()

    asyncio.run(run())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
