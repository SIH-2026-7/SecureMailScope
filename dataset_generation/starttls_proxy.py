"""Isolated lab SMTP capability-stripping proxy; never published on a host port."""
import asyncio


async def connection(client_reader, client_writer):
    server_reader, server_writer = await asyncio.open_connection('self_signed', 25)
    async def forward(reader, writer, strip=False):
        while line := await reader.readline():
            if strip and b'STARTTLS' in line.upper():
                if line.startswith(b'250-'):
                    continue
                line = b'250 HELP\r\n'
            writer.write(line)
            await writer.drain()
    try:
        await asyncio.gather(forward(client_reader, server_writer), forward(server_reader, client_writer, True))
    finally:
        client_writer.close(); server_writer.close()


async def main():
    async with await asyncio.start_server(connection, '0.0.0.0', 25) as server:
        await server.serve_forever()


asyncio.run(main())
