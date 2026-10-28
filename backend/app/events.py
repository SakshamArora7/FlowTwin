"""Bounded, best-effort delivery; slow viewers never block packet processing."""
import asyncio

clients = {}


async def broadcast(message):
    for queue in list(clients):
        if queue.full():
            queue.get_nowait()
            clients[queue] += 1
        queue.put_nowait({**message, "stream_dropped": clients[queue]})


def subscribe():
    queue = asyncio.Queue(maxsize=32)
    clients[queue] = 0
    return queue
