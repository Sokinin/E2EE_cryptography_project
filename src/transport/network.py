import queue

# Simple in-memory simulated network for demo / tests
_incoming = queue.Queue()


def send(raw_message: str):
    _incoming.put(raw_message)


def receive(timeout: float = 1.0):
    try:
        return _incoming.get(timeout=timeout)
    except Exception:
        return None
