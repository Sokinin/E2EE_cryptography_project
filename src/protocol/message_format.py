import json


def make_message(sender_id: str, receiver_id: str, payload: dict) -> str:
    envelope = {
        "sender": sender_id,
        "receiver": receiver_id,
        "timestamp": __import__("time").time(),
        "payload": payload,
    }
    return json.dumps(envelope)


def parse_message(raw: str) -> dict:
    return json.loads(raw)
