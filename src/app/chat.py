from ..protocol import message_format
from ..transport import network

class Chat:
    def __init__(self, user):
        self.user = user

    def send_message(self, receiver_id: str, payload: dict):
        raw = message_format.make_message(self.user.identity(), receiver_id, payload)
        network.send(raw)

    def poll(self):
        raw = network.receive()
        if raw:
            msg = message_format.parse_message(raw)
            return msg
        return None
