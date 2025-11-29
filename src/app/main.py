from .user import User
from .chat import Chat


def demo():
    alice = User("alice")
    bob = User("bob")

    alice_chat = Chat(alice)
    bob_chat = Chat(bob)

    alice_chat.send_message("bob", {"text": "Hello Bob"})
    msg = bob_chat.poll()
    print("Bob received:", msg)

if __name__ == '__main__':
    demo()
