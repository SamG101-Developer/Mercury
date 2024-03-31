from dataclasses import dataclass
from enum import Enum


class MessageType(Enum):
    Text = 0
    Image = 1
    Video = 2
    File = 3


@dataclass
class Message:
    message_type: MessageType
    message_bytes: bytes
    other_info: dict[str, str]
