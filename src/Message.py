from dataclasses import dataclass, field
from enum import Enum


class MessageType(Enum):
    Text = 0
    Image = 1
    Video = 2
    File = 3


@dataclass(kw_only=True)
class Message:
    message_bytes: bytes
    am_i_sender: bool
    message_type: MessageType = field(default=MessageType.Text)
    other_info: dict[str, str] = field(default_factory=dict)
