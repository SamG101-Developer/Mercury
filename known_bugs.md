#### [MER-1]: Chat window does not display messages received during closed window state

If a chat window has been opened, is then closed, and then re-opened, any messages received during the "closed window"
state will not be displayed in the re-opened chat window. This is because the port is not reset to -1 during this time,
and the "port != -1" is the condition to pop messages from the message queue.