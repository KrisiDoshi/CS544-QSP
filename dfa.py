from enum import Enum


class State(Enum):
    START = "START"
    INIT_SENT = "INIT_SENT"
    NEGOTIATED = "NEGOTIATED"
    AUTHENTICATED = "AUTHENTICATED"
    READY = "READY"
    TRANSFERRING = "TRANSFERRING"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    ERROR = "ERROR"


class SessionDFA:

    def __init__(self):
        self.state = State.START

    def transition(self, new_state):

        print(
            f"[DFA] {self.state.value} -> {new_state.value}"
        )

        self.state = new_state

    def validate_message(self, msg_type):

        allowed = {

            State.START: ["INIT"],

            State.INIT_SENT: [
                "INIT_ACK"
            ],

            State.NEGOTIATED: [
                "AUTH_RESULT"
            ],

            State.AUTHENTICATED: [
                "READY"
            ],

            State.READY: [
                "LIST_REQ",
                "UPLOAD_REQ",
                "DOWNLOAD_REQ",
                "CLOSE"
            ],

            State.TRANSFERRING: [
                "DATA",
                "ACK",
                "COMPLETE"
            ],

            State.CLOSING: [
                "CLOSE"
            ]
        }

        valid = allowed.get(
            self.state,
            []
        )

        return msg_type in valid