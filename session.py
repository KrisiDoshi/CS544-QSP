import uuid

from dfa import SessionDFA


class Session:

    def __init__(self):

        self.session_id = uuid.uuid4().int & 0xFFFFFFFF

        self.sequence_number = 0

        self.dfa = SessionDFA()

    def next_sequence(self):

        self.sequence_number += 1

        return self.sequence_number

    def validate_sequence(self, received):

        return received == (
            self.sequence_number + 1
        )