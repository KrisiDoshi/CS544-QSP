import json
import struct

QSP_VERSION = 1
HEADER_SIZE = 24


class MessageType:
    INIT = 1
    INIT_ACK = 2
    AUTH = 3
    AUTH_RESULT = 4
    LIST_REQ = 5
    LIST_RESP = 6
    UPLOAD_REQ = 7
    DOWNLOAD_REQ = 8
    DATA = 9
    ACK = 10
    COMPLETE = 11
    CLOSE = 12
    ERROR = 13


class QSPError(Exception):
    pass


class QSPPacket:
    def __init__(self, msg_type, sequence_number, session_id=0, payload=None):
        self.version = QSP_VERSION
        self.msg_type = msg_type
        self.sequence_number = sequence_number
        self.session_id = session_id
        self.payload = payload or {}

    def serialize(self):
        payload_bytes = json.dumps(self.payload).encode("utf-8")
        payload_length = len(payload_bytes)

        header = struct.pack(
            "!HHIQI",
            self.version,
            self.msg_type,
            self.sequence_number,
            self.session_id,
            payload_length
        )

        header = header + b"\x00" * (HEADER_SIZE - len(header))
        return header + payload_bytes

    @staticmethod
    def deserialize(data):
        if len(data) < HEADER_SIZE:
            raise QSPError("PDU too short")

        header = data[:HEADER_SIZE]

        version, msg_type, sequence_number, session_id, payload_length = struct.unpack(
            "!HHIQI",
            header[:20]
        )

        if version != QSP_VERSION:
            raise QSPError("Unsupported QSP version")

        expected_length = HEADER_SIZE + payload_length

        if len(data) != expected_length:
            raise QSPError("Invalid payload length")

        payload_bytes = data[HEADER_SIZE:expected_length]

        if payload_bytes:
            payload = json.loads(payload_bytes.decode("utf-8"))
        else:
            payload = {}

        return QSPPacket(
            msg_type=msg_type,
            sequence_number=sequence_number,
            session_id=session_id,
            payload=payload
        )