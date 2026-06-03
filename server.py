import asyncio
import logging
import os

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

from protocol import QSPPacket, MessageType
from auth import authenticate
from session import Session
from dfa import State
from file_transfer import calculate_sha256


HOST = "0.0.0.0"
PORT = 4433


logging.basicConfig(
    filename="qsp_server.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class QSPServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = Session()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            try:
                packet = QSPPacket.deserialize(event.data)
                response = self.handle_packet(packet)

                self._quic.send_stream_data(
                    event.stream_id,
                    response.serialize(),
                    end_stream=False
                )
                self.transmit()

            except Exception as e:
                logging.error(f"Server error: {e}")

    def handle_packet(self, packet):
        logging.info(
            f"Received type={packet.msg_type}, seq={packet.sequence_number}, state={self.session.dfa.state.value}"
        )

        if packet.msg_type == MessageType.INIT:
            self.session.dfa.transition(State.NEGOTIATED)

            return QSPPacket(
                MessageType.INIT_ACK,
                self.session.next_sequence(),
                self.session.session_id,
                {"status": "OK", "message": "QSP session initialized"}
            )

        if packet.msg_type == MessageType.AUTH:
            username = packet.payload.get("username")
            password = packet.payload.get("password")

            if authenticate(username, password):
                self.session.dfa.transition(State.AUTHENTICATED)
                self.session.dfa.transition(State.READY)

                return QSPPacket(
                    MessageType.AUTH_RESULT,
                    self.session.next_sequence(),
                    self.session.session_id,
                    {"status": "OK", "message": "Authentication successful"}
                )

            return QSPPacket(
                MessageType.ERROR,
                self.session.next_sequence(),
                self.session.session_id,
                {"status": "FAIL", "message": "Authentication failed"}
            )

        if packet.msg_type == MessageType.LIST_REQ:
            if self.session.dfa.state != State.READY:
                return QSPPacket(
                    MessageType.ERROR,
                    self.session.next_sequence(),
                    self.session.session_id,
                    {"status": "ERROR", "message": "LIST_REQ invalid before authentication"}
                )

            files = os.listdir("server_files")

            return QSPPacket(
                MessageType.LIST_RESP,
                self.session.next_sequence(),
                self.session.session_id,
                {"status": "OK", "files": files}
            )

        if packet.msg_type == MessageType.DOWNLOAD_REQ:
            if self.session.dfa.state != State.READY:
                return QSPPacket(
                    MessageType.ERROR,
                    self.session.next_sequence(),
                    self.session.session_id,
                    {"status": "ERROR", "message": "DOWNLOAD_REQ invalid before authentication"}
                )

            filename = packet.payload.get("filename")
            filepath = os.path.join("server_files", filename)

            if not os.path.exists(filepath):
                return QSPPacket(
                    MessageType.ERROR,
                    self.session.next_sequence(),
                    self.session.session_id,
                    {"status": "ERROR", "message": "File not found"}
                )

            with open(filepath, "r", encoding="utf-8") as file:
                content = file.read()

            file_hash = calculate_sha256(filepath)

            return QSPPacket(
                MessageType.DATA,
                self.session.next_sequence(),
                self.session.session_id,
                {
                    "status": "OK",
                    "filename": filename,
                    "content": content,
                    "sha256": file_hash
                }
            )

        if packet.msg_type == MessageType.CLOSE:
            self.session.dfa.transition(State.CLOSING)
            self.session.dfa.transition(State.CLOSED)

            return QSPPacket(
                MessageType.CLOSE,
                self.session.next_sequence(),
                self.session.session_id,
                {"status": "OK", "message": "Connection closed"}
            )

        return QSPPacket(
            MessageType.ERROR,
            self.session.next_sequence(),
            self.session.session_id,
            {"status": "ERROR", "message": "Unsupported message type"}
        )


async def main():
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=["qsp"]
    )

    configuration.load_cert_chain(
        "certs/cert.pem",
        "certs/key.pem"
    )

    print(f"QSP QUIC server listening on {HOST}:{PORT}")
    logging.info(f"Server started on {HOST}:{PORT}")

    await serve(
        HOST,
        PORT,
        configuration=configuration,
        create_protocol=QSPServerProtocol
    )

    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())