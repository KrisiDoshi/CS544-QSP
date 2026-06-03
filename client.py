import asyncio
import ssl

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

from protocol import QSPPacket, MessageType
from session import Session


HOST = "127.0.0.1"
PORT = 4433


class QSPClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.response_queue = asyncio.Queue()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            self.response_queue.put_nowait(event.data)


class QSPClient:
    def __init__(self, protocol):
        self.protocol = protocol
        self.session = Session()
        self.stream_id = self.protocol._quic.get_next_available_stream_id()

    async def send_packet(self, packet):
        self.protocol._quic.send_stream_data(
            self.stream_id,
            packet.serialize(),
            end_stream=False
        )
        self.protocol.transmit()

        data = await self.protocol.response_queue.get()
        response = QSPPacket.deserialize(data)

        print("Server response:", response.payload)
        return response

    async def send_init(self):
        packet = QSPPacket(
            MessageType.INIT,
            self.session.next_sequence(),
            0,
            {"client": "QSP Client", "version": "1.0"}
        )

        response = await self.send_packet(packet)
        self.session.session_id = response.session_id

    async def send_auth(self, username, password):
        packet = QSPPacket(
            MessageType.AUTH,
            self.session.next_sequence(),
            self.session.session_id,
            {
                "username": username,
                "password": password
            }
        )

        await self.send_packet(packet)

    async def send_list_request(self):
        packet = QSPPacket(
            MessageType.LIST_REQ,
            self.session.next_sequence(),
            self.session.session_id,
            {}
        )

        response = await self.send_packet(packet)

        files = response.payload.get("files", [])

        print("\nServer files:")
        for file in files:
            print("-", file)

    async def send_close(self):
        packet = QSPPacket(
            MessageType.CLOSE,
            self.session.next_sequence(),
            self.session.session_id,
            {}
        )

        await self.send_packet(packet)


async def main():
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["qsp"]
    )

    configuration.verify_mode = ssl.CERT_NONE

    async with connect(
        HOST,
        PORT,
        configuration=configuration,
        create_protocol=QSPClientProtocol
    ) as protocol:
        print("Connected to QSP server")

        client = QSPClient(protocol)

        await client.send_init()
        await client.send_auth("admin", "admin123")
        await client.send_list_request()
        await client.send_close()


if __name__ == "__main__":
    asyncio.run(main())