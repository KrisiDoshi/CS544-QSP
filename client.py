import asyncio
import ssl
import os
import base64

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

from protocol import QSPPacket, MessageType
from session import Session
from file_transfer import calculate_sha256


HOST = "127.0.0.1"
PORT = 4433
UPLOAD_CHUNK_SIZE = 8


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
            {"username": username, "password": password}
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

    async def send_download_request(self, filename):
        packet = QSPPacket(
            MessageType.DOWNLOAD_REQ,
            self.session.next_sequence(),
            self.session.session_id,
            {"filename": filename}
        )

        response = await self.send_packet(packet)

        if response.payload.get("status") != "OK":
            print("Download failed:", response.payload.get("message"))
            return

        content = response.payload.get("content")
        expected_hash = response.payload.get("sha256")

        os.makedirs("client_files", exist_ok=True)
        output_path = os.path.join("client_files", filename)

        with open(output_path, "w", encoding="utf-8") as file:
            file.write(content)

        actual_hash = calculate_sha256(output_path)

        print("\nDownload completed:", filename)
        print("Expected SHA-256:", expected_hash)
        print("Actual SHA-256:  ", actual_hash)

        if actual_hash == expected_hash:
            print("Integrity verification PASSED")
        else:
            print("Integrity verification FAILED")

    async def send_upload_request(self, filename):
        filepath = os.path.join("client_files", filename)

        if not os.path.exists(filepath):
            print("Upload failed: file does not exist:", filepath)
            return

        expected_hash = calculate_sha256(filepath)

        upload_req = QSPPacket(
            MessageType.UPLOAD_REQ,
            self.session.next_sequence(),
            self.session.session_id,
            {
                "filename": filename,
                "sha256": expected_hash
            }
        )

        response = await self.send_packet(upload_req)

        if response.payload.get("status") != "OK":
            print("Upload rejected:", response.payload.get("message"))
            return

        offset = response.payload.get("next_offset", 0)

        with open(filepath, "rb") as file:
            while True:
                file.seek(offset)
                chunk = file.read(UPLOAD_CHUNK_SIZE)

                if not chunk:
                    break

                data_packet = QSPPacket(
                    MessageType.DATA,
                    self.session.next_sequence(),
                    self.session.session_id,
                    {
                        "filename": filename,
                        "offset": offset,
                        "chunk": base64.b64encode(chunk).decode("utf-8")
                    }
                )

                ack = await self.send_packet(data_packet)

                if ack.payload.get("status") != "OK":
                    print("Chunk upload failed:", ack.payload.get("message"))
                    return

                offset = ack.payload.get("next_offset", offset + len(chunk))

        complete_packet = QSPPacket(
            MessageType.COMPLETE,
            self.session.next_sequence(),
            self.session.session_id,
            {
                "filename": filename,
                "sha256": expected_hash
            }
        )

        complete = await self.send_packet(complete_packet)

        if complete.payload.get("status") == "OK":
            print("\nChunked upload completed:", filename)
            print("SHA-256:", complete.payload.get("sha256"))
            print("Integrity verification PASSED")
        else:
            print("\nUpload failed:", complete.payload.get("message"))

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
        await client.send_download_request("hello.txt")

        await client.send_upload_request("upload_test.txt")

        await client.send_list_request()
        await client.send_close()


if __name__ == "__main__":
    asyncio.run(main())