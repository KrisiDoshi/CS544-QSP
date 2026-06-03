# QSync Protocol (QSP/1.0)

## Overview

QSync Protocol (QSP/1.0) is a secure file synchronization protocol implemented on top of QUIC and TLS 1.3. The project was developed as part of the CS-544 Protocol Design Project and demonstrates the implementation of a custom application-layer protocol supporting authentication, file transfer, integrity verification, chunked transmission, acknowledgements, and resumable uploads.

The protocol uses QUIC for transport and TLS 1.3 for secure communication while implementing custom application-layer functionality for file synchronization.

---

## Features

### Connection Management

* QUIC-based client/server communication
* TLS 1.3 encryption
* Session establishment and termination

### Authentication

* Username/password authentication
* Session validation

### File Operations

* List files on server
* Download files from server
* Upload files to server

### Reliability

* Chunked file transfer
* ACK-based transfer confirmation
* Sequence number tracking
* Resumable uploads using offsets

### Security

* TLS 1.3 encryption through QUIC
* SHA-256 integrity verification
* Error detection and reporting

### Protocol Management

* DFA-based session state management
* Logging of protocol events and transitions

---

## Technologies Used

* Python 3.13
* aioquic
* QUIC
* TLS 1.3
* SHA-256
* Git
* GitHub

---

## Project Structure

```text
CS544-QSP/
│
├── client.py
├── server.py
├── protocol.py
├── auth.py
├── session.py
├── dfa.py
├── file_transfer.py
│
├── certs/
│   ├── cert.pem
│   └── key.pem
│
├── client_files/
├── server_files/
│
├── tests/
│   ├── test_protocol.py
│   └── test_dfa.py
│
├── qsp_server.log
└── README.md
```

---

## Protocol Stack

```text
Application Layer
        │
       QSP
        │
      QUIC
        │
       UDP
        │
        IP
        │
   Data Link
```

---

## Authentication Credentials

The current implementation uses the following test credentials:

```text
Username: admin
Password: admin123
```

---

## Implemented Message Types

| Message Type | Description                     |
| ------------ | ------------------------------- |
| INIT         | Session initialization          |
| INIT_ACK     | Session initialization response |
| AUTH         | Authentication request          |
| AUTH_RESULT  | Authentication result           |
| LIST_REQ     | Request list of files           |
| LIST_RESP    | File list response              |
| DOWNLOAD_REQ | Download request                |
| UPLOAD_REQ   | Upload request                  |
| DATA         | File chunk transfer             |
| ACK          | Chunk acknowledgement           |
| COMPLETE     | Transfer completion             |
| ERROR        | Error response                  |
| CLOSE        | Session termination             |

---

## Implemented Features


QUIC Transport
TLS 1.3 Encryption
Authentication    
Session Management
File Listing      
File Download     
File Upload       
Chunked Transfer  
ACK Support       
Resume Support    
SHA-256 Verification
DFA State Machine
Error Handling   
Logging                   

---

## Running the Server

Start the server:

```bash
python server.py
```

Expected output:

```text
QSP QUIC server listening on 0.0.0.0:4433
```

---

## Running the Client

Open a second terminal and run:

```bash
python client.py
```

The client demonstrates:

1. Session initialization
2. Authentication
3. File listing
4. File download
5. SHA-256 verification
6. Chunked upload
7. ACK processing
8. Resume support
9. Connection termination

---

## Example Output

```text
Connected to QSP server

Authentication successful

Server files:
- hello.txt

Download completed: hello.txt
Integrity verification PASSED

Chunked upload completed: upload_test.txt
Integrity verification PASSED

Connection closed
```

---

## Logging

Server activity is recorded in:

```text
qsp_server.log
```

Example events include:

* Server startup
* Authentication requests
* File transfers
* State transitions
* Connection termination

---