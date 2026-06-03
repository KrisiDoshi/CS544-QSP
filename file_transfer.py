import hashlib

CHUNK_SIZE = 4096


def calculate_sha256(filepath):
    sha = hashlib.sha256()

    with open(filepath, "rb") as file:
        while chunk := file.read(CHUNK_SIZE):
            sha.update(chunk)

    return sha.hexdigest()


def read_file_chunks(filepath):
    with open(filepath, "rb") as file:
        while chunk := file.read(CHUNK_SIZE):
            yield chunk


def read_file_from_offset(filepath, offset):
    with open(filepath, "rb") as file:
        file.seek(offset)

        while chunk := file.read(CHUNK_SIZE):
            yield chunk