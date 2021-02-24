import bencode
import random
import hashlib
import string
from functools import reduce

def to_bytes(val: int, num_bytes: int, signed: bool = False) -> bytes:
    return val.to_bytes(num_bytes, byteorder="big", signed= signed)

def getrandbytes(num: int) -> bytes:
    return to_bytes(random.getrandbits(num * 8), num)

ZERO8BYTE = to_bytes(0, 8)
ZERO4BYTE = to_bytes(0, 4)

ONE4BYTE = to_bytes(1, 4)

NEGONE4BYTE = to_bytes(-1, 4, signed=True)

ANNOUNCE_PORT = to_bytes(6885, 2)

ACTION = {
    "connect": ZERO4BYTE,
    "announce": ONE4BYTE
}

PEER_ID = bytes("-KB0001-", encoding="utf-8") + getrandbytes(12)

class TorrentFile:
    def __init__(self, filename) -> None:
        self.filename = filename
        self.data = bencode.bread(filename)

        self.infohash = hashlib.sha1(
            bencode.encode(self.data["info"])).digest()

    def calculate_size_left(self) -> bytes:
        len_files = map(lambda x: x["length"], self.data["info"]["files"])
        return to_bytes(sum(len_files), 8)
