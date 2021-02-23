import bencode
import socket
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

torrent = TorrentFile("test.torrent")

def try_except_loop(func, err = None, num_repeat = 8):
    for _ in range(num_repeat):
        try:
            return func()
        except err:
            pass

def create_socket(timeout: int = 2) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    return sock

def create_conn_req_data(transaction_id: bytes) -> bytes:
    magic_bytes = to_bytes(0x41727101980, 8)
    action = ACTION["connect"]
    conn_req_data = magic_bytes + action + transaction_id
    return conn_req_data

def check_resp(conn_resp: bytes, transaction_id: bytes, type_: str) -> bool:
    if conn_resp[:4] == ACTION[type_]:
        if conn_resp[4:8] == transaction_id:
            return True
    return False

def create_announce_req_data(
    connection_id: bytes, 
    transaction_id: bytes, 
    infohash: bytes, 
    peerid: bytes, 
    size_left: bytes,
    downloaded: bytes = ZERO8BYTE, 
    uploaded: bytes = ZERO8BYTE, 
    event: bytes = ZERO4BYTE,
    ip_addr: bytes = ZERO4BYTE, 
    key: bytes = None, 
    numwant: bytes = NEGONE4BYTE,
    port: bytes = ANNOUNCE_PORT
) -> bytes:
    if key is None:
        key = getrandbytes(4)

    action = ACTION["announce"]

    announce_req = connection_id + action + transaction_id + infohash \
        + peerid + downloaded + size_left + uploaded + event \
        + ip_addr + key + numwant + port

    return announce_req

def parse_announce_resp(announce_resp):
    interval = int.from_bytes(announce_resp[8:12], byteorder="big")
    leechers = int.from_bytes(announce_resp[12:16], byteorder="big")
    seeders = int.from_bytes(announce_resp[16:20], byteorder="big")

    peers = []

    peers_bytes = announce_resp[20:]
    for i in range(0, len(peers_bytes), 6):
        ip = ".".join(map(str, peers_bytes[i:i+4]))
        port = int.from_bytes(peers_bytes[i+4:i+6], byteorder="big")
        peers.append((ip, port))

    return interval, leechers, seeders, peers

def get_peers_from_tracker(
    tracker_host: str = "tracker.opentrackr.org", 
    tracker_port: int = 1337
) -> list:

    sock = create_socket()

    transaction_id = getrandbytes(4)

    conn_req_data = create_conn_req_data(transaction_id)

    sock.sendto(conn_req_data, (tracker_host, tracker_port))
    
    conn_resp = try_except_loop(lambda: sock.recv(16), socket.timeout, 8)

    if not check_resp(conn_resp, transaction_id, "connect"):
        raise AssertionError(
            "Invalid values supplied by tracker in connection response.")

    connection_id = conn_resp[8:16]

    announce_req_data = create_announce_req_data(
        connection_id, transaction_id,
        torrent.infohash, PEER_ID, torrent.calculate_size_left()
    )

    sock.sendto(announce_req_data, (tracker_host, tracker_port))
    announce_resp = try_except_loop(lambda: sock.recv(4096), socket.timeout, 8)

    if not check_resp(announce_resp, transaction_id, "announce"):
        raise AssertionError(
            "Invalid values supplied by tracker in announce response.")

    interval, leechers, seeders, peers = parse_announce_resp(announce_resp)

    return peers


if __name__ == "__main__":
    peers = get_peers_from_tracker()
    print(peers)