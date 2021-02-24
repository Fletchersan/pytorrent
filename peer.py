import socket

from helpers import *


def download_from_peer(peer_ip, peer_port):
    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer_socket.connect((peer_ip, peer_port))

    peer_socket.recv_into()


def build_handshake_message(infohash):

    protocol_string = "BitTorrent protocol"

    p_str_len = to_bytes(len(protocol_string), 1)

    p_str = bytes(protocol_string)

    reserved = ZERO8BYTE

    handshake_message = p_str_len + p_str + reserved + infohash + PEER_ID

    return handshake_message

# message format = length of message (4B) + message id (1B) + payload

# no message id, therfore length of message = 0 in 4 bytes


def build_keepalive_message():
    return ZERO4BYTE


def build_choke_message():
    # length = 1 byte, id = 0
    return ONE4BYTE + to_bytes(0, 1)


def build_unchoke_message():
    # length = 1 byte, id = 1
    return ONE4BYTE + to_bytes(1, 1)


def build_interested_message():
    # length = 1 byte, id = 2
    return ONE4BYTE + to_bytes(2, 1)


def build_uninterested_message():
    # length = 1 byte, id = 3
    return ONE4BYTE + to_bytes(3, 1)


def build_have_message(piece_index):
    # length = 5 bytes, id = 4, payload
    return to_bytes(5, 4) + to_bytes(4, 1) + to_bytes(piece_index, 4)


def build_bitfield_message(bitfield):
    # length = 1 byte (for id) + length of bitfield, id = 5, payload
    return to_bytes(len(bitfield), 4) + to_bytes(5, 1) + bitfield


def build_request_message(piece_index, block_offset, length):
    # length = 13 bytes, id = 6, piece_index, block_offset, length
    return to_bytes(13, 4) + to_bytes(6, 1) + to_bytes(piece_index, 4) \
        + to_bytes(block_offset, 4) + to_bytes(length, 4)


def build_piece_message(piece_index, block_offset, block):
    # length = 9 bytes (for id, piece_index, block_offset) + length of block,
    #   id = 7, piece_index, block_offset, block
    return to_bytes(9 + len(block), 4) + to_bytes(7, 1) + to_bytes(piece_index, 4) \
        + to_bytes(block_offset, 4) + block


def build_cancel_message(piece_index, block_offset, length):
    # length = 13 bytes, id = 8, piece_index, block_offset, length
    return to_bytes(13, 4) + to_bytes(8, 1) + to_bytes(piece_index, 4) \
        + to_bytes(block_offset, 4) + to_bytes(length, 4)


def build_port_message(listen_port):
    # length = 3 bytes, id = 9, port
    return to_bytes(3, 4) + to_bytes(9, 1) + to_bytes(listen_port, 2)