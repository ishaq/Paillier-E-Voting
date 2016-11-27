"""
Common models and utility functions
"""

import struct
import pickle
import socket

import config
import em_interface

class RespError:
    """
    represents an error response from the server
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return "<RespError: {}>".format(self.msg)

def read_message(conn):
    """
    Reads message from a socket

    :param conn: the socket to read from
    :return: length of the message OR None if message length cannot be read
    """

    buf = _read_socket_buf(conn, 4)
    if not buf:
        print("Error: Unable to read message size")
        return None

    msg_size = struct.unpack("!i", buf)[0]
    print("Length of the message is: {}".format(msg_size))

    buf = _read_socket_buf(conn, msg_size)
    if not buf:
        print("Error: Unable to read message of length {}".format(msg_size))
        return None

    obj = pickle.loads(buf)
    return obj

def write_message(conn, obj):
    """
    Writes a message to the socket

    :param conn: the socket to write to
    :param obj: any python object supported by pickle, it will be written to the socket
    :return:
    """

    msg = pickle.dumps(obj)
    msg_size = len(msg)
    buf_to_write = struct.pack("!i", msg_size) + msg
    conn.sendall(buf_to_write)


def get_public_key_from_em():
    """
    Gets public keys from the EM

    :return: public keys
    """
    sock_to_em = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_to_em.connect(config.EM_ADDR)
    write_message(sock_to_em, em_interface.ReqPublicKeys())
    pub_keys = read_message(sock_to_em)
    print("RSA: {}, Paillier: {}".format(pub_keys.rsa_pub_key, pub_keys.paillier_pub_key))
    # socket will be closed by the EM server
    return pub_keys

# --- Private ---

def _read_socket_buf(conn, n):
    """
    Reads buffer from conn up to n bytes

    :param conn: the socket to read from
    :param n: number of bytes to read
    :return: the buffer OR None
    """
    buf = b''
    while len(buf) < n:
        new_data = conn.recv(n - len(buf))
        if not new_data:
            return None
        buf += new_data
    return buf
