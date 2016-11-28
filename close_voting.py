"""
Utility script to close voting session. Running this script will close voting session and display results in the EM
"""

import socket

import config
import common

import bb_interface

sock_to_bb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock_to_bb.connect(config.BB_ADDR)
req = bb_interface.ReqCloseVoting()
common.write_message(sock_to_bb, req)
print("Request Sent! Please check EM for results...")