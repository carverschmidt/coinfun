#!/usr/local/bin/python3
import time
import socket
import struct
import hashlib
import random
from hexdump import hexdump

MAGIC = 0xe8f3e1e3 
NODES = socket.gethostbyname_ex('seed.bitcoinabc.org')[2]
PORT = 8333

def checksum(data):
  return hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]

def receiveBytes(sock, n):
  data = b''
  while len(data) < n:
    packet = sock.recv(n - len(data))
    if not packet:
      return None
    data += packet
  return data
  
def createMessage(command, payload):
  return struct.pack('<L12sL4s', MAGIC, command, len(payload), checksum(payload)) + payload

def createVersionMessage():
  version = 70015
  services = 0
  timestamp = int(time.time())
  perceivedServices = 1
  receiveAddress = b'\x00'*16
  receivePort = 0
  transAddress = b'\x00'*16
  transPort = 0
  nonce = 0
  userAgentBytes = 0
  startHeight = 0 
  
  payload = struct.pack('<LQQQ16shQ16shQ?L', version, services, timestamp, perceivedServices,
                       receiveAddress, receivePort, services, transAddress, transPort, nonce,
                       userAgentBytes, startHeight)
  return createMessage(b'version', payload)

def receiveMessage(sock):
  header = receiveBytes(sock, 24)

  magic, command, payloadLen, cksm = struct.unpack('<L12sL4s', header)
  assert magic == MAGIC
  payload = receiveBytes(sock, payloadLen)
  assert cksm == checksum(payload)

  hexdump(header)
  hexdump(payload)
  return command, payload
  
if __name__ == '__main__':
  # create socket
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((NODES[random.randint(0, len(NODES) - 1)], PORT)) 

  # send and receive version
  sock.send(createVersionMessage())
  receiveMessage(sock)

  # send and receive verack
  sock.send(createMessage(b'verack', b''))
  receiveMessage(sock)

