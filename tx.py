#!/usr/local/bin/python3
import sys
import time
import socket
import struct
import hashlib
import random
import ecdsa
from hexdump import hexdump
from walletgen import *

MAGIC = 0xe8f3e1e3 
NODES = socket.gethostbyname_ex('seed.bitcoinabc.org')[2]
PORT = 8333

OP_DUP = b'\x76'
OP_HASH160 = b'\xA9'
OP_EQUALVERIFY = b'\x88'
OP_CHECKSIG = b'\xAC'

def dsha256(data):
  return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def checksum(data):
  return dsha256(data)[:4]

def getSignature(signingKey, data):
  """Get Signature with low s"""
  while 1:
    signature = signingKey.sign_digest(data, sigencode=ecdsa.util.sigencode_der)
    N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    r, s = ecdsa.util.sigdecode_der(signature, signingKey.curve.generator.order())
    if s < N/2:
      break
  return signature

def receiveBytes(sock, n):
  data = b''
  while len(data) < n:
    try:
      packet = sock.recv(n - len(data))
      data += packet
    except ConnectionResetError:
      print("Connection to the network node has been lost")
      sys.exit(1)
    except KeyboardInterrupt:
      sys.exit(0)
  return data
  
def receiveMessage(sock):
  header = receiveBytes(sock, 24)
  magic, command, payloadLen, cksm = struct.unpack('<L12sL4s', header)
  assert magic == MAGIC

  payload = receiveBytes(sock, payloadLen)
  assert cksm == checksum(payload)

  hexdump(header)
  hexdump(payload)
  return command, payload

def createMessage(command, payload):
  return struct.pack('<L12sL4s', MAGIC, command, len(payload), checksum(payload)) + payload

def createVersionPayload():
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
  return payload 

def createBTCTxPayload(fromTx, fromIndex, toAddress, amount, privateKey):
  """Create payload for BTC Tx
  Hasn't been tested... maybe work?
  """
  fees = 400
  version = 1
  numInputs = 1
  signingKey = ecdsa.SigningKey.from_string(privateKey, curve=ecdsa.SECP256k1)
  pubKey = signingKey.get_verifying_key().to_string("compressed")
  pubKeyHash = hashlib.new('ripemd160')
  pubKeyHash.update(hashlib.sha256(pubKey).digest())
  fromScriptPubKey = OP_DUP + OP_HASH160 + b'\x14' + pubKeyHash.digest() + OP_EQUALVERIFY + OP_CHECKSIG
  sequence = 0xffffffff
  numOutputs = 1
  toPubKeyHash = base58.b58decode(toAddress)[1:-4]
  scriptPubKey = OP_DUP + OP_HASH160 + b'\x14' + toPubKeyHash + OP_EQUALVERIFY + OP_CHECKSIG
  lockTime = 0
  hashCode = 1

  txIn = struct.pack('<32sLB', fromTx, fromIndex, len(fromScriptPubKey)) + fromScriptPubKey
  txIn += struct.pack('<L', sequence)
  
  txOut = struct.pack('<qB', amount, len(scriptPubKey)) + scriptPubKey

  unsignedTx = struct.pack('<lB', version, numInputs) + txIn 
  unsignedTx += struct.pack('<B', numOutputs) + txOut + struct.pack('<L', lockTime)
  unsignedTx += struct.pack('<L', hashCode)

  hashedTx = hashlib.sha256(hashlib.sha256(unsignedTx).digest()).digest()
  signature = signingKey.sign_digest(hashedTx)
  signature += b'\x01'

  print(pubKey.hex())
  print(hex(len(pubKey)))
  scriptSig = struct.pack('<B', len(signature)) + signature + struct.pack('<B', len(pubKey)) + pubKey

  txIn = struct.pack('<32sLB', fromTx, fromIndex, len(scriptSig)) + scriptSig
  txIn += struct.pack('<L', sequence) 

  txOut = struct.pack('<qB', amount-fees, len(scriptPubKey)) + scriptPubKey

  rawTx = struct.pack('<lB', version, numInputs) + txIn
  rawTx += struct.pack('<B', numOutputs) + txOut + struct.pack('<L', lockTime)
  return rawTx

def createBCHTxPayload(fromTx, fromIndex, toAddress, amount, privateKey):
  """Create BCH Tx Payload
  Has been tested... It work!!!!!
  """
  fees = 400
  nVersion = 1
  nSequence = b'\xFF\xFF\xFF\xFF'

  outpoint = struct.pack('<32sL', fromTx, fromIndex)

  hashPrevouts = dsha256(outpoint)
  hashSequence = dsha256(nSequence)

  signingKey = ecdsa.SigningKey.from_string(privateKey, curve=ecdsa.SECP256k1)
  pubKey = signingKey.get_verifying_key().to_string("compressed")
  pubKeyHash = hashlib.new('ripemd160')
  pubKeyHash.update(hashlib.sha256(pubKey).digest())

  fromScriptPubKey = OP_DUP + OP_HASH160 + b'\x14' + pubKeyHash.digest() + OP_EQUALVERIFY + OP_CHECKSIG

  toPubKeyHash = base58.b58decode(toAddress)[1:-4]
  scriptPubKey = OP_DUP + OP_HASH160 + b'\x14' + toPubKeyHash + OP_EQUALVERIFY + OP_CHECKSIG

  hashOutputs = dsha256(struct.pack('<qB', amount-fees, len(scriptPubKey)) + scriptPubKey)

  lockTime = 0
  hashType = b'\x41\x00\x00\x00'

  preImage = struct.pack('<L', nVersion) + hashPrevouts + hashSequence + outpoint 
  preImage += struct.pack('<B', len(fromScriptPubKey)) + fromScriptPubKey + struct.pack('<q', amount) 
  preImage += nSequence + hashOutputs + struct.pack('<L', lockTime) + hashType

  sigHash = dsha256(preImage)
  signature = getSignature(signingKey, sigHash) 
  
  vk = signingKey.get_verifying_key()
  vk.verify_digest(signature, sigHash, sigdecode=ecdsa.util.sigdecode_der)
  
  signature += b'\x41'

  scriptSig = struct.pack('<B', len(signature)) + signature + struct.pack('<B', len(pubKey)) + pubKey

  numInputs = 1
  numOutputs = 1
  rawTx = struct.pack('<lB', nVersion, numInputs) + outpoint + struct.pack('<B', len(scriptSig))
  rawTx += scriptSig + nSequence + struct.pack('<BqB', numOutputs, amount-fees, len(scriptPubKey))
  rawTx += scriptPubKey + struct.pack('<L', lockTime)
  return rawTx
  
if __name__ == '__main__':
  versionMessage = createMessage(b'version', createVersionPayload())
  verackMessage = createMessage(b'verack', b'')
  
  fromTx = bytes.fromhex('acd96385785b52e91ed4d916c777c92307b34426819854245ce346dcc00f3ee1')[::-1]
  fromIndex = 1
  toAddress = '18GSUbU1d5PiEttjFBvE9DHceBfPS3yZR2'
  amount = 41873
  privateKey = wifToPrivateKey('L56apAanasrwDQdJXazgthxwyagqtTeDeqMmct44xECr14k9SPMS')
  
  rawTx = createBCHTxPayload(fromTx, fromIndex, toAddress, amount, privateKey)
  txMessage = createMessage(b'tx', rawTx)

  if(input("Send Tx?: ") == 'y'):
    # create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((NODES[random.randint(0, len(NODES) - 1)], PORT)) 

    # send and receive version
    print("SENDING: ")
    hexdump(versionMessage)
    sock.send(versionMessage)
    print("RECEIVING: ")
    receiveMessage(sock)

    # send and receive verack
    print("SENDING: ")
    hexdump(verackMessage)
    sock.send(verackMessage)
    print("RECEIVING: ")
    receiveMessage(sock)

    # send tx
    print("SENDING: ")
    hexdump(txMessage)
    sock.send(txMessage)

    # receive messages
    while 1:
      print("RECEIVING: ")
      receiveMessage(sock)
  else:
    print(rawTx.hex())

