#!/usr/local/bin/python3
import hashlib
import ecdsa
import base58

def wifFromPrivateKey(privateKey, compressed=True):
  # add 0x80 in front for mainnet private key
  extendedKey = b'\x80' + privateKey
  if compressed: 
    extendedKey += b'\x01'

  # checksum is first 4 bytes of double sha256 hash of extended key
  checksum = hashlib.sha256(hashlib.sha256(extendedKey).digest()).digest()[:4]

  # WIF is extended key + checksum in base58
  WIF = base58.b58encode(extendedKey + checksum) 
  return WIF.decode()

def wifToPrivateKey(WIF): 
  if WIF[:1] == 'K' or WIF[:1] == 'L':
    return base58.b58decode(WIF)[1:-5]
  elif WIF[:1] == '5':
    return base58.b58decode(WIF)[1:-4]
  else:
    print("Invalid WIF for main net!")
    return None

def addressFromPrivateKey(privateKey, compressed=True):
  # get ecdsa key objects for privateKey
  signingKey = ecdsa.SigningKey.from_string(privateKey, curve=ecdsa.SECP256k1)
  verifyingKey = signingKey.get_verifying_key()

  # sha256 then ripemd160 
  if compressed:
    publicKey = verifyingKey.to_string("compressed")
  else:
    publicKey = b'\x04' + verifyingKey.to_string()
  sha256 = hashlib.sha256(publicKey).digest()
  hash160 = hashlib.new('ripemd160')
  hash160.update(sha256)

  # add 0x00 version byte for main network
  extended160 = b'\x00' + hash160.digest()

  # get checksum
  checksum = hashlib.sha256(hashlib.sha256(extended160).digest()).digest()[:4]

  # address is extended ripemd160 + checksum in base58
  address = base58.b58encode(extended160 + checksum)
  return address.decode()
  

if __name__ == '__main__':
  with open("fromWIF", "r") as file:
    fromWIF = file.readline()
  with open("toWIF", "r") as file:
    toWIF = file.readline()

  fromAddress = addressFromPrivateKey(wifToPrivateKey(fromWIF))
  toAddress = addressFromPrivateKey(wifToPrivateKey(toWIF))

  print("{} -> {}".format(fromAddress, toAddress))

