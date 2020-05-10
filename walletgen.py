#!/usr/local/bin/python3
import hashlib
import ecdsa
import base58

def wifFromPrivateKey(privateKey):
  # add 0x80 in front for mainnet private key
  extendedKey = b'\x80' + privateKey

  # checksum is first 4 bytes of double sha256 hash of extended key
  checksum = hashlib.sha256(hashlib.sha256(extendedKey).digest()).digest()[:4]

  # WIF is extended key + checksum in base58
  WIF = base58.b58encode(extendedKey + checksum) 
  return WIF.decode()

def wifToPrivateKey(WIF): 
  extendedKey = base58.b58decode(WIF)[:-4]
  return extendedKey[1:]

def addressFromPrivateKey(privateKey):
  # get ecdsa key objects for privateKey
  signingKey = ecdsa.SigningKey.from_string(privateKey, curve=ecdsa.SECP256k1)
  verifyingKey = signingKey.get_verifying_key()

  # sha256 then ripemd160 on compressed pub key
  compressedPubKey = verifyingKey.to_string("compressed") 
  sha256 = hashlib.sha256(compressedPubKey).digest()
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
  with open("WIF", "r") as file:
    WIF = file.readline()

  privateKey = wifToPrivateKey(WIF)
  address = addressFromPrivateKey(privateKey)
  print(address)

  # with open("WIF", "w") as file:
  #   file.write(WIF)

  # import qrcode
  # img = qrcode.make(address)
  # img.save("address.png")

