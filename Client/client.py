#!/usr/bin/python

import socket
import threading
import sys, signal
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1, PKCS1v15

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

AES_BLOCK_LEN = 16 # bytes
AES_KEY_LEN = 32 # bytes
PKCS7_BIT_LEN = 128 # bits
SOCKET_READ_BLOCK_LEN = 4096 # bytes

def signal_handler(sig, frame):
  print('You pressed Ctrl+C; bye...')
  sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

# An useful function to open files in the same dir as script...
__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
def path(fname):
  return os.path.join(__location__, fname)

host = "localhost"
port = 8080

# RFC 3526's parameters. Easier to hardcode...
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
params_numbers = dh.DHParameterNumbers(p,g)
parameters = params_numbers.parameters()

def connect():
  #Attempt connection to server
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock
  except Exception as e:
    print("Could not make a connection to the server: %s" % e)
    input("Press enter to quit")
    sys.exit(0)

# Receives and returns bytes.
def encrypt(k, m):
  return m # delete this...

  padder = padding.PKCS7(PKCS7_BIT_LEN).padder()
  padded_data = padder.update(m) + padder.finalize()
  iv = os.urandom(AES_BLOCK_LEN)
  cipher = Cipher(algorithms.AES(k), modes.CBC(iv))
  encryptor = cipher.encryptor()

  ct = encryptor.update(padded_data) + encryptor.finalize()
  return iv+ct

# Receives and returns bytes.
def decrypt(k, c):
  return c # delete this...

  iv, ct = c[:AES_BLOCK_LEN], c[AES_BLOCK_LEN:]
  cipher = Cipher(algorithms.AES(k), modes.CBC(iv))
  decryptor = cipher.decryptor()
  pt = decryptor.update(ct) + decryptor.finalize()
  unpadder = padding.PKCS7(PKCS7_BIT_LEN).unpadder()
  pt = unpadder.update(pt) + unpadder.finalize()
  return pt

def handshake(socket):
  return "some random key" # change this...

def process(socket):
  print("Going to do handshake... ", end='')
  k = handshake(socket)
  if k is None:
    print("FAILED.")
    return False
  print("done.")

  while True:
    pt = input("Client message: ")
    if len(pt) > 0:
      socket.sendall(encrypt(k, pt.encode("utf-8")))
    else:
      socket.close()
      break
    try:
      data = socket.recv(SOCKET_READ_BLOCK_LEN)
      pt = decrypt(k, data)
      print(pt.decode("utf-8"))
    except:
      print("You have been disconnected from the server")
      break

# Message is bytes.
def sign(private_key, message):
  signature = private_key.sign(
      message,
      PSS(mgf=MGF1(hashes.SHA256()),
                  salt_length=PSS.MAX_LENGTH),
      hashes.SHA256())
  return signature

# Message and signature bytes.
def verify(public_key, message, signature):
  public_key.verify(
      signature,
      message,
      PSS(mgf=MGF1(hashes.SHA256()),
                  salt_length=PSS.MAX_LENGTH),
      hashes.SHA256())

# Receives the certificate object (not the bytes).
def validate_certificate(certificate, debug = False):
  ca_public_key = None
  ca_cert = None
  with open(path("TC_CA.cert.pem"), "rb") as cert_file:
    ca_cert = load_pem_x509_certificate(cert_file.read())
    ca_public_key = ca_cert.public_key()

  if ca_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value != \
      certificate.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value:
        debug and print("Mismatched field: %s" % NameOID.COUNTRY_NAME)
        return False

  if ca_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value != \
      certificate.issuer.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value:
        debug and print("Mismatched field: %s" % NameOID.STATE_OR_PROVINCE_NAME)
        return False

  if ca_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value != \
      certificate.issuer.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value:
        debug and print("Mismatched field: %s" % NameOID.LOCALITY_NAME)
        return False

  if ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value != \
      certificate.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value:
        debug and print("Mismatched field: %s" % NameOID.ORGANIZATION_NAME)
        return False

  if ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value != \
      certificate.issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value:
        debug and print("Mismatched field: %s" %
            NameOID.ORGANIZATIONAL_UNIT_NAME)
        return False

  if ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != \
      certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value:
        debug and print("Mismatched field: %s" % NameOID.COMMON_NAME)
        return False

  if certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != "TC Server":
    debug and print("Wrong field (server cert): %s" % NameOID.COMMON_NAME)
    return False

  ca_public_key.verify(
    certificate.signature,
    certificate.tbs_certificate_bytes,
    PKCS1v15(),
    certificate.signature_hash_algorithm)

  return True

def main():
  s = connect()
  process(s)

if __name__ == '__main__':
  main()
