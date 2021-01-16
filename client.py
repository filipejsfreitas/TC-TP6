#!/usr/bin/python

import socket
import threading
import sys, signal
import os
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.x509 import load_pem_x509_certificate, Certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1, PKCS1v15

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from cryptography.exceptions import InvalidSignature

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
  padder = padding.PKCS7(PKCS7_BIT_LEN).padder()
  padded_data = padder.update(m) + padder.finalize()

  iv = os.urandom(AES_BLOCK_LEN)

  cipher = Cipher(algorithms.AES(k), modes.CBC(iv))
  encryptor = cipher.encryptor()

  ct = encryptor.update(padded_data) + encryptor.finalize()
  return iv+ct

# Receives and returns bytes.
def decrypt(k, c):
  iv, ct = c[:AES_BLOCK_LEN], c[AES_BLOCK_LEN:]
  
  cipher = Cipher(algorithms.AES(k), modes.CBC(iv))

  decryptor = cipher.decryptor()
  pt = decryptor.update(ct) + decryptor.finalize()

  unpadder = padding.PKCS7(PKCS7_BIT_LEN).unpadder()
  pt = unpadder.update(pt) + unpadder.finalize()

  return pt

def handshake(socket: socket.socket):
  # Generate a private key for this session
  g_x = parameters.generate_private_key()
  g_x_as_bytes = g_x.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

  # Send the public parameter of our DH key to the server
  socket.sendall(g_x_as_bytes)

  # Wait for the public parameter of the server's DH key as well as the salt to be used for key derivation
  salt, g_y_as_bytes, encrypted_signature_gy_gx, server_certificate_as_bytes = socket.recv(SOCKET_READ_BLOCK_LEN).split(b'\r\n\r\n')

  # Create a DHPublicKey object from the server's DH public key bytes
  g_y: dh.DHPublicKey = load_pem_public_key(g_y_as_bytes)

  # Perform the key exchange to derive the shared key
  shared_key = g_x.exchange(g_y)

  # Perform key derivation from the shared key
  derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=AES_KEY_LEN,
    salt=salt,
    info=b''
  ).derive(shared_key)

  # Create a x509.Certificate object from the server's certificate bytes
  server_certificate = load_pem_x509_certificate(server_certificate_as_bytes)
  # TODO: Maybe verify if the server's certificate was issued by the provided CA?

  # Decrypt the server's signature of g^y and g^x and verify it
  signature_gy_gx = decrypt(derived_key, encrypted_signature_gy_gx)

  # Verify the signature of the concatenation of g^y, g^x is valid
  if not verify(server_certificate.public_key(), g_y_as_bytes + g_x_as_bytes, signature_gy_gx):
    print('Signature verification failed!')
    print('Signature verification returned: ' + verify(server_certificate.public_key(), g_y_as_bytes + g_x_as_bytes, signature_gy_gx))
    return None

  # Load this client's private/public key pair and certificate
  private_key = None
  with open(path("TC_Server.key.pem"), "rb") as key_file:
    private_key = load_pem_private_key(key_file.read(), password=None)
  
  certificate_as_bytes = None
  with open(path("TC_Server.cert.pem"), "rb") as cert_file:
    certificate_as_bytes = cert_file.read()
  
  # Sign, with this client's private key, the concatenation of g^x and g^y, in this order
  # and then encrypt the resulting signature with the derived shared secret
  encrypted_signature_gx_gy = encrypt(derived_key, sign(private_key, g_x_as_bytes + g_y_as_bytes))

  # Send to the server this client's encrypted signature of g^x and g^y, as well as this client's 
  print(len(encrypted_signature_gx_gy), len(certificate_as_bytes))
  socket.sendall(b'\r\n\r\n'.join([encrypted_signature_gx_gy, certificate_as_bytes]))

  # Return the derived key to be used for this session
  return derived_key

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
def verify(public_key: RSAPublicKey, message, signature):
  try:
    public_key.verify(
      signature,
      message,
      PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
      hashes.SHA256()
    )
    
    return True
  except InvalidSignature:
    return False

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
