#!/usr/bin/python

import socket
import threading
import signal, sys
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

from cryptography.exceptions import InvalidSignature

# An useful function to open files in the same dir as script...
__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
def path(fname):
  return os.path.join(__location__, fname)

host = "localhost"
port = 8080
connections = []
total_connections = 0

# RFC 3526's parameters. Easier to hardcode...
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
params_numbers = dh.DHParameterNumbers(p,g)
parameters = params_numbers.parameters()

AES_BLOCK_LEN = 16 # bytes
AES_KEY_LEN = 32 # bytes
PKCS7_BIT_LEN = 128 # bits
SOCKET_READ_BLOCK_LEN = 4096 # bytes

def signal_handler(sig, frame):
  print('You pressed Ctrl+C; bye...')
  sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

class Client(threading.Thread):
  def __init__(self, socket: socket.socket, address, id, name):
      threading.Thread.__init__(self)
      self.socket = socket
      self.address = address
      self.id = id
      self.name = name

      # Don't wait for child threads (client connections) to finish.
      self.daemon = True

      # Symmetric (shared) key
      self.key = None

      # Private key from the server's certificate
      self.private_key = None
      with open(path("TC_Server.key.pem"), "rb") as key_file:
        self.private_key = load_pem_private_key(key_file.read(), password=None)

      # Certificate and public key from the server's certificate
      self.public_key = None
      self.certificate_as_bytes = None
      with open(path("TC_Server.cert.pem"), "rb") as cert_file:
        self.certificate_as_bytes = cert_file.read()
        cert = load_pem_x509_certificate(self.certificate_as_bytes)
        self.public_key = cert.public_key()

      self.client_certificate = None
      self.client_public_key = None
    
  def __str__(self):
      return str(self.id) + " " + str(self.address)

  # Receives and returns bytes.
  def encrypt(self, m):
    padder = padding.PKCS7(PKCS7_BIT_LEN).padder()
    padded_data = padder.update(m) + padder.finalize()

    iv = os.urandom(AES_BLOCK_LEN)
    
    cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    ct = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ct

  # Receives and returns bytes.
  def decrypt(self, c):
    iv, ct = c[:AES_BLOCK_LEN], c[AES_BLOCK_LEN:]

    cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))

    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()

    unpadder = padding.PKCS7(PKCS7_BIT_LEN).unpadder()
    pt = unpadder.update(pt) + unpadder.finalize()

    return pt

  def handshake(self, debug = False):
    # Generate a private key for this client
    g_y = parameters.generate_private_key()
    g_y_as_bytes = g_y.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    # Generate a salt to be used for key derivation
    salt = os.urandom(AES_KEY_LEN)

    # Wait for the public parameter of the client's DH key
    g_x_as_bytes = self.socket.recv(SOCKET_READ_BLOCK_LEN)

    # Build DHPublicKey object from the client's public key bytes
    g_x: dh.DHPublicKey = load_pem_public_key(g_x_as_bytes)

    # Perform the key exchange to derive the shared secret
    shared_secret = g_y.exchange(g_x)

    # Perform key derivation from the shared secret
    # This step isn't technically required by the protocol,
    # but it is recommended by cryptography's documentation,
    # so, we decided to implement it for completeness
    self.key = HKDF(
      algorithm=hashes.SHA256(),
      length=AES_KEY_LEN,
      salt=salt,
      info=b''
    ).derive(shared_secret)

    # Send to the client the following, separated by \r\n\r\n:
    # 1) Salt for key derivation
    # 2) g^y
    # 3) E_k(S_B(g^y, g^x)), onde k é a derived key (self.key) acima calculada e B é a chave privada assimétrica do servidor
    # 4) Server certificate
    self.socket.sendall(b'\r\n\r\n'.join([salt, g_y_as_bytes, self.encrypt(self.sign(g_y_as_bytes + g_x_as_bytes)), self.certificate_as_bytes]))

    # Receive from the client the following, separated by \r\n\r\n:
    # 1) E_k(S_A(g^x, g^y)), onde k é a derived key acima calculada e A é a chave privada assimétrica do cliente
    # 2) Client certificate
    encrypted_signature_gx_gy, client_certificate_as_bytes = self.socket.recv(SOCKET_READ_BLOCK_LEN).split(b'\r\n\r\n')

    # Decrypt the signature of the concatenation of g^x, g^y
    signature_gx_gy = self.decrypt(encrypted_signature_gx_gy)

    # Build a x509.Certificate object from the client's certificate
    self.client_certificate = load_pem_x509_certificate(client_certificate_as_bytes)
    self.client_public_key = self.client_certificate.public_key()
    
    # Verify the client's certificate against the CA's certificate
    if not self.validate_certificate(debug):
      return False

    # Verify the signature of the concatenation
    if not self.verify(self.client_public_key, g_x_as_bytes + g_y_as_bytes, signature_gx_gy):
      return False

    # Everything went well! Handshake succeded and connection is ready for communication.
    return True

  def run(self):
    print("Going to do handshake for client " + str(self.address) + "... ", end='')
    hs = self.handshake()
    if hs is None or self.key is None:
      print("FAILED.")
      print("Client " + str(self.address) + ": closing connection.")
      self.socket.close()
      connections.remove(self)
      return False
    print("done.")

    data = ""
    while True:
      try:
        data = self.socket.recv(SOCKET_READ_BLOCK_LEN)
      except:
        pass
      if len(data) > 0:
        pt = self.decrypt(data)
        print("ID " + str(self.id) + ": " + pt.decode("utf-8"))

        self.socket.sendall(self.encrypt("Server received: ".encode("utf-8") + pt))
      else:
        print("Client " + str(self.address) + " has disconnected")
        self.socket.close()
        connections.remove(self)
        break

  # Message is bytes.
  def sign(self, message):
    # Given a message, this function signs the given message
    # with this server's private key and returns that signature.

    # This function is crucial for the STS protocol as it provides the
    # means necessary for the remote client to verify that this server
    # is indeed who it says it is, that there is no man-in-the-middle
    # pretending to be this server, and that the given message was
    # indeed sent by this server.

    signature = self.private_key.sign(
      message,
      PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
      hashes.SHA256()
    )

    return signature

  # m and sig are bytes.
  def verify(self, public_key, m, sig):
    # Given a public key, a message and a signature,
    # this function verifies if the given signature matches
    # the signature obtained by signing the message m with the
    # given public key, and returns True if the signatures match

    # This function is crucial for the STS protocol as it verifies
    # that the remote client is indeed in possession of the private
    # key corresponding to the given public key, and in doing so,
    # verifies that the client is indeed who he says he is (assuming 
    # the certificate was issued by a valid CA).

    try:
      public_key.verify(
        sig,
        m,
        PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
        hashes.SHA256()
      )

      return True
    except InvalidSignature:
      return False

  # Receives the certificate object (not the bytes).
  def validate_certificate(self, debug = False):
    # This function verifies that the client's certificate isn't malformed
    # and that it was properly issued and signed by the Certificate Authority (CA)
    # It does so by comparing the Issuer's attributes present on the client certificate
    # with the subject attributes present on the CA's certificate, as well as by
    # verifying the client certificate's signature using the CA's public key

    certificate = self.client_certificate

    ca_public_key = None
    ca_cert = None
    with open(path("TC_CA.cert.pem"), "rb") as cert_file:
      ca_cert = load_pem_x509_certificate(cert_file.read())
      ca_public_key = ca_cert.public_key()

    # Make sure the country specified in the CA's certificate is the same as
    # the issuer's country specified in the client's certificate
    if ca_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value != \
        certificate.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value:
          debug and print("Mismatched field: %s" % NameOID.COUNTRY_NAME)
          return False

    # Make sure the "state or province name" specified in the CA's certificate is the same as
    # the issuer's "state or province name" specified in the client's certificate
    if ca_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value != \
        certificate.issuer.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value:
          debug and print("Mismatched field: %s" % NameOID.STATE_OR_PROVINCE_NAME)
          return False

    # Make sure the "locality name" specified in the CA's certificate is the same as
    # the issuer's "locality name" specified in the client's certificate
    if ca_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value != \
        certificate.issuer.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value:
          debug and print("Mismatched field: %s" % NameOID.LOCALITY_NAME)
          return False

    # Make sure the "organization name" specified in the CA's certificate is the same as
    # the issuer's "organization name" specified in the client's certificate
    if ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value != \
        certificate.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value:
          debug and print("Mismatched field: %s" % NameOID.ORGANIZATION_NAME)
          return False

    # Make sure the "organizational unit name" specified in the CA's certificate is the same as
    # the issuer's "organizational unit name" specified in the client's certificate
    if ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value != \
        certificate.issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value:
          debug and print("Mismatched field: %s" %
              NameOID.ORGANIZATIONAL_UNIT_NAME)
          return False

    # Make sure the "common name" specified in the CA's certificate is the same as
    # the issuer's "common name" specified in the client's certificate
    if ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != \
        certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value:
          debug and print("Mismatched field: %s" % NameOID.COMMON_NAME)
          return False

    # Make sure the "common name" attribute present on the client's certificate matches
    # the string "TC Client"
    if certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != "TC Client":
      debug and print("Wrong field (server cert): %s" % NameOID.COMMON_NAME)
      return False

    # Make sure the client certificate's signature was issued by the CA
    ca_public_key.verify(
      certificate.signature,
      certificate.tbs_certificate_bytes,
      PKCS1v15(),
      certificate.signature_hash_algorithm)

    return True

def main():
  # Create new server socket. Set SO_REUSEADDR to avoid annoying "address
  # already in use" errors, when doing Ctrl-C plus rerunning the server.
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.bind((host, port))
  sock.listen(5)

  # Create new thread to wait for connections.
  while True:
    client_socket, address = sock.accept()
    global total_connections
    connections.append(Client(client_socket, address, total_connections, "Name"))
    connections[len(connections) - 1].start()
    total_connections += 1
  for t in connections:
    t.join()
  
if __name__ == '__main__':
  main()
