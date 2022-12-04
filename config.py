import rsa
import json
import socket


#WARNING
#editing this file may make this application work in unexpected ways
#by editing this file the users warranty is voided
#as such a refund of $0.00 will no longer be on offer.


USER_NAME = ""

BROADCAST_IP_ADDRESS = "255.255.255.255"
PORT = 4991
HOST = "0.0.0.0"

#bits for generating encryption keys
BITS = 2048

HASHTYPE = "MD5"

###amount of potentially open sockets(unused for now)
SOCKET_RANGE = [5000, 5050]

IP_ADDRESS = socket.gethostbyname(socket.gethostname())

###max users should not be set to a value higher than the range in SOCKET_RANGE
MAX_USERS = SOCKET_RANGE[1] - SOCKET_RANGE[0]

with open("id_rsa", "rb") as f:
    PRIVATE_KEY = rsa.PrivateKey.load_pkcs1(f.read())


with open("id_rsa.pub", "rb") as f:
    PUBLIC_KEY = rsa.PublicKey.load_pkcs1(f.read())

try:
    with open("hosts.json", "r") as hostsfile:
        hosts = json.load(hostsfile)
except json.decoder.JSONDecodeError:
    hosts = {}

