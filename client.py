import socket
import config
import rsa


def sign(message, key=config.PRIVATE_KEY, hashtype=config.HASHTYPE):
    signature = (rsa.sign(message, key, hashtype))
    return message + b"\r\n" + signature

def init_call(ip, port):
    # Create a socket (SOCK_STREAM means a TCP socket)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    key = config.PUBLIC_KEY.save_pkcs1("PEM")
    message = b"INIT\r\n" + config.USER_NAME.encode() + b"\r\n" + key.decode().encode() + b"\r\n" + config.IP_ADDRESS.encode()
    sock.sendto(sign(message), (ip, port))

def find_user(public_key):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in config.hosts:
        ip = i[1][1]
        key = config.PUBLIC_KEY.save_pkcs1("PEM")
        sock.sendto(sign(b"FIND_USER\r\n" + config.USER_NAME.encode() + b"\r\n" + key.decode().encode() + b"\r\n" + public_key.encode()), (ip, config.PORT))

def start_convo(ip_address, public_key = None):
    if public_key == None:
        publickeyset = False
        counter = 0
        for i in config.hosts.values():
            if i[1] == ip_address:
                public_key = list(config.hosts.keys())[counter]
                publickeyset = True
            counter = counter + 1
        
        if not publickeyset:
            print("Key not found")
            return False
        
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    key = config.PUBLIC_KEY.save_pkcs1("PEM")
    message = b"START_CONVO\r\n" + config.USER_NAME.encode() + b"\r\n" + key.decode().encode() + b"\r\n" + config.IP_ADDRESS.encode()
    sock.sendto(sign(message), (ip_address, config.PORT))
