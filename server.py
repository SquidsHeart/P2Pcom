import socketserver
import threading
import json
import time
import socket
import rsa

import config

import Crypto.Cipher.AES as CCA
import Crypto.Random as CR

import base64

global_hostslock = False
hostslock = False

current_port = config.SOCKET_RANGE[0]

class UDPServerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.data = self.request
        self.split_data = self.data[0].split(b"\r\n")
        
        if self.split_data[0] == b"INIT":
            if self.client_address == "127.0.0.1":
                return False
            
            if not verify_signature((b"\r\n".join(self.split_data[0:-1])), self.split_data[-1], self.split_data[2]):
                print("POTENTIAL TAMPERING DETECTED: PACKET DOES NOT MATCH SIGNATURE")
                return False
            else:
                ###verify that intercepted packets are not being used by a different machine
                if not self.split_data[3] == self.client_address[0].encode():
                    print("POTENTIAL TAMPERING DETECTED: CLIENT IP ADDRESS DOES NOT MATCH PACKET")
                    return False
                print("NEW USER ADDED: " + self.split_data[1].decode())

            save_hosts(self.split_data, config.hosts, global_hostslock, self.client_address[0])
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(bytes("INIT_REPLY\r" + config.USER_NAME + "\r\n" + str(config.PUBLIC_KEY), encoding="utf-8"), (self.client_address[0], config.PORT))
            
        
        elif self.split_data[0] == b"INIT_REPLY":
            print("CAPTURING REPLY FROM: " + str(self.client_address[0]))

            save_hosts(self.split_data, config.hosts, global_hostslock, self.client_address)
        
        elif self.split_data[0] == b"FIND_USER":
            if not verify_signature(b"\r\n".join(self.split_data[0:-1]), self.split_data[-1], self.split_data[2]):
                print("POTENTIAL TAMPERING")
                return False
            
            values = config.hosts[self.split_data[1]]
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(bytes("FIND_USER_REPLY\r\n" + self.split_data[3] + "\r\n" + values[0] + "\r\n" + values[1], encoding="utf-8"), (self.client_address[0], config.PORT))
        
        elif self.split_data[0] == b"FIND_USER_REPLY":
            if not self.split_data[1].decode() in config.hosts.keys():
                config.hosts[self.split_data[1].decode()] = [self.split_data[2], self.split_data[3]]
        
        elif self.split_data[0] == b"START_CONVO":
            if not verify_signature(b"\r\n".join(self.split_data[0:-1]), self.split_data[-1], self.split_data[2]):
                print("POTENTIAL TAMPERING: SIGNATURE DOES NOT MATCH")
                return False
            
            if not self.split_data[3] == self.client_address[0].encode():
                print("POTENTIAL TAMPERING DETECTED: CLIENT IP ADDRESS DOES NOT MATCH PACKET")
                return False
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.client_address[0], config.PORT))

            client_key = rsa.PublicKey.load_pkcs1(self.split_data[2])

            message = rsa.encrypt(b"ahoy!", client_key)
            message = base64.b64encode(message)
            sock.send(message)


            message = rsa.encrypt(CR.get_random_bytes(16), client_key)
            sock.send(message)
            sock.close()




class TCPServerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            self.data = self.request.recv(1024).strip()
            if self.data != b"":
                break
        
        decrypted = rsa.decrypt(base64.b64decode(self.data), config.PRIVATE_KEY)

        
        print("connection made> " + decrypted.decode())

        while True:
            aes_recv = self.request.recv(1024).strip()
            if aes_recv != b"":
                break
        
        print(aes_recv)

        aes_key = rsa.decrypt(aes_recv, config.PRIVATE_KEY)
        print(aes_key)
            

def open_tunnel(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind("127.0.0.1", port)

    return sock


def save_hosts(split_data, hosts_dictionary, hostslock, client_address):
    key = split_data[-1].decode()
    name = split_data[1].decode()
    if (not key in hosts_dictionary.keys()):
        hosts_dictionary[key] = [name, client_address]
        while True:
            if (not hostslock):
                hostslock = True
                with open("hosts.json", "w") as hostsfile:
                    json.dump(config.hosts,hostsfile)
                hostslock = False
                break
            else:
                time.sleep(0.2)
    else:
        print("Init recieved from computer already in hosts file")

def init_server(server_type):
    if server_type=="udp":
        with socketserver.UDPServer((config.HOST, config.PORT), UDPServerHandler) as server:
            server.serve_forever()

    elif server_type=="tcp":
        with socketserver.TCPServer((config.HOST, config.PORT), TCPServerHandler) as server:
            server.serve_forever()

def verify_signature(message, signature, public_key):
    imported_key = rsa.PublicKey.load_pkcs1(public_key)
    try:
        rsa.verify(message, signature, imported_key)
    except Exception as e:
        print(e)
        print("POTENTIAL VERIFICATION ERROR")
        return False
    
    return True


def main():
    udp_server_thread = threading.Thread(target=init_server, args=["udp"])
    tcp_server_thread = threading.Thread(target=init_server, args=["tcp"])
    
    udp_server_thread.start()
    tcp_server_thread.start()
