from socket import *

serverPort = 67
clientPort = 68

addr = ('localhost', serverPort) #test en local

server = socket(AF_INET, SOCK_DGRAM)
server.bind(addr)

while True:
    print("Waiting for DHCP discovery")
    data, address = server.recvfrom(2048)
    print(bytes(data))
    print("Received DHCP discovery!")






