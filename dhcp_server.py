from socket import *

serverPort = 67
clientPort = 68

addr = ('', serverPort)

server = socket(AF_INET, SOCK_DGRAM)
server.bind(addr)

print('Im ready bro')

while True:
    print("Waiting for DHCP discovery")
    data, address = server.recvfrom(2048)
    print("Received DHCP discovery!")
    print(data.decode('utf-8'), address.decode('utf-8'))


def test()




