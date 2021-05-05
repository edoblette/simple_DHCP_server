import socket

serverPort = 67
clientPort = 68


print("DHCP client is starting...")
dest = ('localhost', serverPort)

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

ip = bytes([0xC0,0xA8,0x01,0x01]) #petit test d'envoi de bytes (adresse IP)
clientSocket.sendto(ip, dest)
print("Client test")


