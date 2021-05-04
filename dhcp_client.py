import socket

serverPort = 67
clientPort = 68


print("DHCP client is starting...")
dest = ('localhost', serverPort)

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

data = bytes([0x00, 0x00, 0x00, 0x00]) #petit test d'envoi de bytes
clientSocket.sendto(data, dest)
print("Client test")
		


