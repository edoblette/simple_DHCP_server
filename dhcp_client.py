import socket

serverPort = 67
clientPort = 68

#client inutile


print("DHCP client is starting...")
dest = ('<broadcast>', serverPort)

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
#clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

ip = bytes([0xC0,0xA8,0x01,0x01]) #petit test d'envoi de bytes (adresse IP)
clientSocket.sendto(ip, dest)
print("Message sent")
print("Client test")


