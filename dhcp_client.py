import socket,sys

serverPort = 67
clientPort = 68

#connect to server
print("DHCP client is starting...\n")
dest = ('<broadcast>', serverPort)
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
clientSocket.bind(('0.0.0.0', clientPort))
while True:
	    # Send data
		message = input('lowercase sentence:').encode('utf-8')
		print("sending %s" % format(message))
		data = message
		clientSocket.sendto(data, dest)


		data = clientSocket.recv(4096)
		if data:
			print(' Receive \t {} \t '.format(data ))				

		else:
			print('NO MSG:', server_address)
			print('close:', server_address)
			clientSocket.close()
			break
