from socket import *

serverPort = 67
clientPort = 68

class serverDHCP(object):

	network = '192.168.65.0'
	router = '192.168.65.1'

	def get_clientmsg(packet): #avec cette méthode on récupère le message discover d'un client
		OP = packet[0]
		HTYPE = packet[1]
		HLEN = packet[2]
		HOPS = packet[3]
		XID = packet[4:8]
		SECS = packet[8:10]
		FLAGS = packet[10:12]
		CIADDR = packet[12:16]
		YIADDR = packet[16:20]
		SIADDR = packet[20:24]
		GIADDR = packet[24:28]
		CHADDR = packet[28:28 + HLEN + 192]
		magic_cookie = packet[236:240]
		DHCPoptions = packet[240:]

		return OP, HTYPE, HLEN, HOPS, XID, SECS, FLAGS, CIADDR, YIADDR, SIADDR, GIADDR, CHADDR, magic_cookie, DHCPoptions

	def set_offer(xid, ciaddr, chaddr, magicookie, router):
		OP = bytes([0x02])
		HTYPE = bytes([0x01])
		HLEN = bytes([0x06])
		HOPS = bytes([0x00])
		XID = xid
		SECS = bytes([0x00, 0x00])
		FLAGS = bytes([0x00, 0x00])
		CIADDR = ciaddr
		YIADDR = inet_aton(serverDHCP.network)
		SIADDR = inet_aton(serverDHCP.router)
		GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		CHADDR = chaddr
		magic_cookie = magicookie
		DHCPoptions1 = bytes([53, 1, 2])
		DHCPoptions2 = bytes([1 , 4 , 0xFF, 0xFF, 0xFF, 0x00])
		DHCPoptions3 = bytes([3 , 4 , 0xC0, 0xA8, 0x01, 0x01])
		DHCPOptions4 = bytes([51 , 4 , 0x00, 0x01, 0x51, 0x80])
		DHCPOptions5 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01])

		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + magic_cookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 + DHCPOptions4 + DHCPOptions5
		return package



	def server(self):
		print("RUN")
		broadcast_address = '255.255.255.255'
		subnet_mask = '255.255.255.0'
		dest = ('<broadcast>', clientPort)
		lease_time = 300

		server = socket(AF_INET, SOCK_DGRAM)
		server.setsockopt(SOL_IP, SO_REUSEADDR, 1)
		server.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
		server.bind(('0.0.0.0', serverPort))

		while True:
			print("Waiting for DHCP discovery")
			packet, address = server.recvfrom(4096)
			xid, ciaddr, chaddr, magic_cookie = serverDHCP.get_clientmsg(packet)[4], serverDHCP.get_clientmsg(packet)[7], serverDHCP.get_clientmsg(packet)[11], serverDHCP.get_clientmsg(packet)[12]
			#print(packet)

			print("Received DHCP discovery!")
			data = serverDHCP.set_offer(xid, ciaddr, chaddr, magic_cookie, serverDHCP.router)
			print(data)
			server.sendto(data, dest)
			print("Waiting for Request...")


if __name__ == '__main__':
	dhcp_server = serverDHCP()
	dhcp_server.server()
    




