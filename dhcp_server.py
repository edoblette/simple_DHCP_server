from socket import *
import re

MAX_BYTES = 1024
serverPort = 67
clientPort = 68
lease_time = 8100

class serverDHCP(object):

	ip_list = '192.168.65.150'
	router = '192.168.65.1'

	def server(self):
		print("RUN")
		broadcast_address = '255.255.255.255'
		subnet_mask = '255.255.255.0'
		dest = ('<broadcast>', clientPort)

		server = socket(AF_INET, SOCK_DGRAM)
		server.setsockopt(SOL_IP, SO_REUSEADDR, 1)
		server.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
		server.bind(('0.0.0.0', serverPort))

		while True:
			print("Waiting for DHCP discovery")
			packet, address = server.recvfrom(MAX_BYTES)
			xid, ciaddr, chaddr, magic_cookie = serverDHCP.packet_analyser(packet)[4], serverDHCP.packet_analyser(packet)[7], serverDHCP.packet_analyser(packet)[11], serverDHCP.packet_analyser(packet)[12]

			print("Received DHCP discovery! (" + serverDHCP.mac_addr_format(chaddr) + ')')
			data = serverDHCP.set_offer(xid, ciaddr, chaddr, magic_cookie, serverDHCP.router)
			server.sendto(data, dest)

			while True:
					try:
						print("Wait DHCP request.")
						data, address = server.recvfrom(MAX_BYTES)
						print("Receive DHCP request.")

						print("Send DHCP pack.\n")
						data = serverDHCP.pack_get(xid, ciaddr, chaddr, magic_cookie, serverDHCP.router)
						server.sendto(data, dest)
						break
					except:
						raise

	def mac_addr_format(adress):
		adress = adress.hex()[:16]
		adress = ':'.join(adress[i:i+2] for i in range(0,12,2))

		return adress

	def packet_analyser(packet): #avec cette méthode on récupère le message discover d'un client
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
		CHADDR = packet[28:28 + 16 + 192]
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
		YIADDR = inet_aton(serverDHCP.ip_list) #adresse a donner
		SIADDR = inet_aton(serverDHCP.router)
		GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		CHADDR = chaddr
		Magiccookie = magicookie
		DHCPoptions1 = bytes([53, 1, 2])  # DHCP Offer
		DHCPoptions2 = bytes([1 , 4 , 0xFF, 0xFF, 0xFF, 0x00]) # subnet_mask 255.255.255.0
		DHCPoptions3 = bytes([3 , 4 ]) + inet_aton(router) # router
		DHCPOptions4 = bytes([51 , 4]) + ((lease_time).to_bytes(4, byteorder='big')) #86400s(1, day) IP address lease time
		DHCPOptions5 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01]) # DHCP server
		ENDMARK = bytes([0xff])

		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + Magiccookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 + DHCPOptions4 + DHCPOptions5 + ENDMARK
		return package

	def pack_get(xid, ciaddr, chaddr, magicookie, router):
		OP = bytes([0x02])
		HTYPE = bytes([0x01])
		HLEN = bytes([0x06])
		HOPS = bytes([0x00])
		XID = xid
		SECS = bytes([0x00, 0x00])
		FLAGS = bytes([0x00, 0x00])
		CIADDR = ciaddr 
		YIADDR = inet_aton(serverDHCP.ip_list) #adresse a donner
		SIADDR = inet_aton(serverDHCP.router)
		GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		CHADDR = chaddr
		Magiccookie = magicookie
		DHCPoptions1 = bytes([53 , 1 , 5]) #DHCP ACK(value = 5)
		DHCPoptions2 = bytes([1 , 4 , 0xFF, 0xFF, 0xFF, 0x00]) #255.255.255.0 subnet mask
		DHCPoptions3 = bytes([3 , 4 ]) + inet_aton(router)
		DHCPoptions4 = bytes([51 , 4]) + ((lease_time).to_bytes(4, byteorder='big')) #86400s(1, day) IP address lease time
		DHCPoptions5 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01]) #DHCP server
		ENDMARK = bytes([0xff])

		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + Magiccookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 + DHCPoptions4 + DHCPoptions5 + ENDMARK
		return package



if __name__ == '__main__':
	dhcp_server = serverDHCP()
	dhcp_server.server()
    




