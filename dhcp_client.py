import socket, uuid
from ipaddress import ip_address
import argparse

MAX_BYTES = 1024
serverPort = 67
clientPort = 68
raw_mac_addr = uuid.getnode()

class DHCP_client(object):
	def client(self):
		print("DHCP client is starting...\n")
		dest = ('<broadcast>', serverPort)
		clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		clientSocket.bind(('0.0.0.0', clientPort))

		print("Send DHCP discovery.")
		data = DHCP_client.discover_get();
		clientSocket.sendto(data, dest)

		packet, address = clientSocket.recvfrom(MAX_BYTES)
		print("Receive DHCP offer.")
		xid, yiaddr, siaddr, chaddr, magic_cookie = DHCP_client.packet_analyser(packet)[4], DHCP_client.packet_analyser(packet)[8], DHCP_client.packet_analyser(packet)[9], DHCP_client.packet_analyser(packet)[11], DHCP_client.packet_analyser(packet)[12]

		print("Send DHCP request.")
		data = DHCP_client.request_get(xid, yiaddr, siaddr, chaddr, magic_cookie);
		clientSocket.sendto(data, dest)

		data, address = clientSocket.recvfrom(MAX_BYTES)
		print("Receive DHCP ack.\n")
		DHCP_client.info_pack(data)
		

	def ip_addr_format(address):
		address = '{}.{}.{}.{}'.format(*bytearray(address))

		return address

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
		CHADDR = packet[28:28 + 16 +  192]
		magic_cookie = packet[236:240]
		DHCPoptions = packet[240:]

		return OP, HTYPE, HLEN, HOPS, XID, SECS, FLAGS, CIADDR, YIADDR, SIADDR, GIADDR, CHADDR, magic_cookie, DHCPoptions

	def discover_get():
		OP = bytes([0x01])
		HTYPE = bytes([0x01])
		HLEN = bytes([0x06])
		HOPS = bytes([0x00])
		XID = bytes([0x39, 0x03, 0xF3, 0x26]) #a randomiser
		SECS = bytes([0x00, 0x00])
		FLAGS = bytes([0x00, 0x00])
		CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		GIADDR = bytes([0x00, 0x00, 0x00, 0x00]) 
		CHADDR1 = bytes.fromhex(hex(raw_mac_addr)[2:10]) #remplacer par argv  (4 octets)
		CHADDR2 = bytes.fromhex(hex(raw_mac_addr)[10:14]) + bytes([0x00, 0x00]) #(2 octets + 2 octet de bourrage)
		CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00]) 
		CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00]) 
		CHADDR5 = bytes(192)
		Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
		DHCPOptions1 = bytes([53 , 1 , 1])
		DHCPOptions2 = bytes([50 , 4 ]) + socket.inet_aton('0.0.0.100') # a virer
		ENDMARK = bytes([0xff])

		print("adresse mac est :")
		chaddr = hex(raw_mac_addr)[2:]
		mac_addr = ':'.join(chaddr[i:i+2] for i in range(0,12,2))
		print(mac_addr) 

		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + ENDMARK

		return package

	def request_get(xid, yiaddr, siaddr, chaddr, magic_cookie):
		OP = bytes([0x01])
		HTYPE = bytes([0x01])
		HLEN = bytes([0x06])
		HOPS = bytes([0x00])
		XID = xid
		SECS = bytes([0x00, 0x00])
		FLAGS = bytes([0x00, 0x00])
		CIADDR = yiaddr
		YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		SIADDR = siaddr
		GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		CHADDR = chaddr
		Magiccookie = magic_cookie
		DHCPOptions1 = bytes([53 , 1 , 3])
		DHCPOptions2 = bytes([50 , 4 ]) + yiaddr
		DHCPOptions3 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01])
		ENDMARK = bytes([0xff])

		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR  + Magiccookie + DHCPOptions1 + DHCPOptions2 +  DHCPOptions3 + ENDMARK

		return package

	def info_pack(packet): #get final information from DHCPACK
		print("XID : " + str((packet[4:8]).hex())) #XID
		print("IPV4 : " + DHCP_client.ip_addr_format(packet[16:20])) #YIADDR
		print("MAC ADDR : " + DHCP_client.mac_addr_format(packet[28:236])) #CHADRR
		print("ROUTER : " + DHCP_client.ip_addr_format(packet[20:24])) #SIADDR
		print("IP address lease time : " + str(int.from_bytes(packet[257:261], "big"))  + "secs") #BAIL

		return

	

if __name__ == '__main__':
	# Initialize parser
	parser = argparse.ArgumentParser()
	# Adding optional argument
	parser.add_argument("-o", "--Output", help = "Show Output")
	# Read arguments from command line
	args = parser.parse_args()
	if args.Output:
	   raw_mac_addr = int(str(args.Output).replace(":", ""), base=16)

	print(raw_mac_addr)	
	dhcp_client = DHCP_client()
	dhcp_client.client()