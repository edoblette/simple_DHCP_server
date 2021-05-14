from socket import *
from ipaddress import ip_address
import re, argparse, threading
from datetime import datetime

MAX_BYTES = 4096
serverPort = 67
clientPort = 68

class serverDHCP(object):

	def server(self, _server_ip, _gateway, _subnet_mask, _range, _time, _dns ):
		self.server 
		self.server_ip = _server_ip
		self.gateway = _gateway
		self.subnet_mask = _subnet_mask
		self.addr_manager = IpVector(_server_ip, _gateway, _subnet_mask, _range )
		self.broadcast_address = self.addr_manager.get_broadcast_adress()
		self.lease_time = _time
		self.dns = [inet_aton(_dns[i]) for i in range(len(_dns))]
		self.running = True
		self.server_option = 0

	def start(self):
		self.server = socket(AF_INET, SOCK_DGRAM)
		self.server.setsockopt(SOL_IP, SO_REUSEADDR, 1)
		self.server.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
		self.server.bind((self.server_ip, serverPort))

		while self.running:
			dest = ('<broadcast>', clientPort)
			self.info_msg("... Waiting for DHCP paquets ... ")

			packet, address = self.server.recvfrom(MAX_BYTES)
			dhcpoptions = self.packet_analyser(packet)[13] 												#Récupère les options du packet reçu
			dhcpMessageType = dhcpoptions[2] 														 	#Type de message reçu
			dhcpRequestedIp = False
			for i in range(len(dhcpoptions)):
				if(dhcpoptions[i:i+2] == bytes([50, 4])):
					dhcpRequestedIp = self.ip_addr_format(dhcpoptions[i+2:i+6]) 						#on récupère l'adresse demandée

			xid, ciaddr, chaddr, magic_cookie = self.packet_analyser(packet)[4], self.packet_analyser(packet)[7], self.packet_analyser(packet)[11], self.packet_analyser(packet)[12]
			dhcpClientMacAddress = self.mac_addr_format(chaddr)

			if(dhcpClientMacAddress not in self.addr_manager.get_banned_adresses()):					#Si le client n'est pas banni
				if(dhcpMessageType == 1): 																#Si c'est un DHCP Discover
					self.info_msg("Received DHCP discovery! (" + dhcpClientMacAddress + ')')
					ip = self.addr_manager.get_ip(str(dhcpClientMacAddress), dhcpRequestedIp)
					if(ip != False):
						data = self.set_offer( xid, ciaddr, chaddr, magic_cookie, ip)
						self.server.sendto(data, dest)
					else:
						self.info_msg(self.error_msg(0))

				if(dhcpMessageType == 3): 																#Si c'est un DHCP Request
					self.info_msg("Receive DHCP request.(" + dhcpClientMacAddress + ')')
					ip = self.addr_manager.get_ip(str(dhcpClientMacAddress), dhcpRequestedIp)
					if(ip != False):
						data = self.pack_get( xid, ciaddr, chaddr, magic_cookie, ip)
						self.addr_manager.update_ip(ip, str(dhcpClientMacAddress))
						self.server.sendto(data, dest)
						self.info_msg(self.addr_manager.get_ip_allocated())
					else:
						self.info_msg(self.error_msg(0))
			else:
				self.info_msg(self.error_msg(2))
		pass	

	def stop(self):
		self.running = False					
		self.info_msg("--- DHCP server stoped ---")
		self.server.sendto(bytes(590), ('<broadcast>', serverPort))
		pass

	def gui(self):
		while self.running:
			request = input("Server info: ").lower()
			if(request == "help"):
				print("[ stop ]	: stop the DHCP server ")
				print("[ usage ] : show ip assignment ")
				print("[ available ] : show ip still available ")
				print("[ free <mac adresse> ] : free/detach ip address from mac adresse ")
				print("[ remove <ip adresse> ] : eemove the ip address from the addresses available by the server ")
				print("[ banned ] : show banned adresses ")
				print("[ ban <mac adresse> ] : ban the mac address ")
				print("[ unban <mac adresse> ] : unban the mac address ")
				print("[ quiet ] : hide the log informations (default)")
				print("[ verbose ] : show the log informations ")
				print("[ erase ] : erase log file ")

			elif(request == "stop"):
				self.stop()

			elif(request == "usage"):
				print(self.addr_manager.get_ip_allocated())

			elif(request == "available"):
				print(self.addr_manager.get_ip_available())

			elif(request.startswith('free') == True):
				mac_addr = request.split(' ', 2)
				if (len(mac_addr) == 2):
					opVal, ip = self.addr_manager.detach_ip(mac_addr[1])
					if(opVal == True):
						self.info_msg("[MANUAL] Detach : " + mac_addr[1] + " at " + ip )
						print(mac_addr[1] + " at " + ip + " detached")
					else:
						print(self.error_msg(1))

			elif(request.startswith('remove') == True):
				ip_addr = request.split(' ', 2)
				if (len(ip_addr) == 2):
					opVal = self.addr_manager.remove_ip(ip_addr[1])
					if(opVal == True):
						self.info_msg("[MANUAL] Remove : " + ip_addr[1])
						print(ip_addr[1] + " removed")
					else:
						print(self.error_msg(1))

			elif(request == "banned"):
				banned_list = self.addr_manager.get_banned_adresses()
				print("Banned addresses : " + str(len(banned_list)))
				print(*banned_list, sep = "\n")
							
			elif(request.startswith('ban') == True):
				mac_addr = request.split(' ', 2)
				if (len(mac_addr) == 2):
					opVal = self.addr_manager.ban_addr(mac_addr[1])
					if(opVal == True):
						self.info_msg("[MANUAL] Ban : " + mac_addr[1]  )
						print(mac_addr[1] + " banned")
					else:
						print(self.error_msg(1))

			elif(request.startswith('unban') == True):
				mac_addr = request.split(' ', 2)
				if (len(mac_addr) == 2):
					opVal = self.addr_manager.unban_addr(mac_addr[1])
					if(opVal == True):
						self.info_msg("[MANUAL] Unban : " + mac_addr[1]  )
						print(mac_addr[1] + " unbanned")
					else:
						print(self.error_msg(1))

			elif(request == "quiet"):
				self.server_option = 0

			elif(request == "verbose"):
				self.server_option = 1

			elif(request == "erase"):
				self.clearLog()
			else:
				print("'" + request + "'" + " is not a valid command. See 'help'.")
		pass

	#### Server Methods
	def ip_addr_format(self, address):
		return ('{}.{}.{}.{}'.format(*bytearray(address)))

	def mac_addr_format(self, address):
		address = address.hex()[:16]
		return (':'.join(address[i:i+2] for i in range(0,12,2)))

	def packet_analyser(self, packet): 											#avec cette méthode on récupère le message discover d'un client
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

	def set_offer(self, xid, ciaddr, chaddr, magicookie, ip):
		OP = bytes([0x02])
		HTYPE = bytes([0x01])
		HLEN = bytes([0x06])
		HOPS = bytes([0x00])
		XID = xid
		SECS = bytes([0x00, 0x00])
		FLAGS = bytes([0x00, 0x00])
		CIADDR = ciaddr
		YIADDR = inet_aton(ip) 													#adresse a donner
		SIADDR = inet_aton(self.server_ip)
		GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		CHADDR = chaddr
		magic_cookie = magicookie
		DHCPoptions1 = bytes([53, 1, 2])
		DHCPoptions2 = bytes([1 , 4]) + inet_aton(self.subnet_mask)				# subnet_mask 255.255.255.0
		DHCPoptions3 = bytes([3 , 4 ]) + inet_aton(self.gateway) 				# gateway/router
		DHCPOptions4 = bytes([51 , 4]) + ((self.lease_time).to_bytes(4, byteorder='big')) 	#86400s(1, day) IP address lease time
		DHCPOptions5 = bytes([54 , 4]) + inet_aton(self.server_ip) 				# DHCP server
		DHCPOptions6 = bytes([6, 4 * len(self.dns)]) 							#DNS servers
		for i in self.dns:
			DHCPOptions6 += i
		ENDMARK = bytes([0xff])

		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + magic_cookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 + DHCPOptions4 + DHCPOptions5 + DHCPOptions6 + ENDMARK
		return package

	def pack_get(self, xid, ciaddr, chaddr, magicookie, ip):
		OP = bytes([0x02])
		HTYPE = bytes([0x01])
		HLEN = bytes([0x06])
		HOPS = bytes([0x00])
		XID = xid
		SECS = bytes([0x00, 0x00])
		FLAGS = bytes([0x00, 0x00])
		CIADDR = ciaddr 
		YIADDR = inet_aton(ip) 													#adresse a donner
		SIADDR = inet_aton(self.server_ip)
		GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		CHADDR = chaddr
		Magiccookie = magicookie
		DHCPoptions1 = bytes([53 , 1 , 5]) 										#DHCP ACK(value = 5)
		DHCPoptions2 = bytes([1 , 4]) + inet_aton(self.subnet_mask)				# subnet_mask 255.255.255.0
		DHCPoptions3 = bytes([3 , 4 ]) + inet_aton(self.gateway) 				# gateway/router
		DHCPoptions4 = bytes([51 , 4]) + ((self.lease_time).to_bytes(4, byteorder='big')) 	#86400s(1, day) IP address lease time
		DHCPoptions5 = bytes([54 , 4]) + inet_aton(self.server_ip) 				# DHCP server
		DHCPOptions6 = bytes([6, 4 * len(self.dns)]) 							# DNS servers
		for i in self.dns:
			DHCPOptions6 += i
		ENDMARK = bytes([0xff])

		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + Magiccookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 + DHCPoptions4 + DHCPoptions5 + DHCPOptions6 + ENDMARK
		return package

	def info_msg(self, message):
		if(self.server_option == 1):											#si l'option est a 1 on est en mode verbose
			print("{0}".format(message))
 
		now = datetime.now()
		date_time = now.strftime("%m/%d/%Y %H:%M:%S")
		logFile.write("%s | %s\n" % (date_time, message.replace('\n', "\n\t\t")))
		logFile.flush()
		pass

	def error_msg(self, type_error):
		error = {
				0:'ERROR (No more IPs available)',
				1:'ERROR (Address don\'t exist )',
				2:'ERROR (Address banned )',
				3:'Monday'														#Monday is always a problem :)
		}
		return error.get(type_error, "Unexpected error")

	def clearLog(self):															#clear le log 
	    logFile.seek(0)
	    logFile.truncate()

class IpVector(object):
	def __init__(self, _server_ip, _gateway, _subnet_mask, _range):
		addr = [int(x) for x in _server_ip.split(".")]
		mask = [int(x) for x in _subnet_mask.split(".")]
		cidr = sum((bin(x).count('1') for x in mask))
		netw = [addr[i] & mask[i] for i in range(4)]
		bcas = [(addr[i] & mask[i]) | (255^mask[i]) for i in range(4)]
		print("Network: {0}".format('.'.join(map(str, netw))))
		print("DHCP server: {0}".format(_server_ip))
		print("Gateway/Router: {0}".format(_gateway))
		print("Broadcast: {0}".format('.'.join(map(str, bcas))))
		print("Mask: {0}".format('.'.join(map(str, mask))))
		print("Cidr: {0}".format(cidr))
		#convert to str format
		netw = '.'.join(map(str, netw))
		bcas = '.'.join(map(str, bcas))
		start_addr = int(ip_address(netw).packed.hex(), 16) + 1
		end_addr = int(ip_address(bcas).packed.hex(), 16) if (int(ip_address(netw).packed.hex(), 16) + 1 +_range) > int(ip_address(bcas).packed.hex(), 16) else int(ip_address(netw).packed.hex(), 16) + 1 + _range #ternary operation for range limit 
		self.list = {}
		self.banned_list = []
		self.broadcast = bcas
		self.allocated = 2							#2 on compte le routeur et le serveur

		for ip in range(start_addr, end_addr):
			self.add_ip(ip_address(ip).exploded, 'null') 

		self.update_ip(_gateway, "gateway")			#on ajoute le gateway/router
		self.update_ip(_server_ip, "DHCP server")	#on ajoute le server DHCP

    #method SET
	def add_ip(self, ip, mac_address):				#fait le lien clee/valeur entre l'ip et l'adresse mac
		self.list[ip] = mac_address
		self.allocated += 1							#incremente le compteur d'adresse disponible
		return

	def update_ip(self, ip, mac_address):
		if mac_address not in self.list.values():
			self.allocated -= 1						#decremente le compteur d'adresse disponible

		self.list.update({ip: mac_address})			#update l'adresse mac liee a l'adresse ip
		return

	def remove_ip(self, ip):
		for key, value in self.list.items() :		#on verifie que l'ip existe
			if(key == ip):							#si oui on supprime l'adresse ip
				self.list.pop(ip)
				self.allocated -= 1					#decremente le compteur d'adresse disponible
				return True
		return False

	def detach_ip(self, mac_address):
		for key, value in self.list.items() :		#on verifie que le client existe
			if(value == mac_address):				#si oui on remplace le client par 'null'
				print("addr " + mac_address)
				self.add_ip(key, 'null')
				return True, key
		return False, 0

	def ban_addr(self, mac_address):
		if mac_address not in self.banned_list:		#on verifie que le client existe
			self.banned_list.append(mac_address)	#on l'ajoute a la liste des adresse bannite
			return True
		return False

	def unban_addr(self, mac_address):
		if mac_address in self.banned_list:			#on verifie que le client existe
			self.banned_list.remove(mac_address)	#on l'ajoute a la liste des adresse bannite
			return True
		return False

	def get_banned_adresses(self):					#renvoie la liste des adresses mac banned
		return self.banned_list

	def get_broadcast_adress(self):					#renvoie l'adresse broadcast
		return self.broadcast

	def get_ip(self, mac_address, ip):
		for key, value in self.list.items() :		#on verifie que le client n'as pas deja une ip
			if(value == mac_address):				#si oui on retourne l'ip qui lui a ete precedement attribue 
				return key						

		if(ip != False):							#si on demande une adresse specifique alors on regarde si elle est deja attribue 
			if(self.list.get(ip) == "null"):		#si libre on renvoie l'adresse specifiee
				return ip 						

		return self.get_free_ip()					#sinon on appele la fonction d'allocation d'ip

	def get_free_ip(self):						
		for key, value in self.list.items() :		#on cherche une ip disponible
			if(value == "null"):					#on retourne l'adresse libre trouvee
				return key
		return False								#il n'y a plus d'adresse dispo on renvoie False

	def get_ip_allocated(self):
		package = "IP ADDRESSES  |  MAC ADDRESSES \n\t----------------------------- \n"
		for key, value in sorted(self.list.items(), key=lambda x: x[0]) :
			if(value != "null"):
				package += ("\t(" + key + ") at " + value + '\n')
		return package

	def get_ip_available(self):
		package = "IP availables : " + str(self.allocated) + '\n'
		for key, value in self.list.items() :
			if(value == "null"):
				package += ("\t(" + key + ") \n")
		return package


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("server", type=str, help="your ip")
	parser.add_argument("gateway", type=str, help="your gateway/router ip")
	parser.add_argument("submask", type=str, help="network submask")
	parser.add_argument("range", type=int, help="IPs range")
	parser.add_argument("time", type=int, help="lease time")
	parser.add_argument("dns", type=str, nargs='+',  help="local dns")
	args = parser.parse_args()
	
	logFile = open("serverlog.txt", "a")

	dhcp_server = serverDHCP()
	dhcp_server.server(args.server, args.gateway, args.submask, args.range, args.time, args.dns)

	# creating threads
	server_thread = threading.Thread(target=dhcp_server.start, name='server')
	server_gui = threading.Thread(target=dhcp_server.gui, name='gui')
  
	# starting threads
	server_thread.daemon = True
	server_gui.daemon = True
	server_thread.start()
	server_gui.start()

	# wait until all threads finish
	server_thread.join()
	server_gui.join()
    
