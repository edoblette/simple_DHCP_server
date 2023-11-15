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
			self.info_msg("... Waiting for DHCP paquets ... ", False)

			packet, address = self.server.recvfrom(MAX_BYTES)
			packet_analyzed = self.packet_analyser(packet)
			dhcpoptions = packet_analyzed[13] 												#Récupère les options du packet reçu
			dhcpMessageType = dhcpoptions[2] 														 	#Type de message reçu
			dhcpRequestedIp = False
			for i in range(len(dhcpoptions)):
				if(dhcpoptions[i:i+2] == bytes([50, 4])):
					dhcpRequestedIp = self.ip_addr_format(dhcpoptions[i+2:i+6]) 						#on récupère l'adresse demandée

			htype, xid, ciaddr, chaddr, magic_cookie = packet_analyzed[1], packet_analyzed[4], packet_analyzed[7], packet_analyzed[11], packet_analyzed[12]
			dhcpClientMacAddress = self.mac_addr_format(chaddr)

			if(dhcpClientMacAddress not in self.addr_manager.get_banned_adresses()):					#Si le client n'est pas banni
				match dhcpMessageType:
					case 1:															#Si c'est un DHCP Discover
						self.info_msg("Received DHCP discovery! (" + dhcpClientMacAddress + ')', True)
						ip = self.addr_manager.get_ip(str(dhcpClientMacAddress), dhcpRequestedIp)
						if(ip != False):
							data = self.response(2, htype, xid, ciaddr, ip, chaddr, magic_cookie) #0x02 is the value of "offer"
							self.server.sendto(data, dest)
						else:
							self.info_msg(self.error_msg(0), True)

					case 3:	 																#Si c'est un DHCP Request
						self.info_msg("Receive DHCP request.(" + dhcpClientMacAddress + ')', True)
						ip = self.addr_manager.get_ip(str(dhcpClientMacAddress), dhcpRequestedIp)
						if(ip != False):
							data = self.response(5, htype, xid, ciaddr, ip, chaddr, magic_cookie) #0x02 is the value of "offer"
							self.addr_manager.update_ip(ip, str(dhcpClientMacAddress))
							self.server.sendto(data, dest)
							self.info_msg(self.addr_manager.get_ip_allocated(), True)
						else:
							self.info_msg(self.error_msg(0), True)
			else:
				self.info_msg(self.error_msg(2), True)
		pass	

	def stop(self):
		self.running = False					
		self.info_msg("--- DHCP server stoped ---", True)
		self.server.sendto(bytes(590), ('<broadcast>', serverPort))
		pass

	def gui(self):
		while self.running:
			request = input("\033[0;37;41m Server info: \033[0m ").lower()
			match request:
				case "help":
					print("[ stop ]	: stop the DHCP server ")
					print("[ usage ] : show ip assignment ")
					print("[ available ] : show ip still available ")
					print("[ free <mac adresse> ] : free/detach ip address from mac adresse ")
					print("[ remove <ip adresse> ] : remove the ip address from the addresses available by the server ")
					print("[ banned ] : show banned adresses ")
					print("[ ban <mac adresse> ] : ban the mac address ")
					print("[ unban <mac adresse> ] : unban the mac address ")
					print("[ quiet ] : hide the log informations (default)")
					print("[ verbose ] : show the log informations ")
					print("[ erase ] : erase log file ")
				
				case "stop":
					self.stop()
				
				case "usage":
					print(self.addr_manager.get_ip_allocated())
				
				case "available":
					print(self.addr_manager.get_ip_available())
				
				case _ if request.startswith('free '):
					mac_addr = request.split(' ', 2)
					if len(mac_addr) == 2:
						opVal, ip = self.addr_manager.detach_ip(mac_addr[1])
						if opVal:
							self.info_msg(f"[MANUAL] Detach: {mac_addr[1]} at {ip}", True)
							print(f"{mac_addr[1]} at {ip} detached")
						else:
							print(self.error_msg(1))
				
				case _ if request.startswith('remove '):
					ip_addr = request.split(' ', 2)
					if len(ip_addr) == 2:
						opVal = self.addr_manager.remove_ip(ip_addr[1])
						if opVal:
							self.info_msg(f"[MANUAL] Remove: {ip_addr[1]}", True)
							print(f"{ip_addr[1]} removed")
						else:
							print(self.error_msg(1))
				
				case "banned":
					banned_list = self.addr_manager.get_banned_adresses()
					print("Banned addresses : " + str(len(banned_list)))
					for ban_id in banned_list:
						print('\t' + ban_id)
				
				case _ if request.startswith('ban '):
					mac_addr = request.split(' ', 2)
					if len(mac_addr) == 2:
						opVal = self.addr_manager.ban_addr(mac_addr[1])
						if opVal:
							self.info_msg(f"[MANUAL] Ban: {mac_addr[1]}", True)
							print(f"{mac_addr[1]} banned")
						else:
							print(self.error_msg(1))
				
				case _ if request.startswith('unban '):
					mac_addr = request.split(' ', 2)
					if len(mac_addr) == 2:
						opVal = self.addr_manager.unban_addr(mac_addr[1])
						if opVal:
							self.info_msg(f"[MANUAL] Unban: {mac_addr[1]}", True)
							print(f"{mac_addr[1]} unbanned")
						else:
							print(self.error_msg(1))
				
				case "quiet":
					self.server_option = 0
				
				case "verbose":
					self.server_option = 1
				
				case "erase":
					self.clearLog()
					self.info_msg("[MANUAL] Erase log", True)
				
				case _:
					print(f"'{request}' is not a valid command. See 'help'.")

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

	def response(self, dhcp_code, htype, xid, ciaddr, yiaddr, chaddr, magiccookie):
		OP = bytes([0x02]) #0x02 represents response
		HTYPE = bytes([htype]) #Hardware type
		HLEN = bytes([0x06]) #Hardware Address Length - Ethernet address length which is 6 bytes
		HOPS = bytes([0x00]) # zero because just create packet
		XID = xid
		SECS = bytes([0x00, 0x00])
		FLAGS = bytes([0x00, 0x00]) # unicast - 1000 0000 for a broadcast; and 0000 0000 for a unicast.
		CIADDR = ciaddr # by default 0.0.0.0 till DORA succed
		YIADDR = inet_aton(yiaddr) 	#Your (client) IP Address
		SIADDR = inet_aton(self.server_ip) #Server IP
		GIADDR = bytes([0x00, 0x00, 0x00, 0x00]) #Gateway IP 
		CHADDR = chaddr #Client Hardware
		magic_cookie = magiccookie
		DHCPoptions1 = bytes([53, 1, dhcp_code])	#DHCP Msg Type : option code - lenght - 0x02 is the value of "offer"/ 0x05 is the value of "ACK"
		DHCPoptions2 = bytes([1 , 4]) + inet_aton(self.subnet_mask)				# subnet_mask 255.255.255.0
		DHCPoptions3 = bytes([3 , 4 ]) + inet_aton(self.gateway) 				# gateway/router
		DHCPoptions4 = bytes([51 , 4]) + ((self.lease_time).to_bytes(4, byteorder='big')) 	#86400s(1, day) IP address lease time
		DHCPoptions5 = bytes([54 , 4]) + inet_aton(self.server_ip) 				# DHCP server
		DHCPOptions6 = bytes([6, 4 * len(self.dns)]) 							# DNS servers
		for i in self.dns:
			DHCPOptions6 += i
		ENDMARK = bytes([0xff])
		
		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + magic_cookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 +  DHCPoptions4 + DHCPoptions5 + DHCPOptions6 + ENDMARK
		return package
	
	def info_msg(self, message, loggable):
		if(self.server_option == 1):											#si l'option est a 1 on est en mode verbose
			print("{0}".format(message))

		if (loggable == True):
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
				3:'Other'														
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
    
