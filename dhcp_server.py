from socket import *
import ipaddress

class serveurDHCP(object):

    #Serveur DHCP qui fonctionne sur le réseau local 
    network = '192.168.1.0'
    server_address = '192.168.1.21'
    broadcast_address = '192.168.1.255'
    subnet_mask = '255.255.255.0'
    router = '192.168.1.1'

    poll = [str(ip) for ip in ipaddress.IPv4Network(network+'/24')] #plage d'adresses à attribuer

    usedIps = [network, router, server_address, broadcast_address]
    usedMacAddresses = []

    lease_time = bytes([51, 4, 0x00, 0x01, 0x51, 0x80]) #default lease time

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
        CHADDR = packet[28:28 + 16 + 192]
        magic_cookie = packet[236:240]
    
        DHCPoptions = packet[240:]

        return OP, HTYPE, HLEN, HOPS, XID, SECS, FLAGS, CIADDR, YIADDR, SIADDR, GIADDR, CHADDR, magic_cookie, DHCPoptions

    def set_offer(xid, chaddr, magicookie, lease_time, server_address, gift_address):
        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])

        XID = xid

        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])

        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = inet_aton(gift_address)
        SIADDR = inet_aton(server_address)
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR = chaddr

        magic_cookie = magicookie

        DHCPoptions1 = bytes([53, 1, 2])
        DHCPoptions2 = bytes([1 , 4 , 0xFF, 0xFF, 0xFF, 0x00])
        DHCPoptions3 = bytes([3 , 4 , 0xC0, 0xA8, 0x01, 0x01])
        DHCPOptions4 = lease_time
        DHCPOptions5 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x15]) #adresse du serveur
        DHCPOptions6 = bytes([6, 4 , 0xC0, 0xA8, 0x01, 0x01])  #DNS servers
        ENDMARK = bytes([0xff])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + magic_cookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 + DHCPOptions4 + DHCPOptions5 + DHCPOptions6 + ENDMARK
        return package

    def set_pack(xid, chaddr, magicookie, lease_time, server_address, ack, requestedAddress):

        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])

        XID = xid

        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])

        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = inet_aton(requestedAddress)
        SIADDR = inet_aton(server_address)
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR = chaddr

        magic_cookie = magicookie

        DHCPoptions1 = bytes([53, 1, ack])
        DHCPoptions2 = bytes([1 , 4 , 0xFF, 0xFF, 0xFF, 0x00])
        DHCPoptions3 = bytes([3 , 4 , 0xC0, 0xA8, 0x01, 0x01])
        DHCPOptions4 = lease_time
        DHCPOptions5 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x15])
        DHCPOptions6 = bytes([6, 4 , 0xC0, 0xA8, 0x01, 0x01]) 
        ENDMARK = bytes([0xff])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + magic_cookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 + DHCPOptions4 + DHCPOptions5 + DHCPOptions6 + ENDMARK
        return package



    serverPort = 67
    clientPort = 68

    addr = (server_address, serverPort) #test sur le réseau local

    server = socket(AF_INET, SOCK_DGRAM)
    server.setsockopt(SOL_IP, SO_REUSEADDR, 1)
    server.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    server.bind(addr)

    while True:

        print("Server is running...")

        dest = ('<broadcast>', 68) #Destination des messages du serveur

        packet, address = server.recvfrom(4096) #Message
        dhcpoptions = get_clientmsg(packet)[13] #Récupère les options du packet reçu
        chaddr = get_clientmsg(packet)[11] #Champ CHADDR de la trame reçue
        dhcpMessageType = dhcpoptions[2] #Type de message reçu

        xid, ciaddr, chaddr, magic_cookie = get_clientmsg(packet)[4], get_clientmsg(packet)[7], get_clientmsg(packet)[11], get_clientmsg(packet)[12]

        for b in range(0, len(dhcpoptions)):
            if(dhcpoptions[b:b+2] == bytes([51, 4])):
                print("WE IN BITCH")
                lease_time = dhcpoptions[b:b+6]

        print("DHCP Message Type : ")
        print(dhcpMessageType)

        print("\nClient MAC Address : ")
        clientMacAddress = chaddr[:6].hex(":")
        print(clientMacAddress)

        if(dhcpMessageType == 1): #Si c'est un DHCP Discover
            print("Received DHCP Discovery!")
            for addr in reversed(poll):
                if addr not in usedIps:
                    gift_address = addr
            print("Gifted address :")
            print(gift_address)

            if clientMacAddress in usedMacAddresses:
                usedMacAddresses.remove(clientMacAddress)
            dataOffer = set_offer(xid, chaddr, magic_cookie, lease_time, server_address, gift_address)
            server.sendto(dataOffer, dest) #On envoie offer
        
        if(dhcpMessageType == 3): #Si c'est un DHCP Request
            print("Received DHCP Request!")
            for b in range(0, len(dhcpoptions)):
                if(dhcpoptions[b:b+3] == bytes([50, 4, 0xc0])): #on check l'option 50
                    requested_Address = inet_ntoa(dhcpoptions[b+2:b+6]) #on récupère l'adresse demandée
                    print("What the fuck is going on :")
                    print(dhcpoptions[b:b+6].hex())

            if (requested_Address in usedIps) and (clientMacAddress not in usedMacAddresses):
                dataPack = set_pack(xid, chaddr, magic_cookie, lease_time, server_address, 6, requested_Address) #nack
            else:
                dataPack = set_pack(xid, chaddr, magic_cookie, lease_time, server_address, 5, requested_Address) #ack

            server.sendto(dataPack, dest) #On envoie Pack

            if requested_Address not in usedIps:
                usedIps.append(requested_Address) #On stocke l'adresse attribuée dans une liste
            
            if clientMacAddress not in usedMacAddresses:
                usedMacAddresses.append(clientMacAddress) #On stocke l'adresse MAC dans une liste

        print(usedIps)
        print(usedMacAddresses)
        
if __name__ == "main":
    serveurDHCP()
    




