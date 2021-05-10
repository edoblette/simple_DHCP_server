from socket import *

class serveurDHCP(object):

    #Serveur DHCP qui fonctionne sur le réseau local 
    network = '192.168.1.0'
    server_address = '192.168.1.21'
    broadcast_address = '255.255.255.255'
    subnet_mask = '255.255.255.0'
    router = '192.168.1.1'
    lease_time = 300

    poll = ['192.168.1.100', '192.168.1.101', '192.168.1.102', '192.168.1.103', '192.168.1.104', '192.168.1.105', '192.168.1.106']

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

    def set_offer(xid, chaddr, magicookie, server_address, poll):
        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])

        XID = xid

        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])

        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        #YIADDR = inet_aton('192.168.1.201')
        YIADDR = inet_aton(poll[0])
        print("Valeur de YIADDR : ")
        print(YIADDR)
        SIADDR = inet_aton(server_address)
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR = chaddr

        magic_cookie = magicookie

        DHCPoptions1 = bytes([53, 1, 2])
        DHCPoptions2 = bytes([1 , 4 , 0xFF, 0xFF, 0xFF, 0x00])
        DHCPoptions3 = bytes([3 , 4 , 0xC0, 0xA8, 0x01, 0x01])
        DHCPOptions4 = bytes([51 , 4 , 0x00, 0x01, 0x51, 0x80])
        DHCPOptions5 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x15]) #adresse du serveur
        DHCPOptions6 = bytes([6, 4 , 0xC0, 0xA8, 0x01, 0x01])  #DNS servers
        ENDMARK = bytes([0xff])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + magic_cookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 + DHCPOptions4 + DHCPOptions5 + DHCPOptions6 + ENDMARK
        return package

    def set_pack(xid, chaddr, magicookie, server_address, poll):

        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])

        XID = xid

        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])

        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        #YIADDR = inet_aton('192.168.1.201')
        YIADDR = inet_aton(poll[0])
        SIADDR = inet_aton(server_address)
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR = chaddr

        magic_cookie = magicookie

        DHCPoptions1 = bytes([53, 1, 5])
        DHCPoptions2 = bytes([1 , 4 , 0xFF, 0xFF, 0xFF, 0x00])
        DHCPoptions3 = bytes([3 , 4 , 0xC0, 0xA8, 0x01, 0x01])
        DHCPOptions4 = bytes([51 , 4 , 0x00, 0x01, 0x51, 0x80])
        DHCPOptions5 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x15])
        DHCPOptions6 = bytes([6, 4 , 0xC0, 0xA8, 0x01, 0x01]) 
        ENDMARK = bytes([0xff])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + magic_cookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 + DHCPOptions4 + DHCPOptions5 + DHCPOptions6 + ENDMARK
        return package



    serverPort = 67
    clientPort = 68

    serverAddress = '0.0.0.0'

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
        dhcpMessageType = dhcpoptions[2] #Type de message reçu

        xid, ciaddr, chaddr, magic_cookie = get_clientmsg(packet)[4], get_clientmsg(packet)[7], get_clientmsg(packet)[11], get_clientmsg(packet)[12]

        print("DHCP Message Type : ")
        print(dhcpMessageType)

        if(dhcpMessageType == 1): #Si c'est un DHCP Discover
            print("Received DHCP Discovery!")
            dataOffer = set_offer(xid, chaddr, magic_cookie, server_address, poll)
            server.sendto(dataOffer, dest) #On envoie offer
        
        if(dhcpMessageType == 3): #Si c'est un DHCP Request
            print("Received DHCP Request!")
            dataPack = set_pack(xid, chaddr, magic_cookie, server_address, poll)
            server.sendto(dataPack, dest) #On envoie Pack
            poll.pop(0) #on retire l'adresse donéee de la poll (système not perfect)
        

        #print(packet)
        #print("Requested IP Address : ")
        #print(get_clientmsg(packet)[14])

        '''
        print("Received DHCP discovery!")
        dataOffer = set_offer(xid, chaddr, magic_cookie, server_address)
        print("Data dans setoffer:")
        print(dataOffer)
        #print(data)
        server.sendto(dataOffer, dest)
        while True:
            print("Waiting for Request...")
            packet2, address2 = server.recvfrom(4096)
            dhcpoptions = get_clientmsg(packet2)[13]
            dhcpMessageType = dhcpoptions[1]
            print("Type dhcp :")
            print(dhcpMessageType)
            print(packet2)
            dataPack = set_pack(xid, chaddr, magic_cookie, server_address)
            server.sendto(dataPack, dest) '''

if __name__ == "main":
    serveurDHCP()
    




