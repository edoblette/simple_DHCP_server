import socket

class clientDHCP(object):

    serverPort = 67
    clientPort = 68

    #client inutile mdr

    def discover_get():
        OP = bytes([0x01])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04]) 
        CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00]) 
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00]) 
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00]) 
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53 , 1 , 1])
        DHCPOptions2 = bytes([50 , 4 , 0xC0, 0xA8, 0x01, 0x64])


        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2

        return package


    print("DHCP client is starting...")
    dest = ('<broadcast>', serverPort)

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    #clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    packet = discover_get() #petit test d'envoi de bytes du client
    clientSocket.bind(('0.0.0.0', clientPort))

    while True:

        clientSocket.sendto(packet, dest)
        data, address = clientSocket.recvfrom(4096)
        print("Received : ")
        print(data)

if __name__ == "main":
    clientDHCP()


