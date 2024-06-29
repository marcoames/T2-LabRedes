import socket
import sys
import uuid

def get_mac_address():
    mac_int = uuid.getnode()  
    mac_bytes = mac_int.to_bytes(6, byteorder='big')  # Converte para bytes

    # Formata
    mac = b''.join([bytes([int(b)]) for b in mac_bytes])
    return mac

# Checksum dos pacotes
def calculate_checksum(msg):
    if len(msg) % 2 == 1:
        msg += b'\x00'
    
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1])
        s += w

    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    s = ~s & 0xffff
    return s

# Criação do socket RAW
def create_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.bind(('', 67)) 
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    print("Socket Criado...")
    return s

# Função para criar pacote DHCP Offer
def dhcp_offer(transaction_id, server_mac, client_mac, server_ip, offered_ip, mascara, router_ip, dns_ip):
    # Eth header
    dest_mac = client_mac
    src_mac = server_mac
    eth_type = b'\x08\x00'  # IPv4

    # novo Header ETH
    eth_header = dest_mac + src_mac + eth_type

    # IP header 
    version = b'\x45'
    dsf = b'\x00'  
    total_length = b'\x00\x00' 
    identification = b'\x00\x00'
    fragment_offset = b'\x00\x00'
    ttl = b'\x80'
    protocol = b'\x11'
    checksum = b'\x00\x00'
    source_ip = socket.inet_aton(server_ip)
    #dest_ip = b'\xff\xff\xff\xff'  # Broadcast --> Ip do cliente
    dest_ip = offered_ip

    ip_header = version + dsf + total_length + identification + fragment_offset + ttl + protocol + checksum + source_ip + dest_ip

    ip_checksum = calculate_checksum(ip_header)
    ip_checksum = ip_checksum.to_bytes(2, byteorder='big')

    # novo Header IP
    ip_header = version + dsf + total_length + identification + fragment_offset + ttl + protocol + ip_checksum + source_ip + dest_ip

    # UDP header
    source_port = b'\x00\x43'
    dest_port = b'\x00\x44'
    length = b'\x00\x00'  
    checksum = b'\x00\x00'

    # novo Header UDP sem checksum e len
    udp_header = source_port + dest_port + length + checksum

    # DHCP header
    op = b'\x02'              
    htype = b'\x01'           
    hlen = b'\x06'            
    hops = b'\x00'
    xid = transaction_id  
    secs = b'\x00\x00'
    flags = b'\x00\x00'       
    cli_addr = b'\x00\x00\x00\x00'
    #your_cli_addr = socket.inet_aton(offered_ip)
    your_cli_addr = offered_ip
    next_server_ip_addr = socket.inet_aton(server_ip)
    relay_agent_ip_addr = b'\x00\x00\x00\x00'
    cli_mac = client_mac + b'\x00' * 10
    server_host_name = b'\x00' * 64
    file_name = b'\x00' * 128
    magic_cookie = b'\x63\x82\x53\x63'  

    # novo Header DHCP
    dhcp_header = op + htype + hlen + hops + xid + secs + flags + cli_addr + your_cli_addr + next_server_ip_addr + relay_agent_ip_addr + cli_mac + server_host_name + file_name + magic_cookie

    # DHCP options
    options = b''
    options += b'\x35\x01\x02'  # DHCP Offer
    options += b'\x01\x04' + socket.inet_aton(mascara)  # Mascara
    options += b'\x3a\x04\x00\x00\x07\x08'  # Renewal Time Value
    options += b'\x3b\x04\x00\x00\x0c\x4e'  # Rebinding Time Value
    options += b'\x33\x04\x00\x00\x0e\x10'  # Lease time 3600s
    options += b'\x36\x04' + socket.inet_aton(server_ip)    # DHCP Server
    options += b'\x03\x04' + socket.inet_aton(router_ip)  # Router
    options += b'\x06\x08' + socket.inet_aton(dns_ip) + socket.inet_aton(dns_ip) # DNS server
    options += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # padding
    options += b'\xff'  # End option
    options += b'\x00\x00\x00\x00' # padding

    # Calcula UDP length e checksum
    udp_length = 8 + len(dhcp_header) + len(options)

    # UDP header com length
    udp_header = source_port + dest_port + udp_length.to_bytes(2, byteorder='big') + checksum

    udp_checksum = calculate_checksum(udp_header + dhcp_header + options)
    udp_checksum = udp_checksum.to_bytes(2, byteorder='big')

    # UDP header com checksum
    udp_header = source_port + dest_port + udp_length.to_bytes(2, byteorder='big') + udp_checksum

    # Pacote final
    packet = eth_header + ip_header + udp_header + dhcp_header + options
    packet = ip_header + udp_header + dhcp_header + options

    print("Enviando Pacote Offer: ", packet)

    return packet


# Função para criar pacote DHCP Acknowledgement
def dhcp_ack(transaction_id, server_mac, client_mac, server_ip, offered_ip, mascara, router_ip, dns_ip):
    # Eth header
    dest_mac = client_mac
    src_mac = server_mac
    eth_type = b'\x08\x00'  # IPv4

    eth_header = dest_mac + src_mac + eth_type

    # IP header 
    version = b'\x45'
    dsf = b'\x00'  
    total_length = b'\x00\x00' 
    identification = b'\x00\x00'
    fragment_offset = b'\x00\x00'
    ttl = b'\x80'
    protocol = b'\x11'
    checksum = b'\x00\x00'
    source_ip = socket.inet_aton(server_ip)
    #dest_ip = b'\xff\xff\xff\xff'  # Broadcast --> Ip do cliente
    dest_ip = offered_ip


    ip_header = version + dsf + total_length + identification + fragment_offset + ttl + protocol + checksum + source_ip + dest_ip

    ip_checksum = calculate_checksum(ip_header)
    ip_checksum = ip_checksum.to_bytes(2, byteorder='big')

    # novo Header IP
    ip_header = version + dsf + total_length + identification + fragment_offset + ttl + protocol + ip_checksum + source_ip + dest_ip

    # UDP header
    source_port = b'\x00\x43'
    dest_port = b'\x00\x44'
    length = b'\x00\x00'  
    checksum = b'\x00\x00'

    # novo Header UDP sem checksum e len
    udp_header = source_port + dest_port + length + checksum

    #DHCP header 
    op = b'\x02'              
    htype = b'\x01'           
    hlen = b'\x06'            
    hops = b'\x00'
    xid = transaction_id  
    secs = b'\x00\x00'
    flags = b'\x00\x00'       
    cli_addr = b'\x00\x00\x00\x00'
    your_cli_addr = offered_ip
    next_server_ip_addr = b'\x00\x00\x00\x00'
    relay_agent_ip_addr = b'\x00\x00\x00\x00'
    cli_mac = client_mac + b'\x00' * 10 # com padding
    server_host_name = b'\x00' * 64
    file_name = b'\x00' * 128
    magic_cookie = b'\x63\x82\x53\x63'  

    # novo Header DHCP
    dhcp_header = op + htype + hlen + hops + xid + secs + flags + cli_addr + your_cli_addr + next_server_ip_addr + relay_agent_ip_addr + cli_mac + server_host_name + file_name + magic_cookie

    # DHCP options
    options = b''
    options += b'\x35\x01\x05'  # DHCP Ack
    options += b'\x36\x04' + socket.inet_aton(server_ip) # DHCP Server 
    options += b'\x33\x04\x00\x00\x0e\x10'  # Lease time 3600s
    options += b'\x01\x04' + socket.inet_aton(mascara)  # Mascara
    options += b'\x03\x04' + socket.inet_aton(router_ip)  # Router
    options += b'\x06\x08' + socket.inet_aton(dns_ip) +  socket.inet_aton(dns_ip) # DNS server
    options += b'\x0f\x04\x00\x00\x00\x00' # Domain Name
    options += b'\xff'  # End 
    options += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # padding

    # Calcula UDP length e checksum
    udp_length = 8 + len(dhcp_header) + len(options)

    # UDP header com length
    udp_header = source_port + dest_port + udp_length.to_bytes(2, byteorder='big') + checksum

    udp_checksum = calculate_checksum(udp_header + dhcp_header + options)
    udp_checksum = udp_checksum.to_bytes(2, byteorder='big')

    # UDP header com checksum
    udp_header = source_port + dest_port + udp_length.to_bytes(2, byteorder='big') + udp_checksum

    # Pacote final
    packet = eth_header + ip_header + udp_header + dhcp_header + options

    print("Enviando Pacote Acknowledgement: ", packet)

    return packet


def dhcp_offer2(transaction_id, ip_header, udp_header, dhcp_header, dhcp_options, server_ip, server_mac, client_mac, dns_ip):
    print("\n")
    print("IP header: ", ip_header.hex())
    print("UDP header: ", udp_header.hex())
    print("DHCP header: ", dhcp_header.hex())
    print("DHCP options: ", dhcp_options.hex())

    # ETH HEADER
    new_eth_header = bytearray(14)
    new_eth_header[:6] = client_mac
    new_eth_header[6:12] = server_mac
    new_eth_header[12:14] = b'\x08\x00'

    print("NEW_ETH header: ", new_eth_header.hex())

    # IP HEADER
    new_ip_header = bytearray(ip_header)
    new_ip_header[:16] = ip_header[:16]
    new_ip_header[12:16] = socket.inet_aton(server_ip)
    new_ip_header[17:20] = client_mac

    ip_checksum = calculate_checksum(ip_header)
    new_ip_header[10:12] = ip_checksum.to_bytes(2, byteorder='big')

    print("NEW_IP header: ", new_ip_header.hex())

    # UDP HEADER
    new_udp_header = bytearray(udp_header)
    new_udp_header[0:2] = b'\x00\x44'   # Source Port
    new_udp_header[2:4] = b'\x00\x43'   # Dest Port
    new_udp_header[4:] = udp_header[4:]

    print("NEW_UDP header: ", new_udp_header.hex())

    # DHCP HEADER
    new_dhcp_header = bytearray(dhcp_header)
    new_dhcp_header[0:1] = b'\x02'
    new_dhcp_header[1:17] = dhcp_header[1:17]
    new_dhcp_header[17:21] = socket.inet_aton(server_ip)
    new_dhcp_header[21:28] = dhcp_header[21:28]
    new_dhcp_header[28:33] = client_mac
    new_dhcp_header[33:254] = dhcp_header[33:254]

    print("NEW_DHCP header: ", new_dhcp_header.hex())

    # DHCP Options
    new_dhcp_options = bytearray(dhcp_options)
    new_dhcp_options[:3] =  b'\x35\x01\x05'
    new_dhcp_options[3:9] = socket.inet_aton(server_ip)
    new_dhcp_options[9:15] = b'\x33\x04\x00\x00\x0e\x10'  # Lease time 3600s
    new_dhcp_options[15:21] = b'\x01\x04\xff\xff\xff\x00'  # Mascara
    new_dhcp_options[21:26] = b'\x03\x04' + socket.inet_aton(server_ip)
    new_dhcp_options[26:36]= b'\x06\x08' + socket.inet_aton(dns_ip) +  socket.inet_aton(dns_ip) # DNS server
    new_dhcp_options[36:42] = b'\x0f\x04\x00\x00\x00\x00' # Domain Name
    new_dhcp_options[36:37] = b'\xff'
    new_dhcp_options[37:]= b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # Padding

    print("NEW_DHCP options: ", new_dhcp_options.hex())

    packet = new_eth_header + new_ip_header + new_udp_header + new_dhcp_header + new_dhcp_options
    packet = new_ip_header + new_udp_header + new_dhcp_header + new_dhcp_options

    print("\n")
    print("PACKET: ", packet)
    print("\n")

    return packet

# Função principal para executar o servidor DHCP
def dhcp_server():
    hostname = socket.gethostname()
    server_ip = socket.gethostbyname(hostname)
    s = create_socket()
    print("SERVER IP: ", server_ip)
    server_mac = get_mac_address()
    print("Server MAC: ", server_mac.hex())

    print("Servidor em execução...")

    # Dados
    offered_ip = b'\xc0\xa8\x01\x64' #'192.168.1.100' # IP PARA OFFER
    mascara = '255.255.255.0'
    router_ip = server_ip
    dns_ip = '8.8.8.8'      # IP DO SERVIDOR DNS A SER CONFIGURADO COM BIND9

    while True:
        try:
            print("\nEscutando...")
            packet, addr = s.recvfrom(4096)

            print("Pacote Recebido:", packet)
            print("Endereço:", addr)

   

            # dados do header eth
            # eth_header = packet[0:14]
            # print("Eth header: ", eth_header.hex())

            # dados do header ip
            ip_header = packet [0:20]
            #print("IP header: ", ip_header.hex())

            # dados do header udp
            udp_header = packet[20:28]

            # dados do header dhcp
            dhcp_header = packet[28:268]

            # dados dhcp options
            dhcp_options = packet[268:]

            transaction_id = packet[32:36]
            print("\nTransaction ID: ", transaction_id.hex())
            client_mac = packet[56:61]
            print("Client MAC: ", client_mac.hex())
            #client_ip = ??

            message_type = packet[270]
            print("Message Type: ", message_type)

            # Envia Pacotes de Offer e Ack
            if message_type == 1:
                print(f'\nDHCP Discover recebido de {addr}, enviando DHCP Offer')
                packet = dhcp_offer(transaction_id, server_mac, client_mac, server_ip, offered_ip, mascara, router_ip, dns_ip)
                #packet = dhcp_offer2(transaction_id, ip_header, udp_header, dhcp_header, dhcp_options, server_ip, server_mac, client_mac, dns_ip)
                s.sendto(packet, ('<broadcast>', 68))

            elif message_type == 3:
                print(f'\nDHCP Request recebido de {addr}, enviando DHCP Acknowledgement')
                packet = dhcp_ack(transaction_id, server_mac, client_mac, server_ip, offered_ip, mascara, router_ip, dns_ip)
                s.sendto(packet, ('<broadcast>', 68))
        
        except BlockingIOError:
            pass

if __name__ == "__main__":
   try:
       dhcp_server()
   except PermissionError:
       print("Error: PermissionError.")
       sys.exit(1)
