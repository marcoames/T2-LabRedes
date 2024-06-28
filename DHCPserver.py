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
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1])
        s = s + w

    s = (s >> 16) + (s & 0xffff)
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
    header = source_ip + dest_ip + b'\x00' + b'\x11' + udp_length.to_bytes(2, byteorder='big')

    # UDP header com length
    udp_header = source_port + dest_port + udp_length.to_bytes(2, byteorder='big') + checksum

    udp_checksum = calculate_checksum(header + udp_header + dhcp_header + options)
    udp_checksum = udp_checksum.to_bytes(2, byteorder='big')

    # UDP header com checksum
    udp_header = source_port + dest_port + udp_length.to_bytes(2, byteorder='big') + udp_checksum

    # Pacote final
    packet = eth_header + ip_header + udp_header + dhcp_header + options

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
    #your_cli_addr = socket.inet_aton(offered_ip)
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
    header = source_ip + dest_ip + b'\x00' + b'\x11' + udp_length.to_bytes(2, byteorder='big')

    # UDP header com length
    udp_header = source_port + dest_port + udp_length.to_bytes(2, byteorder='big') + checksum

    udp_checksum = calculate_checksum(header + udp_header + dhcp_header + options)
    udp_checksum = udp_checksum.to_bytes(2, byteorder='big')

    # UDP header com checksum
    udp_header = source_port + dest_port + udp_length.to_bytes(2, byteorder='big') + udp_checksum

    # Pacote final
    packet = eth_header + ip_header + udp_header + dhcp_header + options

    print("Enviando Pacote Acknowledgement: ", packet)

    return packet


# Função principal para executar o servidor DHCP
def dhcp_server():
    hostname = socket.gethostname()
    server_ip = socket.gethostbyname(hostname)
    s = create_socket()
    print("SERVER IP: ", server_ip)
    server_mac = get_mac_address()
    print("Server MAC: ", server_mac)

    print("Servidor em execução...")

    # Dados
    offered_ip = b'\xc0\xa8\x01\x64' #'192.168.1.100' # IP PARA OFFER
    mascara = '255.255.255.0'
    router_ip = server_ip
    dns_ip = '8.8.8.8'      # IP DO SERVIDOR DNS A SER CONFIGURADO COM BIND9

    while True:
        try:
            print("Escutando...")
            packet, addr = s.recvfrom(4096)

            print("Pacote Recebido:", packet)
            print("Endereço:", addr)

            message_type = packet[284-14]
            print("Message Type: ", message_type)

            # dados do header eth
            # eth_header = packet[0:14]
            # print("Eth header: ", eth_header.hex())

            # dados do header ip
            ip_header = packet [0:20]
            print("IP header: ", ip_header.hex())

            # transaction_id = dhcp_header[4:8]
            transaction_id = packet[46-14:50-14]
            print("Transaction ID: ", transaction_id.hex())
            client_mac = packet[70-14:76-14]
            print("Client MAC: ", client_mac.hex())
            #client_ip = ??

            # Envia Pacotes de Offer e Ack
            if message_type == 1:
                print(f'DHCP Discover recebido de {addr}, enviando DHCP Offer')
                packet = dhcp_offer(transaction_id, server_mac, client_mac, server_ip, offered_ip, mascara, router_ip, dns_ip)
                s.sendto(packet, ('<broadcast>', 68))

            elif message_type == 3:
                print(f'DHCP Request recebido de {addr}, enviando DHCP Acknowledgement')
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
