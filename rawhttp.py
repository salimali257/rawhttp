#Author: Salim Ali Siddiq
#Time: March 2016
#!/usr/bin/env python

# package imported to create sockets
import socket
import sys, time, random, subprocess
# package imported to pack and unpack packets
import struct

# Global variables used throughout the project
source_ip = ""
destination_ip = ""
first_seqNo = 0
userData = ""
present_cwnd = 1
prev_seq = 0
old_dataLen = 0


# Construct IP header using parameters and !BBHHHBBH4s4s format
def construct_ipHeader(ihl_ver_of_ip, tos_of_ip, tot_length_of_ip, id_of_ip_pkt, fragm_off_of_ip, ttl_of_ip, protocol_of_ip, chksum_of_ip, source_add_of_ip, dest_add_of_ip):
    return struct.pack('!BBHHHBBH4s4s' , ihl_ver_of_ip, tos_of_ip, tot_length_of_ip, id_of_ip_pkt, fragm_off_of_ip, ttl_of_ip, protocol_of_ip, chksum_of_ip, source_add_of_ip, dest_add_of_ip)

# Construct IP header using parameters and !4s4sBBH format
def construct_pseudoHeader(source_address, dest_address, placeholder, protocol, tcp_length):
    return struct.pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length)

# find local machine IP address
def find_srcIP():
    sock_findIP = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_findIP.connect(("google.com", 0))
    return sock_findIP.getsockname()[0]

# method to send ARP request and get the destination MAC address(Gateway MAC address)
def destinationMac():
    global src_IPaddr, src_MacAddr, dest_IPaddr

    # convert source IP address in ascii form
    src_IPaddr = socket.inet_aton(source_ip)

    # get MAC address of source
    sock_srcMac = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock_srcMac.bind(("eth0", socket.SOCK_RAW))
    src_MacAddr = sock_srcMac.getsockname()[4]

    # get the gateway IP address
    route_param = subprocess.check_output(['route', '-n']).split()
    gateway_IP = route_param[13]
    dest_IPaddr = socket.inet_aton(gateway_IP)

    # consrtuct and send ARP packet
    # broadcast ARP message with destination Mac address as below
    broadcast_MacAddr = struct.pack('!6B', 255, 255, 255, 255, 255, 255)
    #send hardware type, protocol type, hardware length, protocol length in arp packet
    arp_pkt = struct.pack('!HHBBH6s4s6s4s', 1, 2048, 6, 4, 1, src_MacAddr, src_IPaddr, broadcast_MacAddr, dest_IPaddr)
    #send the source mac, broadcast mac in the ethernet header
    eth_header = struct.pack('!6s6sH', broadcast_MacAddr, src_MacAddr, 2054)
    # send ethernet packet containing ethernet header and ARP packet
    eth_pkt = eth_header + arp_pkt


    # bind this socket for "eth0"
    sock.bind(("eth0",socket.SOCK_RAW))
    # send ethernet packet, so that MAC address of gateway can be retrieved from its response.
    sock.send(eth_pkt)

    while True:
        packet =  sock.recv(65565)
        # unpack ethernet packet received
        eth_field = struct.unpack('!6s6sH', packet[:14])
        if eth_field[2] == 2054:
            break
    # unpack arp packet from eth packet
    arp_field = struct.unpack('!HHBBH6s4s6s4s', packet[14:][:28])
    # 5th field is source h/w address from where the packet is received. Hence it is our destination MAC address
    dest_MacAddr = arp_field[5]
    return dest_MacAddr

# construct HTTP header with empty data. This is used to send ACK/FIN ACK to the server
def httpHead_noData():
    global userData
    userData = ""

# calculate checksum for the TCP and IP input message
def create_checksum(data_for_checksum):
    counter = 0
    sum = 0
    msgLen = len(data_for_checksum)
    msg_limit = 2

    while msgLen >= msg_limit:
        w = (ord(data_for_checksum[counter+1]) << 8 ) + ord(data_for_checksum[counter])
        sum = sum + w
        counter= counter + msg_limit
        msgLen = msgLen - msg_limit
    if msgLen == 1:
        sum = sum + ord(data_for_checksum[counter])

    carry = (sum >> 16) + (sum & 0xffff);
    sum = carry + (carry * (2 ** 16));
    sum = ~sum & 0xffff
    return sum

# create Packet with TCP, IP and Ethernet header
def constructPacket(tcp_src, tcp_dest, tcp_seq, tcp_ackSeq, tcp_off, tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, tcp_urg, tcp_window, tcp_checksum, tcp_ptrUrg):
    global tcp_header, ip_header, eth_header
    src_addr = socket.inet_aton( source_ip )
    dest_address = socket.inet_aton(destination_ip)
    protocol = socket.IPPROTO_TCP

    # TCP Header Section
    # set window size
    tcp_window = socket.htons (tcp_window)
    # set tcp offset flag
    tcp_offsetNumber = (tcp_off * (2 ** 4)) + 0
    # set all flags of tcp header and concatenate them
    tcp_flags = tcp_fin + (tcp_syn * (2 ** 1)) + (tcp_rst * (2 ** 2)) + (tcp_psh * (2 ** 3)) + (tcp_ack * (2 ** 4)) + (tcp_urg * (2 ** 5))
    # construct raw tcp header 1st
    tcp_header_1 = struct.pack("!HHLLBBHHH", tcp_src, tcp_dest, tcp_seq, tcp_ackSeq, tcp_offsetNumber, tcp_flags, tcp_window, tcp_checksum, tcp_ptrUrg)
    tcp_length = len(tcp_header_1) + len(userData)
    # create TCP Pseudo header
    pseudo_header = construct_pseudoHeader(src_addr, dest_address, 0, protocol, tcp_length)
    pseudo_header = pseudo_header + tcp_header_1 + userData;
    # Calculate TCP checksum
    tcp_checksum = create_checksum(pseudo_header)
    # now put correct checksum into re-created tcp header.
    tcp_header = struct.pack('!HHLLBBH', tcp_src, tcp_dest, tcp_seq, tcp_ackSeq, tcp_offsetNumber, tcp_flags, tcp_window) + struct.pack('H', tcp_checksum) + struct.pack('!H', tcp_ptrUrg)
    tcp_header = tcp_header + userData

    # IP Header Section
    ip_headerLength = 5
    ip_version = 4
    ip_ver_headerLen = (ip_version * (2 ** 4)) + ip_headerLength
    ip_totalLen = 4 * ip_headerLength + len(tcp_header)
    # Calculate IP Header
    ip_header = construct_ipHeader (ip_ver_headerLen, 0, ip_totalLen, 54321, 0, 225, protocol, 0, src_addr, dest_address)
    # Calculate IP CHecksum
    ip_checksum =  create_checksum(ip_header)
    # now put correct checksum into re-created IP header.
    ip_header = construct_ipHeader (ip_ver_headerLen, 0, ip_totalLen, 54321, 0, 225, protocol, ip_checksum, src_addr, dest_address)
    ip_header = ip_header + tcp_header

    # Ethernet Header Section
    # create the ethernet header
    eth_wrap = struct.pack('!6s6sH', mac, src_MacAddr, 2048)
    #create the packet with the ethernet header
    eth_header = eth_wrap + ip_header

# Method for sending packet to the server
def send_packet():
    global time_lastPktSent
    sock.bind(("eth0",0))
    sock.send(eth_header)
    time_lastPktSent = time.time()

# Method to receive data from the server
def receive_data():
    global ACK, sequence,  old_dataLen, prev_seq, remainingRT_toAck, present_cwnd

    remainingRT_toAck = 0
    # open a file in  and write relevant data into it received from the server
    f = open(downloadFile,'a')
    # sys.exit(0)
    while True:
        # Check whether data is getting received from server within 3 minutes; else close the connection
        if (time.time() - time_lastPktSent) > 180:
                print "Not receiving any data for three minutes. retry later."
                sys.exit(0)
        # receive data from server
        packet = sock.recvfrom(65565)
        packet = packet[0]

        # locate ip header
        ip_header = packet[14:14 + 20]
        # unpack data from ip
        unwrapped_IPheader = struct.unpack('!BBHHHBBH4s4s', ip_header)
        ip_ver_headerLen = unwrapped_IPheader[0]
        ihl = ip_ver_headerLen & 0xF
        IP_headerLen = ihl * 4
        src_addr = socket.inet_ntoa(unwrapped_IPheader[8]);
        dest_addr = socket.inet_ntoa(unwrapped_IPheader[9]);

        # locate tcp header
        tcp_header = packet[IP_headerLen + 14:14 + IP_headerLen + 20]
        # unpack data from the tcp
        unwrapped_tcpHeader = struct.unpack('!HHLLBBHHH', tcp_header)
        src_port = unwrapped_tcpHeader[0]
        dest_port = unwrapped_tcpHeader[1]
        sequence = unwrapped_tcpHeader[2]
        ACK = unwrapped_tcpHeader[3]
        dOffset_res = unwrapped_tcpHeader[4]
        tcp_flag = unwrapped_tcpHeader[5]
        # unpack tcp flag values flag_fin, flag_syn, flag_ack
        fin_flag = tcp_flag & 1
        syn_flag = (tcp_flag >> 1) & 1
        ack_flag = (tcp_flag >> 4) & 1
        # unpack other tcp parameters
        tcp_headerLen = dOffset_res >> 4
        totalHeader_size = 14 + IP_headerLen + tcp_headerLen * 4

        # locate data
        data_size = len(packet) - totalHeader_size
        data = packet[totalHeader_size:]
        index = data.find('\r\n\r\n') + 4
        header = data[:index]


        #Receive packet for the raw client program for the correct client-server port and IP adddress
        if (dest_port) == local_port and src_port == 80 and src_addr == destination_ip and dest_addr == source_ip :
            #Receive SYN ACK from the server
            if ack_flag == 1 and syn_flag==1:
                #store the sequence number for in order delivery of the packets
                prev_seq = sequence + 1
                break

            # Check whether size of current cwnd window must lie between 1 and 1000'''
            if  data_size > 6 and present_cwnd <= 1000:
                #condition to check in-order delivery of the packets
                if prev_seq + old_dataLen == sequence and create_checksum(ip_header) == 0:
                    #Receive Data and Send an ACK if a packet is ACKed within 1 minute
                    if (time.time() - time_lastPktSent) < 60:
                        # Check whether data begins with HTTP
                        if data.startswith('HTTP/1.1'):
                            status = header[9:12]
                            # If header doesnt contain 200 ok, exit the program
                            if status != '200':
                                sys.exit( "not 200 OK status! try again.")
                            else:
                                 f.write(data[index:])
                        else:
                            f.write(data)
                        # save current sequence, and data size to check in-order delivery of the packets
                        prev_seq = sequence
                        old_dataLen = data_size


                        # If a retransmitted packet is ACKed, reduce counter by 1.
                        if remainingRT_toAck > 0:
                            remainingRT_toAck = remainingRT_toAck - 1

                        # increment the cwnd after each succesful ACK. Maximum limit up to 1000
                        if present_cwnd + 1 > 0 and present_cwnd + 1 < 1000:
                            present_cwnd = present_cwnd + 1
                        else:
                            present_cwnd = 1
                        send_DataAck(sequence)

                    else:
                        retransmit_DataAck(prev_seq)
                else:
                    if present_cwnd + 1 > 0 and present_cwnd + 1 < 1000:
                        present_cwnd = present_cwnd + 1
                    else:
                        present_cwnd = 1
                    remainingRT_toAck = 1
                    # Retransmit old seq if data is not received within 3 minutes
                    retransmit_DataAck(prev_seq)

            # if FIN flag is set for the packet, which is being sniffed send back a FIN ACK
            if fin_flag == 1 and remainingRT_toAck == 0 :
                f.close()
                send_finAck()
                break
                sys.exit(0)

# Methods to send and handle raw socket requests and responses
# 1st step of handshake
def handshake_part1():
    httpHead_noData()
    initial_ACK_number = 0
    constructPacket(local_port, 80, first_seqNo, initial_ACK_number, 5, 0, 1, 0, 0, 0, 0, 5840, 0, 0)
    send_packet()

# 3rd step of handshake
def handshake_part3():
    httpHead_noData()
    constructPacket(local_port, 80, first_seqNo + 1, sequence + 1, 5, 0, 0, 0, 0, 1, 0, 5840, 0, 0)
    send_packet()

# send initial http request data
def send_data():
    global userData, message_len
    httpHeader = "GET " + url + " HTTP/1.0\r\n\r\n"
    userData = httpHeader
    message_len = len(httpHeader)
    constructPacket(local_port, 80, first_seqNo + 1, int (sequence), 5, 0, 0, 0, 1, 1, 0, 5840, 0, 0)
    send_packet()

# send ACK of data
def send_DataAck(seq_no):
    httpHead_noData()
    constructPacket(local_port, 80, first_seqNo + 1 + message_len, seq_no + 1, 5, 0, 0, 0, 0, 1, 0, 5840, 0, 0)
    send_packet()

# retransmit ACK of data
def retransmit_DataAck(seq_no):
    httpHead_noData()
    constructPacket(local_port, 80, first_seqNo + 1 + message_len, seq_no + old_dataLen, 5, 0, 0, 0, 0, 1, 0, 5840, 0, 0)
    send_packet()

# send FIN ACK message
def send_finAck():
    httpHead_noData()
    constructPacket(local_port, 80, ACK, int (sequence) + 1, 5, 1, 0, 0, 0, 1, 0, 5840, 0, 0)
    send_packet()


# socket initialization
global sock
try:
    sock = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.bind(("eth0",0))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit(0)


try:
    for i in range(1):
        local_port = int('%04d' % random.uniform(2000, 65534))

    if len(sys.argv) == 2:

        downloadedFileToBeNamed = ""
        url = sys.argv[1]
        # check whether the link starts with 'http://' and split it at that point to get URL
        urlArray = url.split('http://')

        if urlArray > 1 and urlArray[0] == "":
            link = urlArray[1]
            slashseperatedarray = link.split('/')

        # if link does not contain any '/' then the file should be named index.html
            if slashseperatedarray[0] == link or slashseperatedarray[1]=="":
                downloadFile = "index.html"
                HostName = urlArray[1]
            else:
                HostName = slashseperatedarray[0]
                # create the name of the file as the page to be downloaded
                downloadFile = slashseperatedarray[len(slashseperatedarray)-1]


            # find server IP address
            destination_ip = socket.gethostbyname(HostName)

            # find sender or source IP address
            source_ip = find_srcIP()

            # find gateway MAC address
            mac = destinationMac()

            message_len = len("GET " + url + " HTTP/1.0\r\n\r\n")
            # start of execution
            handshake_part1()
            receive_data()
            handshake_part3()
            send_data()
            receive_data()
        else:
            print "Error! Please try again."

    else:
        print "Illegal number of arguments passed."
except:
    print "Error! Try again."
