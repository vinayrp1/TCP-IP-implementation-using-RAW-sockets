##########################################################################################
# rawhttpget.py	
##########################################################################################

#! /usr/bin/python

# import modules here

import socket
import sys
import binascii
from struct import *
import urlparse
import thread
import time
import random
import re
import fcntl
import signal
import binascii
import subprocess

##########################################################################################

# constants go here

# sender_sock parameters
sender_sock_domain = socket.AF_PACKET
sender_sock_type = socket.SOCK_RAW
sender_sock_protocol = socket.SOCK_RAW 

# receiver_sock parameters
receiver_sock_domain = socket.AF_INET
receiver_sock_type = socket.SOCK_RAW
receiver_sock_protocol = socket.IPPROTO_TCP

url = sys.argv[1]

# constants for TCP header
TCP_HDR_LEN = 20
SRC_PORT =  26121  # source port
DEST_PORT = 80   # destination port
RST_FLAG = 0

# constants for IP header
IHL = 5
IP_VERSION = 4
TYPE_OF_SERVICE = 0
DONT_FRAGMENT = 0
IP_HDR_LEN = 20
MIN_TOTAL_LENGTH = IP_HDR_LEN + TCP_HDR_LEN
FRAGMENT_STATUS = DONT_FRAGMENT
TIME_TO_LIVE = 255
PROTOCOL = socket.IPPROTO_TCP
SOURCE_IP_ADDR = ""
DEST_IP_ADDR = ""

valid_HTTP_code = '200 OK'
SRC_MAC = ""
DEST_MAC = ""
interface = "eth0"

##########################################################################################

# sub routines

def get_IPADDR_of_source():

	# creating dummy socket and connecting to a server, to extract the source IP addr from the socket
	# object	
	dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,0)
	dummy_sock.connect(("david.choffnes.com",DEST_PORT))
	source_ip_add = dummy_sock.getsockname()[0]
	return source_ip_add

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
def get_IPADDR_of_dest():

	global HOST_NAME
	dest_ip_add = socket.gethostbyname(HOST_NAME)
	return dest_ip_add

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
def create_sender_sock():

	try:
		sock_tx = socket.socket(sender_sock_domain,sender_sock_type,sender_sock_protocol)		#creating sender raw socket
	except socket.error , event:
		print 'Sender Raw socket could not be created. Error Code : ' + str(event[0]) + ' Notif ' + event[1]
		sys.exit()
	return sock_tx

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
def create_receiver_sock():

	global SOURCE_IP_ADDR
	try:
		sock_rx = socket.socket(receiver_sock_domain,receiver_sock_type,receiver_sock_protocol)
	except socket.error , event:
		print 'Receiver raw socket sould not be created. Error Code : ' + str(event[0]) + ' Notif ' + event[1]
		sys.exit()
	return sock_rx

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
def build_IP_header(payload_len):	  

	global IHL, IP_VERSION, TYPE_OF_SERVICE, DONT_FRAGMENT, IP_HDR_LEN, MIN_TOTAL_LENGTH, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, SOURCE_IP_ADDR, DEST_IP_ADDR 
	src_IP = socket.inet_aton(SOURCE_IP_ADDR)
	dest_IP = socket.inet_aton(DEST_IP_ADDR)
	pktID = random.randint(10000,50000) 							# some random number as ID in IP hdr
	check_sum_of_hdr = 0 
	total_len = 20 + payload_len 
	IHL_VERSION = IHL + (IP_VERSION << 4) 
	IP_header = pack('!BBHHHBBH4s4s' , IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, src_IP,dest_IP)
	check_sum_of_hdr = get_checksum(IP_header)
	IP_header = pack('!BBHHHBBH4s4s' , IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, src_IP,dest_IP)	
	return IP_header

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
def build_TCP_header(seq_no, ack_no, ackf, synf, finf=0, data=""):
	
	global SOURCE_IP_ADDR, DEST_IP_ADDR,SRC_PORT,DEST_PORT
	tcp_hdr_len = 5    						# length of tcp hdr in hexadecimal
	pushf, urgptr, temp_checksum, rstf, urgent_ptr = 0, 0, 0, 0, 0	
	adv_window = socket.htons(1500)	
	offset = (tcp_hdr_len << 4) 
	tcp_flags = finf + (synf << 1) + (rstf << 2) + (pushf <<3) + (ackf << 4) + (urgent_ptr << 5) #6bit tcp flags 
	payload_len = len(data)
	if(payload_len % 2 == 1):
		payload_len = payload_len + 1			
	pack_arg = '!HHLLBBHHH'	 			    #  for check_sum calculation
	if not data:							# For syn,ack,fin segments
		tcp_header = pack(pack_arg, SRC_PORT, DEST_PORT, seq_no, ack_no, offset, tcp_flags,  adv_window, temp_checksum, urgptr)	
	else:								# For segements that contain some payload
		pack_arg = pack_arg + str(payload_len) + 's'
		tcp_header = pack(pack_arg, SRC_PORT, DEST_PORT, seq_no, ack_no, offset, tcp_flags,  adv_window, temp_checksum, urgptr,data)	
	source_address = socket.inet_aton(SOURCE_IP_ADDR)
	dest_address = socket.inet_aton(DEST_IP_ADDR)
	# constructing pseudo header for checksum calculation
	protocol = socket.IPPROTO_TCP
	rsrv_bits = 0
	tcp_length = len(str(tcp_header))
	pseudo_hdr = pack('!4s4sBBH', source_address, dest_address, rsrv_bits, protocol, tcp_length)
	pseudo_hdr = pseudo_hdr + tcp_header
	tcp_checksum = get_checksum(pseudo_hdr)
	#actual tcp header
	if not data:	
		tcp_header = pack(pack_arg, SRC_PORT, DEST_PORT, seq_no, ack_no, offset, tcp_flags,  adv_window, tcp_checksum, urgptr)	
	else:
		tcp_header = pack(pack_arg, SRC_PORT, DEST_PORT, seq_no, ack_no, offset, tcp_flags,  adv_window, tcp_checksum, urgptr,data)
	return tcp_header,20+payload_len

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
def get_received_packet(rx_sock):
	
	global DEST_IP_ADDR, SOURCE_IP_ADDR, SRC_PORT, DEST_PORT
	sourceIP = ""
	dest_port = ""
	# loop until we get the packet destined for our port and IP addr
	while ( sourceIP != str(DEST_IP_ADDR) and dest_port != str(SRC_PORT) or sourceIP != "" and dest_port != ""):
        	recvPacket = rx_sock.recv(65565)
        	ipHeader=recvPacket[0:20]
        	ipHdr=unpack("!2sH8s4s4s",ipHeader)					#unpacking to get IP header
        	sourceIP=socket.inet_ntoa(ipHdr[3])
        	tcpHeader=recvPacket[20:40]						#unpacking to get TCP header
        	tcpHdr=unpack('!HHLLBBHHH',tcpHeader)
        	dest_port=str(tcpHdr[1])
        	destinationIP = ""
        	dest_port = ""
	return recvPacket

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def check_ack_received(seq_no,ack_no,rx_sock,tcp_hdr_max = 40):
	
	recvPacket = get_received_packet(rx_sock)
	ipHdr=unpack("!2sH8s4s4s",recvPacket[0:20])
	mss = 0
	unpack_arg = '!HHLLBBHHH'
	if (tcp_hdr_max == 44):
		unpack_arg = unpack_arg + 'L'					# for syn-ack segment which is of 24 bytes
	tcpHdr=unpack(unpack_arg,recvPacket[20:tcp_hdr_max])
	length = ipHdr[1] - 40
	if (length == 0 or length == 4):					# length == 4 is for syn-ack segment
		seq_no_recv = tcpHdr[2]
		ack_no_recv = tcpHdr[3]
		tcp_flags = tcpHdr[5]
		if(tcp_hdr_max == 44):
			mss = tcpHdr[9]						# get MSS from SYN-ACK segment
		ack_flag = (tcp_flags & 16)
		if(ack_flag == 16 and ((seq_no == ack_no_recv - 1 and length == 4) or (seq_no == ack_no_recv and length == 0))):
			return seq_no_recv,mss
	return False,mss

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
def initiate_conn():
	
	# updating the source and destination IP addresses
	global SOURCE_IP_ADDR, DEST_IP_ADDR
	SOURCE_IP_ADDR = get_IPADDR_of_source()
	DEST_IP_ADDR = get_IPADDR_of_dest()

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++	

def perform_TCP_handshake(rx_sock,tx_sock):
	
	seq_no = 1
	ack_no = 0
	syn_flag = 1
	ack_flag = 0 
	tcp_seg,length = build_TCP_header(seq_no, ack_no, ack_flag,syn_flag)
	packet = build_IP_header(length) + tcp_seg
	send_ethernet_frame(packet,tx_sock)
	new_ack,mss = check_ack_received(seq_no,ack_no,rx_sock,44)						
	if (new_ack == False):																# in case we dont receive our syn-ack
		print "handshake failed !\n"
		sys.exit()
	else:
		seq_no = 2									# send ack if we get our syn ack
		syn_flag = 0
		ack_flag = 1 			
		tcp_seg,length = build_TCP_header(seq_no, new_ack+1, ack_flag,syn_flag)
	        packet = build_IP_header(length) + tcp_seg
		send_ethernet_frame(packet,tx_sock)
		return new_ack,2,mss

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		
def get_checksum(data):

	sum = 0
    	for index in range(0,len(data),2):
       		word = (ord(data[index]) << 8) + (ord(data[index+1]))
       		sum = sum + word
    	sum = (sum >> 16) + (sum & 0xffff);
    	sum = ~sum & 0xffff
    	return sum

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
def parse_URL(url):

	# extract Host name, path from the given URL, if the format is wrong, abort !
	http_srch_obj = re.search('http://',url,re.I|re.M)
	if not http_srch_obj:
        	url = 'http://' + url							# prepend http:// to actual url if not present
	url_obj = urlparse.urlparse(url)
	if(url_obj[0] == 'http'):
        	HOST_NAME = url_obj[1]
	    	PATH_NAME = url_obj[2]
        	if(not PATH_NAME):
        		PATH_NAME = '/'							#if no path_name, default is '/'
	else:
        	print "Given URL is not in expected format\n"
		sys.exit()
	return HOST_NAME,PATH_NAME

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
def constructGETRequest(HOST_NAME,PATH_NAME):
    
	# GET request using HTTP/1.0 , dont want to get extra characters in form of chunked encoding
	get_request = "GET " + PATH_NAME + " HTTP/1.0\r\n" + "Host: " + HOST_NAME + "\r\n\r\n" 	
	return get_request

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
def send_to_server(send_string, ack, seq,rx_sock,tx_sock,cwnd,mss):
	
	# basic implementation of congestion window
	global current_index,slow_start_flag
	last_segment = 0
	if (slow_start_flag == 1):						# if slow_start,then set cwnd = 1
        	slow_start_flag = 0
        	cwnd = 1
    	else:									# else additive increase
		current_index = current_index + cwnd*mss			# max cwnd is 1000
        cwnd = min(2*cwnd,1000)							
	if(len(send_string) - current_index  <= 0):				# return if there is no more data to send
		return
	if (len(send_string) - current_index > cwnd*mss):
		buffer = send_string[current_index:(current_index + cwnd)]	# collect data from send_string and put it in buffer
	else: 
		buffer = send_string[current_index:]									
		last_segment = 1
	tcp_seg,length = build_TCP_header(seq, ack+1, 1,0,last_segment,buffer)
        packet = build_IP_header(length) + tcp_seg
	send_ethernet_frame(packet,tx_sock)
	thread.start_new_thread(time_out_for_thread,(current_index,len(send_string),))   # start a thread that maintains timer
	seq_no,mss = check_ack_received(seq+cwnd,ack,rx_sock)
	while(seq_no == False and slow_start_flag == 0):
		seq_no,mss = check_ack_received(seq+cwnd,ack,rx_sock)		# loop until you get ack or timeout 
	if(last_segment == 1):							#    i.e. slow_start_flag				
		return 
	send_to_server(send_string, ack, seq+cwnd*mss,rx_sock,tx_sock,cwnd,mss)

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++	

def time_out_for_thread(index,len):

	global current_index,slow_start_flag
	time.sleep(1)
	if(index == current_index and current_index < len):			# current index hasn't moved forward for 60s,
		slow_start_flag = 1						# enter slow start phase
	thread.exit()

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
def get_response(seq_no,ack_no,rx_sock):

	fin_flag = 0
	data = {}								# dictionary to maintain the payload
	tear_down_success_flag = 0		
	while(tear_down_success_flag != 1):	
		recvPacket = get_received_packet(rx_sock)
		ipHeader=recvPacket[0:20]
		tcpHeader=recvPacket[20:40]
		ipHdr = unpack("!2sH8s4s4s",ipHeader)
		recv_length = ipHdr[1] - 40
		tcpHdr=unpack('!HHLLBBHHH',tcpHeader)
		fin_ack_psh_flag = tcpHdr[5] & 25
		new_seq = int(tcpHdr[3])
        	new_ack = int(tcpHdr[2])
		if (recv_length != 0):						# segment that contains a payload
			unpack_arg = "!" + str(recv_length) + "s"
			app_part = unpack(unpack_arg,recvPacket[40:(recv_length+40)]) 
			data[new_ack] = app_part[0]				# key -> ack_no and value -> data
			if( verify_checksum(recvPacket,recv_length) == True):		# verify checksum 
				tcp_seg,length = build_TCP_header(new_seq, new_ack+recv_length, 1,0)
			        packet = build_IP_header(length) + tcp_seg
				send_ethernet_frame(packet,tx_sock)
		if (fin_ack_psh_flag == 25):					# upon receiving FIN/PSH flag, 
			tear_down_success_flag = 1				# gracefully tearing down the conn
			tcp_seg,length = build_TCP_header(new_seq, new_ack+recv_length+1,1,0,1)
		        packet = build_IP_header(length) + tcp_seg
			send_ethernet_frame(packet,tx_sock)
	return data,new_seq,new_ack

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
def verify_checksum(packet,payload_len):

	ipHeader=packet[0:20]
    	ipHdr=unpack("!BBHHHBBH4s4s",ipHeader)
	placeholder = 0
	tcp_length = ipHdr[2] - 20
	protocol = ipHdr[6]
	sourceIP=ipHdr[8]
	destIP=ipHdr[9]
    	tcpHeader=packet[20:]
	unpack_arg = '!HHLLBBHHH' + str(payload_len) + 's'
	if(payload_len % 2 == 1):						# if the len is a odd number, add 1
		payload_len = payload_len + 1
	pack_arg = '!HHLLBBHHH' + str(payload_len) + 's'
    	tcpHdr=unpack(unpack_arg,tcpHeader)
	received_tcp_segment = pack(pack_arg,tcpHdr[0],tcpHdr[1],tcpHdr[2],tcpHdr[3],tcpHdr[4],tcpHdr[5],tcpHdr[6],0,tcpHdr[8],tcpHdr[9])
	pseudo_hdr = pack('!4s4sBBH' , sourceIP , destIP , placeholder , protocol , tcp_length)		#pseudo header
	total_msg = pseudo_hdr + received_tcp_segment
	checksum_from_packet = tcpHdr[7]
	tcp_checksum = get_checksum(total_msg)
	return (checksum_from_packet == tcp_checksum)	

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def send_arp_frame(dest_ip,interface,sender_mac):                                   #send an arp frame , whose reply contains the MAC address of the gateway , which will be
	                                                                            # used while sending ethernet packets
	global SRC_MAC
	send_socket=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.SOCK_RAW)
	send_socket.bind((interface,socket.SOCK_RAW))
	broadcast_mac_addr = pack('!6B',*(0xFF,)*6)
	zero_mac_addr = pack('!6B',*(0x00,)*6)
	socket_mac_addr = send_socket.getsockname()[4]
	SRC_MAC = socket_mac_addr
	if sender_mac == 'auto':
		sender_mac_addr = socket_mac_addr
	else:
		raise Exception("Cannot send an ARP to this mac address" + sender_mac)
	REQUEST_TYPE= pack('!H',0x0001)
	target_mac_addr = zero_mac_addr
	system_ip = get_IPADDR_of_source()
	source_ip_addr = pack('!4B',*[int(x) for x in system_ip.split('.')])
	target_ip_addr = pack('!4B',*[int(x) for x in dest_ip.split('.')])
	protocol_type_arp = pack('!H',0x0806)
	protocol_type_ethernet= pack('!HHBB',0x0001,0x0008,0x0006,0x0004)
	arp_frame=create_arp_frame(broadcast_mac_addr,socket_mac_addr,
		REQUEST_TYPE,protocol_type_arp,protocol_type_ethernet,sender_mac_addr,source_ip_addr,target_mac_addr,target_ip_addr)
	num = 3
	while(num != 0):
		send_socket.send(''.join(arp_frame))             #send the arp frame 
		num = num -1

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def create_arp_frame(broadcast_mac_addr,socket_mac_addr,op_type,protocol_type_arp,protocol_type_ethernet,sender_mac_addr,source_ip_addr,target_mac_addr,target_ip_addr):

	arp_frame=[
	broadcast_mac_addr,
	socket_mac_addr,
	protocol_type_arp,
	protocol_type_ethernet,
	op_type,
	sender_mac_addr,
	source_ip_addr,                                                     #create an arp fram
	target_mac_addr,
	target_ip_addr]
	return arp_frame

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def receive_arp_reply(target_ip_addr,source_ip_addr,interface):

	receiver_socket= socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0806))
	global SRC_MAC,DEST_MAC
	while True:                                                                                             #while we haven't recieved the packet which has its source ip as the gateway , we keep looping. 
		recieved_packet = receiver_socket.recvfrom(4096)                                              
		eth_header = recieved_packet[0][0:14]
		eth_header_contents=unpack("!6s6s2s",eth_header)
		arp_header = recieved_packet[0][14:42]
		arp_header_contents=unpack("!2s2s1s1s2s6s4s6s4s",arp_header)
		if socket.inet_ntoa(arp_header_contents[6]) == target_ip_addr:                                  #break the loop when we have found the specified packet
			break
	DEST_MAC = eth_header_contents[1]

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def send_ethernet_frame(data,sock):

	global SRC_MAC, DEST_MAC,interface	
	sock.bind((interface,socket.SOCK_RAW))
	sock.send(DEST_MAC+SRC_MAC+"\x08\x00"+data)                                                          #send an ethernet packet by string appending the src_mac,dst_mac, ethernet type and data

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def get_gateway_address():

	GATEWAY_IP = subprocess.check_output("echo $(/sbin/ip route | awk '/default/ {print $3}')", shell=True)
	return GATEWAY_IP.rstrip('\n')

#########################################################################################################

# get host name and path from url
HOST_NAME,PATH_NAME = parse_URL(url)		

# get source and dest IP addr and prepare for handshake
initiate_conn()

send_arp_frame(get_gateway_address(),interface,'auto')

receive_arp_reply(get_gateway_address(),get_IPADDR_of_source(),interface)

# create sender and receiver sockets
tx_sock = create_sender_sock()						#create sender socket
rx_sock = create_receiver_sock()					# create receiver socket

# perform handshake and get latest ack and MSS 
new_ack,new_seq,mss= perform_TCP_handshake(rx_sock,tx_sock)		# perform handshake

# contruct the HTTP GET request 
request_string = constructGETRequest(HOST_NAME,PATH_NAME)		# construct the HTTP GET request

# using congestion control mechanism send the GET request
current_index,slow_start_flag = 0,1				
send_to_server(request_string,new_ack,new_seq,rx_sock,tx_sock,3,mss)	# send the request 

# receive the receive in the form of a dictionary
http_response_dict,seq,ack = get_response(new_seq,new_ack,rx_sock)	# get the response

# construct response from the dictionary, sort the keys and concatenate their values
http_response = ""
for key in sorted(http_response_dict):
    	http_response = http_response + http_response_dict[key]		# the dictionary might have unsorted keys, sort them and
# using the URL given, come up with a file name and open a file with that name !
pieces = PATH_NAME.split('/')						# concatenate the correspondance values
file_name = pieces[-1]			
if not file_name:							# get the file name to be created
	file_name = "index.html"
index = open(file_name, "wb")

# verifying the code in HTTP header
srch_obj = re.search(valid_HTTP_code, http_response,re.I)
if not srch_obj:
        print "Error : BAD HTTP RESPONSE !"
	sys.exit()

# extracting the body from HTTP response and write into the created file
presence = http_response.find('\r\n\r\n')				 # extract the body from the http response
if presence >= 0:							
        index.write(http_response[presence+4:])
else:
	index.write(http_response)					# write the body into the file

# close the sockets and file 
tx_sock.close()
rx_sock.close()
index.close()



