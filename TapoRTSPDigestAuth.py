import os
import socket
import re
import base64
import binascii
import hashlib

#socketizing stuff
target_ip = "192.168.1.199"
rtsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Open socket connection by shooting over a start bit
rtsock.connect((target_ip, 554))


#------------------------------------Build-A-Packet Workshop---------------------------------


#---------RTSP Protocol----------------------------
#---------Packet 1: Options packet-----------------

header = "OPTIONS rtsp://192.168.1.199/stream1 RTSP/1.0\r\n"
opt = header

seq = "CSeq 1\r\n"
opt += seq

usr_name = "User-Agent: Aaron\r\n"
opt += usr_name

end_bit = "\r\n"
opt += end_bit

#Take a look at what I sent
print(opt, "\n\n")

#---------Packet 2: Describe 1 packet-----------------
# Uses describe to submit a request to use SDP
header = "DESCRIBE rtsp://192.168.1.199/stream2 RTSP/1.0\r\n"
desc1 = header

seq = "CSeq 2\r\n"
desc1 += seq

usr_name = "User-Agent: Aaron\r\n"
desc1 += usr_name

sdp_app = "Accept: application/sdp\r\n"

end_bit = "\r\n"
desc1 += end_bit

#Packet 2 sent after packet 1 information received


#-----------------------------Send section------------------------------------
#Convert packet into bytes so camera can read
rt_opt_packt = bytes(opt, 'utf-8')
rt_des1_packt = bytes(desc1, 'utf-8')


#Send options packet
rtsock.sendto(rt_opt_packt, (target_ip, 554))

#Catching the response
reply = rtsock.recv(4096)
reply1 = reply.decode('utf-8')
print(reply1, "\n\n")

#Send describe packet 1
rtsock.sendto(rt_des1_packt, (target_ip, 554))

#Catching the response
reply = rtsock.recv(4096)
reply2 = reply.decode('utf-8')
print(reply2, "\n\n")
nonce = re.search(r'nonce="([^"]+)"', reply2, re.IGNORECASE).group(1)
print(nonce, "\n\n")

#---------Packet 3: Describe 2 packet-----------------
# Using describe, sends SDP Authorization request
header = "DESCRIBE rtsp://192.168.1.199/stream2 RTSP/1.0\r\n"
desc2 = header

seq = "CSeq 3\r\n"
desc2 += seq

usr_name = "User-Agent: Aaron\r\n"
desc2 += usr_name

#Authorization body, super fucked up
username = "tadmin"
password = "abc123"
method = "DESCRIBE"
desc2 += 'Authorization: Digest username="tadmin", '
realm = re.search(r'realm="([^"]+)"', reply2, re.IGNORECASE).group(1)
nonce = re.search(r'nonce="([^"]+)"', reply2, re.IGNORECASE).group(1)
desc2 += f'realm={realm}, '
desc2 += f'nonce="{nonce}", '
uri = "rtsp://192.168.1.199:554/stream2"
desc2 += f'uri={uri}, '

#Response is two hashes of different plaintext combinations of categories and the instanced nonce token
#nonce token changes with every session, is unique per session
hash1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
hash2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
response = hashlib.md5(f"{hash1}:{nonce}:{hash2}".encode()).hexdigest()
desc2 += f'response="{response}"\r\n'
#print(auth, "\n\n")

sdp_app = "Accept: application/sdp\r\n"
desc2 += sdp_app
end_bit = "\r\n"
desc2 += end_bit

print(desc2, "\n\n")

#Convert packet 2 to bytes
rt_des2_packt = bytes(desc2, 'utf-8')

print(rt_des2_packt, "\n\n")

#Send describe packet 2
rtsock.sendto(rt_des2_packt, (target_ip, 554))

reply = rtsock.recv(4096)
reply3 = reply.decode('utf-8')
print(reply3, "\n\n")

#Close socket connection by shooting over an end bit
rtsock.close()




