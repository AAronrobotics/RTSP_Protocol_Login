import base64
import socket
import binascii

rtsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Packet info
header = "DESCRIBE rtsp://192.168.1.199/stream1 RTSP/1.0\r\n"
seq = "CSeq 1\r\n"
usr_name = "User-Agent: Aaron\r\n"
tapouser = "tadmin"
tapopass = "abc123"
login = base64.b64encode(f'{tapouser}:{tapopass}'.encode()).decode()
auth = f'Authorization: Basic {login}'
sdpapp = "Accept: application/sdp\r\n"
endbit = "\r\n"

print(login, "\n\n")

#------------------------------------Build-A-Packet Workshop---------------------------------
#---Packet assembly line
packet = header
packet += seq
packet += usr_name
packet += auth
packet += sdpapp
packet += endbit
print(f'RTSP Basic Auth Packet Sent:\n{packet}\n')

#---Package packet and prepare for launch
rtsock.connect(('192.168.1.199', 554))
rtsock.send(packet.encode())

reply = rtsock.recv(4096).decode()
print("Response from Tapo:\n")
print(reply, "\n")

rtsock.close()