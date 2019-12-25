import os
import socket
import sys
import time 
import select

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock.setblocking(0)
#sock.settimeout(1)

path = "/var/log/suricata/files/"
#path = "/home/gateway/Documents/comms/test"
sleep_time = 5

port = 13012

server_address = ("172.16.1.85", port)
print('connecting to %s port %s' % server_address)
sock.connect(server_address)

client_address = ("172.16.1.50", port)
print('connecting to %s port %s' % client_address)
sock2.connect(client_address)

def send_file(file_name):
	print(file_name)
	message = "New PDF document detected. Filename: " + file_name
	print("Sending data...")
	sock.sendall(message.encode())
	print("Sending complete!")
	

def get_response():
	gatewaysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_address = ("172.16.1.1", port)
	gatewaysocket.bind(server_address)
	gatewaysocket.listen(5)
	print("Waiting for analysis result")
	while True:
		
		connection, client_address = gatewaysocket.accept()
		data = connection.recv(10).decode()
		print('received "%s"' % data)
		return data

def scanfile(path):
	print("Scanning file folder")
	files = os.listdir(path)
	if len(files) == 0:
		print("Folder is empty. sleeping now...")
		time.sleep(sleep_time)
		scanfile(path)
	else:
		file_name = files[0]
		print("A new download detected")
		#notification = "PDF download detected. Standby for analysis!"
		#sock2.sendall(notification.encode())
		send_file(file_name)
		result = get_response()
		#print(result)
		if result == "1":
			result_message = "The file is malicious. Download blocked!"
			sock2.sendall(result_message.encode())
			print("Result sent to client!")
		else:
			result_message = "The file is clean"
			sock2.sendall(result_message.encode())
			print("Result sent to client!")
		
		
scanfile(path)
