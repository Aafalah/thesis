import os
import socket
import sys
import time 
import select

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock.setblocking(0)
#sock.settimeout(1)

#path = "/var/log/suricata/files/"
path = "/home/gateway/Documents/comms/test"
sleep_time = 5

server_address = ("172.16.1.85", 10032)
print('connecting to %s port %s' % server_address)
sock.connect(server_address)

def send_file(file_name):
	print(file_name)
	message = "New PDF document detected. Filename: " + file_name
	print("Sending data...")
	sock.sendall(message.encode())
	print("Sending complete!")
	

def get_response():
	try:
		ready = select.select([sock], [], [], 30)
		if ready[0]:
			data_expected = 1
			data_received = 0
			while data_received < data_expected:
				data = sock.recv(25)
				data_received += len(data)
			print("data: ", data)
			label = data.decode()
			print('received: ', label)
	
	finally:
		print("Test")

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
		send_file(file_name)
		get_response()
		
scanfile(path)		

		
		








