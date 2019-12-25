import socket

clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 13012
client_address = ("172.16.1.50", port)

print('starting up on %s port %s' % client_address)
clientsocket.bind(client_address)
clientsocket.listen(5)

while True:
	#print('waiting for a connection')
    connection, client_address = clientsocket.accept()
    data = connection.recv(44).decode()
    print(data)
    
