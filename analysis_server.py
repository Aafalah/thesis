import socket
import sys
import subprocess
import re
import os
import time
import json
from sklearn.preprocessing import StandardScaler
import joblib
port = 13012
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ("172.16.1.85", port)

print('starting up on %s port %s' % server_address)
serversocket.bind(server_address)
serversocket.listen(5)

def find_digit(line='', idx=0):
    try:
        return re.findall("\\d+", line)[idx]
    except IndexError:
        return 0

def content_size(a,b):
	if int(a) <= 25 and int(b) >= 2:
		return 1
	else:
		return 0

def process_pdfid(lines):
    #main features
    endobj = find_digit(lines[3], 0)
    js = find_digit(lines[12], 0)
    javascript = find_digit(lines[13], 0)
    startxref = find_digit(lines[8], 0)
    page = find_digit(lines[9], 0)
    xref = find_digit(lines[6], 0)    
    
   #only needed for the little content feature
    obj = find_digit(lines[2], 0)
    aa = find_digit(lines[14], 0) 
    openaction = find_digit(lines[15], 0)   
    acroform = find_digit(lines[16], 0)
    richmedia = find_digit(lines[18], 0)    
    launch = find_digit(lines[19], 0)   
    embeddedfile = find_digit(lines[20], 0)    
    xfa = find_digit(lines[21], 0)   
    
    malicious_objects = int(javascript) + int(aa) + int(openaction) + int(acroform) + int(richmedia) + int(launch) + int(embeddedfile) + int(xfa) 
    
    little_content = content_size(obj, malicious_objects)
    
    pdfid_features = [int(endobj), int(js), int(javascript), int(startxref), int(page), int(little_content), int(xref)]
    #pdfid_features = [map(int, pdfid_features_raw)]
    #print("pdfid vector: ", pdfid_features)
    return pdfid_features
        
def pdfidextractor(inputfile):
    with open(inputfile, 'r') as src_file:
        chunk_24_lines = []
        for line in src_file:
            chunk_24_lines.append(line)
            if len(chunk_24_lines) == 27:
                return process_pdfid(chunk_24_lines)
 
def peepdfextractor(jsonfile):
	json_data = json.load(open(jsonfile))
	input_file = json_data["peepdf_analysis"]
	#data extraction
	if len(input_file["advanced"]) > 1:
		advanced_version = len(input_file["advanced"][-1])
	else:
		advanced_version = 0
	
	objects = input_file["basic"]["num_objects"]
	updates = input_file["basic"]["updates"]
	encoded_streams = len(input_file["advanced"][advanced_version]["version_info"]["encoded_streams"])
	
	try:
		actions = len(input_file["advanced"][advanced_version]["version_info"]["suspicious_elements"]["actions"])
	except TypeError:
		actions = 0
	
	try:
		triggers = len(input_file["advanced"][advanced_version]["version_info"]["suspicious_elements"]["triggers"])
	except TypeError:
		triggers = 0		
	
	size = input_file["basic"]["size"]
	streams = input_file["basic"]["num_streams"]
	
	peepdf_vector = [objects, updates, encoded_streams, actions, streams, triggers, size]
	#print("PeePDF vector: ",peepdf_vector)
	return peepdf_vector

def parser(filename_list):
	
	print("Now parsing the file:", filename)
	
	outputfile_peepdf = filename[:-4] + "peepdf.json"
	outputfile_pdfid = filename[:-4] + "pdfid.txt"
	
	command_peepdf = "peepdf.py -flj " + filename +  " > "  + outputfile_peepdf
	#print(command_peepdf)
	subprocess.call(command_peepdf, shell=True)
	
	command_pdfid = "pdfid.py " + filename +  " > "  + outputfile_pdfid
	#print(command_pdfid)
	subprocess.call(command_pdfid, shell=True)
	
	#call peepdf/json extractor
	vector_peepdf = peepdfextractor(outputfile_peepdf)
	#call pdfid extractor
	vector_pdfid = pdfidextractor(outputfile_pdfid)
		
	#delete both files
	delete_file1 = "rm " + outputfile_peepdf
	subprocess.call(delete_file1, shell=True)
	#print("deleted file" , outputfile_peepdf)
	delete_file2 = "rm " + outputfile_pdfid
	subprocess.call(delete_file2, shell=True)
	#print("deleted file" , outputfile_pdfid)
	print("pdfid: ",vector_pdfid)
	print("peepdf: ",vector_peepdf)
	
	feature_vector = vector_pdfid + vector_peepdf
	print(feature_vector)
	
	#classify_vector = feature_vector.reshape(1,-1)	
	#standardised_vector = StandardScaler().fit_transform(feature_vector)
	#print(standardised_vector)
	#standardised_vector = standardised_vector.reshape(len(standardised_vector), 1) 
	#"""
	#load trained model
	clf = joblib.load('joblib_model.pkl')
	label = clf.predict([feature_vector])
	if label == ['M']:
		prediction = "Malicious"
	else:
		prediction = "Clean"
	print("#######################################")
	print("# This file appears to be ", prediction, " #")
	print("#######################################")
	delete = "rm " + filename
	print("Deleting :", filename)
	subprocess.call(delete, shell=True)
	return prediction

def header_check(file):
    firstline = file.readline()
    #IMPORTANT: might want to handle small case PDF.
    # first check if it is a valid header and readers can read it
    result = re.search("\A%PDF", firstline)
    #print(x)
    if result != None:
        return 1
    else:
        return 0
    
def root_check(file):
    text = file.read()
    #Handle obfuscation - using Hex ASCII to replace any char in /Root
    root_list = ["/Root ", "/#52oot ", "/#52#6fot ", "/#52#6f#6ft ", "/#52#6f#6f#74 ", "/R#6fot ", "/R#6f#6ft ", "/#52#6fo#74 ", "/Ro#6ft ", "/Ro#6f#74 ", "/R#6f#6f#74 ", "/Roo#74 ", "/#52o#6ft ", "/#52o#6f#74 ", "/#52oo#74 ", "/R#6fo#74 "]
    root_result = re.findall(r"(?=("+'|'.join( root_list)+r"))",text)
    
    if root_result != None:
        root = 1
    else:
        root = 0
    
    count_obj = text.count('obj')
    #print("obj count = ",count_obj)
    
    count1 = text.count('<<')
    #print("<< count = ",count1)
    
    count2 = text.count('>>')
    #print(">> count = ",count2)
    #print(text)
    
    
    
    return [root, count_obj, count1, count2]
    

def check_type(doc):
	if os.path.isdir(doc) or os.stat(doc).st_size > 104857600:
		print("skipped :", doc)
		#print("##################################")
	else:
		with open(doc, 'r', encoding="utf8", errors='ignore') as file:
			print("Now examining: ", doc)
			#check for file header presence
			condition1 = header_check(file)
			
			content_list = root_check(file)
			
			#check for /Root object
			condition2 = content_list[0]
			
			#object count
			obj = content_list[1]
			
			#<< count
			a = content_list[2]
			
			#>> count
			b = content_list[3]
			
			if obj >= 5 and a >= 3 and b >= 2:
				condition3 = 1
			else:
				condition3 = 0
			
			print("condition1: ", condition1)
			print("condition2: ", condition2)
			print("obj: ",obj)
			print("<<: ", a)
			print(">>: ", b)
			print("condition3: ", condition3)
			
			if condition1 and condition2 and condition3:
				print(doc, "is a PDF file!")
				return 1			
			else:
				print(doc, "is not a PDF file!")
				return 0
				

while True:
    # Wait for a connection
	print('waiting for a connection')
	connection, client_address = serversocket.accept()
    
    #try:
	print('connection from', client_address)

	
	while True:
		data = connection.recv(47).decode()
		print('received "%s"' % data)
		if data:
			print('new_file notification - Initiating Scanning procedure')
			filename = data[-10:]
			print("Filename: ", filename)
			
			url = "172.16.1.1/"+str(filename)
			command = "wget " + url 
			subprocess.call(command, shell=True)
			if check_type(filename) == 1:
				decision = parser(filename)
				print("output: ", decision)
				if decision == "Malicious":
					message = "1"
				else:
					 message = "0"
				print('sending message: ', message)
				socket2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				gateway_address = ("172.16.1.1", port)
				socket2.connect(gateway_address)
				socket2.sendall(message.encode())
				print("Sending complete!")
				
				
					
			
			
			#message = "Ack!"
			#sock.sendall(message.encode())
		
		
		else:
			print('Received something weird from: ', client_address)
			break
"""        
    finally:
        # Clean up the connection
        connection.close()
"""
